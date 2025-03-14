package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"time"

	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/jackc/pgx/v5/stdlib"

	stub "github.com/miltsm/pesan-grpc-stubs/go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"
)

// NOTE: core - APPLICATION
// *this is for an nvim easy jump; consider it as table of contents
var (
	db         *sql.DB
	statements map[StatementKey]*sql.Stmt
	cache      *redis.Client
	wbAuthn    *webauthn.WebAuthn
	apiSecret  []byte
)

type pesanServer struct {
	stub.UnimplementedPesanServer
}

func newServer() *pesanServer {
	return &pesanServer{}
}

func main() {
	extractSecrets()
	establishDb()
	prepareStatements()
	establishRedis()
	configureWebAuthn()

	port, err := strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		log.Fatalf("[WARN] %s", err.Error())
		port = 50051
	}
	var lis net.Listener
	lis, err = net.Listen("tcp", fmt.Sprintf("%s:%d", os.Getenv("HOST"), port))
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		db.Close()
		return
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(logInterceptor))
	stub.RegisterPesanServer(srv, newServer())

	fmt.Printf("[INFO] listening to port: %d..\n", port)
	err = srv.Serve(lis)
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		db.Close()
	}
}

// NOTE: core - CONFIG
func extractSecrets() {
	var err error
	apiSecret, err = os.ReadFile(os.Getenv("JWT_SECRET_PATH"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
		return
	}
}

// NOTE: core - INTERCEPTORS
func logInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	log.Printf("[INFO] Method: %s, Request: %v", info.FullMethod, req)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("[ERROR] %v", err)
	}
	log.Printf("[INFO] %v", resp)
	return resp, err
}

// NOTE: core - DATABASE
type StatementKey int

const (
	CreateAnUser StatementKey = iota
	ReadAnUserByHandle
	ReadAnUserProfile
	CreateAPublicKey
	CreateAPassword
	ReadAPassword
	CreateProduct
	CreateCategory
	UpdateCategory
	CreateProductCategories
)

func establishDb() {
	var pgPort int64
	var pwd []byte
	pgPort, err := strconv.ParseInt(os.Getenv("POSTGRES_PORT"), 10, 32)

	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		pgPort = 5432
	}
	pwd, err = os.ReadFile(os.Getenv("POSTGRES_PASSWORD_FILE"))
	if err != nil {
		log.Fatalf("[FATAL] %v\n", err)
		return
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		os.Getenv("POSTGRES_USER"),
		pwd,
		os.Getenv("POSTGRES_HOST"),
		pgPort,
		os.Getenv("POSTGRES_DB"))

	db, err = sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("[FATAL] unable to use data source name -\n%v\n", err)
		return
	}
	fmt.Println("[INFO] db connected!")
	//db.SetConnMaxLifetime(0)
	//db.SetMaxIdleConns(50)
	//db.SetMaxOpenConns(50)
}

func prepareStatements() {
	temp := make(map[StatementKey]*sql.Stmt)

	queries := map[StatementKey]string{
		CreateAnUser: `
			INSERT INTO
				users(user_id, user_handle, display_name)
			VALUES( $1, $2, $3)
		`,
		ReadAnUserByHandle: `
			SELECT 
				user_id, user_handle, display_name
			FROM
				users
			WHERE
				user_handle = $1
		`,
		ReadAnUserProfile: `
			SELECT
				user_handle, display_name, passkey_count, last_password_updated_at
			FROM
				user_profile
			WHERE
				user_handle = $1 or user_id::text = $1
		`,
		CreateAPublicKey: `
			INSERT INTO
				passkeys(passkey_id, public_key, attestation_type, transport, flags, authenticator_aaguid, user_id)
			VALUES( $1, $2, $3, $4, $5, $6, $7)
		`,
		CreateAPassword: `
			INSERT INTO
				passwords(hashed, user_id)
			VALUES
				( $1, $2)
			ON CONFLICT 
				(user_id)
			DO UPDATE SET
				hashed = EXCLUDED.hashed;
		`,
		ReadAPassword: `
			SELECT
				updated_at
			FROM
				passwords
			WHERE
				hashed = crypt($1, hashed)
			
		`,
		//CreateProduct: `INSERT INTO products(product_id, name, description, unit, price) VALUES( $1, $2, $3, $4, $5)`,
		//// client will provide id on their side for an easy sync and redundant API refresh
		//CreateCategory: `
		//	INSERT INTO
		//		categories(category_id, name, description, open_hour, closing_hour, weekly)
		//	VALUES( $1, $2, $3, $4, $5, $6)
		//`,
		//UpdateCategory: `
		//	UPDATE
		//		categories
		//	SET
		//		name = $2, description = $3, open_hour = $4, closing_hour = $5, weekly = $6
		//	WHERE
		//		category_id = $1
		//`,
		//CreateProductCategories: `INSERT INTO product_categories(product_id, category_id) VALUES( $1, $2)`,
	}

	for key, query := range queries {
		stmt, err := db.Prepare(query)
		if err != nil {
			log.Fatalf("[ERROR] error preparing statement for %v: %v", key, err)
			db.Close()
			return
		}
		temp[key] = stmt
	}

	fmt.Println("[INFO] sql statements prepared!")
	statements = temp
}

// NOTE: core - CACHE

// NOTE: might need to cache credentials, just incase user request on another device
type OnboardCache struct {
	User    User                 `json:"user"`
	Session webauthn.SessionData `json:"session"`
}

func establishRedis() {
	rdHost, rdPort := os.Getenv("RDS_HOST"), os.Getenv("RDS_PORT")
	if len(rdHost) == 0 {
		fmt.Println("[WARN] redis host isn't specified!")
		rdHost = "core-cache"
	}
	if len(rdPort) == 0 {
		fmt.Println("[WARN] redis port isn't specified!")
		rdPort = "6379"
	}

	cache = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", rdHost, rdPort),
		Password: "",
		DB:       0,
		Protocol: 2,
	})

	fmt.Println("[INFO] cache established!")
}

func cacheAssertSession(ctx context.Context, session *webauthn.SessionData, user *User) error {
	key := fmt.Sprintf("asserts:%s", session.Challenge)

	cacheData := &OnboardCache{
		Session: *session,
		User:    *user,
	}

	jsonCacheData, err := json.Marshal(cacheData)
	if err != nil {
		return status.Errorf(codes.Internal, "[ERROR] json marshaling failed: %v", err)
	}

	_, err = cache.JSONSet(ctx, key, "$", jsonCacheData).Result()
	if err != nil {
		return status.Errorf(codes.Internal, "[ERROR] unable to cache session: %v", err)
	}

	var expiring bool
	expiring, err = cache.ExpireAt(ctx, key, session.Expires).Result()
	if err != nil || !expiring {
		return status.Error(codes.Internal, "[ERROR] setting cache expiration")
	}

	return nil
}

func getCachedUserFromAssertSession(ctx context.Context, challengeId string) (*string, error) {
	key := fmt.Sprintf("asserts:%s", challengeId)
	result, err := cache.JSONGet(ctx, key, ".user").Result()
	if err != nil {
		return nil, status.Error(codes.DeadlineExceeded, "[ERROR] session ended")
	}
	return &result, nil
}

func cacheAttestDiscoverableSession(ctx context.Context, session webauthn.SessionData) error {
	cacheKey := fmt.Sprintf("attests:%s", session.Challenge)

	marshaledSession, err := json.Marshal(session)
	if err != nil {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var res string
	res, err = cache.JSONSet(ctx, cacheKey, "$", marshaledSession).Result()
	if err != nil || strings.Compare(res, "OK") != 0 {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var isExpiring bool
	isExpiring, err = cache.ExpireAt(ctx, cacheKey, session.Expires).Result()
	if err != nil || !isExpiring {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return nil
}

func getCachedDiscoverableSessionFromAttestSession(ctx context.Context, challengeId string) (*string, error) {
	cacheKey := fmt.Sprintf("attests:%s", challengeId)
	res, err := cache.JSONGet(ctx, cacheKey, "$").Result()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	return &res, nil
}

// NOTE: core - WEBAUTHN
func configureWebAuthn() {
	androidOrigin, webHost := fmt.Sprintf("android:apk-key-hash:%s", os.Getenv("ANDROID_KEY_HASH")), os.Getenv("WBAUTHN_RP_ID")
	webOrigin := fmt.Sprintf("%s://%s", os.Getenv("WEB_SCHEME"), webHost)

	config := &webauthn.Config{
		RPDisplayName: "Pesan Authentication",
		RPID:          webHost,
		RPOrigins:     []string{webOrigin, androidOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * PASSKEY_DURATION,
				TimeoutUVD: time.Second * PASSKEY_DURATION,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * PASSKEY_DURATION,
				TimeoutUVD: time.Second * PASSKEY_DURATION,
			},
		},
	}

	var err error
	wbAuthn, err = webauthn.New(config)
	if err != nil {
		log.Println(err)
		// NOTE: don't close the server; user still able to sign up/in with password
	}

	fmt.Println("[INFO] webauthn configured!")
}
