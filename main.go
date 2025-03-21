package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"strings"

	"time"

	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	_ "github.com/jackc/pgx/v5/stdlib"

	stub "github.com/miltsm/pesan-grpc-stubs/go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"google.golang.org/grpc/status"
)

// NOTE: core - APPLICATION
// *this is for an nvim easy jump; consider it as table of contents
var (
	port, dbPort, cachePort                                int
	db                                                     *sql.DB
	statements                                             map[StatementKey]*sql.Stmt
	cache                                                  *redis.Client
	wbAuthn                                                *webauthn.WebAuthn
	accessSecret, refreshSecret                            []byte
	passkeyDuration, accessJwtLifespan, refreshJwtLifespan int
)

type pesanServer struct {
	stub.UnimplementedPesanServer
}

func newServer() *pesanServer {
	return &pesanServer{}
}

func main() {
	setEnvs()
	establishDb()
	prepareStatements()
	establishRedis()
	configureWebAuthn()

	var lis net.Listener
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", os.Getenv("HOST"), port))
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		db.Close()
		return
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(unaryInterceptor))
	stub.RegisterPesanServer(srv, newServer())

	fmt.Printf("[INFO] listening to port: %d..\n", port)
	err = srv.Serve(lis)
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		db.Close()
	}
}

// NOTE: core - CONFIG
func setEnvs() {
	var err error

	port, err = strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		log.Fatalf("[WARN] %s", err.Error())
		port = 50051
	}

	dbPort, err = strconv.Atoi(os.Getenv("POSTGRES_PORT"))
	if err != nil {
		log.Fatalf("[WARN] %v", err)
		dbPort = 5432
	}

	cachePort, err = strconv.Atoi(os.Getenv("RDS_PORT"))
	if err != nil {
		log.Fatalf("[WARN] %v", err)
		cachePort = 6379
	}

	accessJwtLifespan, err = strconv.Atoi(os.Getenv("ACCESS_JWT_LIFESPAN"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	refreshJwtLifespan, err = strconv.Atoi(os.Getenv("REFRESH_JWT_LIFESPAN"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	passkeyDuration, err = strconv.Atoi(os.Getenv("PASSKEY_DURATION"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	accessSecret, err = os.ReadFile(os.Getenv("ACCESS_SECRET_PATH"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
		return
	}

	refreshSecret, err = os.ReadFile(os.Getenv("REFRESH_SECRET_PATH"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
		return
	}
}

// NOTE: core - INTERCEPTOR
func unaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {

	log.Printf("[INFO] Method: %s", info.FullMethod)
	serviceName := "/pesan.Pesan"

	switch info.FullMethod {
	case fmt.Sprintf("%s/OnboardWithPublicKey", serviceName):
	case fmt.Sprintf("%s/VerifyPublicKeyAndOnboard", serviceName):
	case fmt.Sprintf("%s/OnboardWithPassword", serviceName):
	case fmt.Sprintf("%s/DiscoverLogin", serviceName):
	case fmt.Sprintf("%s/VerifyPublicKeyLogin", serviceName):
	case fmt.Sprintf("%s/LoginWithPassword", serviceName):
	default:
		// NOTE: Auth
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			err := status.Errorf(codes.PermissionDenied, "[WARN] missing metadata")
			log.Println(err)
			return nil, err
		}

		authHeader := md["authorization"]
		if len(authHeader) < 1 {
			return nil, status.Errorf(codes.PermissionDenied, "[WARN] missing authorisation")
		}

		accessToken := strings.TrimPrefix(authHeader[0], "Bearer ")

		parsedToken, err := jwt.Parse(accessToken, func(*jwt.Token) (interface{}, error) {
			return []byte(accessSecret), nil
		})

		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, status.Error(codes.Unauthenticated, "[WARN] not a token")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, status.Error(codes.Unauthenticated, "[ERROR] invalid token signature")
		case errors.Is(err, jwt.ErrTokenExpired):
			allowedMethods := []string{fmt.Sprintf("%s/RefreshSession", serviceName), fmt.Sprintf("%s/ReAuth", serviceName), fmt.Sprintf("%s/VerifyPublicKeyReAuth", serviceName), fmt.Sprintf("%s/ReAuthWithPassword", serviceName)}
			switch info.FullMethod {
			case allowedMethods[0], allowedMethods[1], allowedMethods[2], allowedMethods[3]:
				var userId *uuid.UUID
				userId, err = extractUserIdFromToken(parsedToken)
				if err != nil {
					return nil, err
				}
				ctx = context.WithValue(ctx, "user_id", *userId)
				if strings.Compare(info.FullMethod, allowedMethods[2]) == 0 || strings.Compare(info.FullMethod, allowedMethods[3]) == 0 {
					checkTotalReAuthAttempts(ctx, *userId)
				}
			default:
				return nil, status.Error(codes.Unauthenticated, "[ERROR] session expired")
			}
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, status.Error(codes.Unavailable, "[WARN] token yet valid")
		case parsedToken.Valid:
			var userId *uuid.UUID
			userId, err = extractUserIdFromToken(parsedToken)
			if err != nil {
				return nil, err
			}
			ctx = context.WithValue(ctx, "user_id", *userId)
		default:
			return nil, status.Errorf(codes.Unauthenticated, "[ERROR] couldnt handle this token: %v", err)
		}
	}

	// NOTE: Logger
	log.Printf("[INFO] Request: %v", req)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("[ERROR] %v", err)
	}
	log.Printf("[INFO] %v", resp)

	return resp, err
}

func extractUserIdFromToken(access *jwt.Token) (*uuid.UUID, error) {
	userIdStr, err := access.Claims.GetSubject()
	if err != nil {
		return nil, status.Error(codes.DataLoss, "[WARN] unknown token owner")
	}
	var userId uuid.UUID
	userId, err = uuid.Parse(userIdStr)
	if err != nil {
		return nil, status.Error(codes.Aborted, "[ERROR] malformed user id")
	}
	return &userId, nil
}

// NOTE: core - DATABASE
type StatementKey int

const (
	CreateAnUser StatementKey = iota
	ReadAnUserByHandle
	ReadAnUserProfile
	ReadAnUserProfileByCredentialId
	ReadAnUserWithPasskeys
	CreateAPublicKey
	UpdateAPublicKey
	CreateAPassword
	ReadAPassword
	CreateAShop
	ReadShops
	CreateProduct
	CreateCategory
	UpdateCategory
	CreateProductCategories
)

func establishDb() {
	pwd, err := os.ReadFile(os.Getenv("POSTGRES_PASSWORD_FILE"))
	if err != nil {
		log.Fatalf("[FATAL] %v\n", err)
		return
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		os.Getenv("POSTGRES_USER"),
		pwd,
		os.Getenv("POSTGRES_HOST"),
		dbPort,
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
				user_id, user_handle, display_name, passkey_count
			FROM
				user_profiles
			WHERE
				user_handle = $1 or user_id::text = $1		`,
		ReadAnUserProfileByCredentialId: `	
			SELECT
				user_id, user_handle, display_name, passkey_count, last_password_updated_at
			FROM
				user_profiles
			WHERE
				passkey_id = $1
		`,
		ReadAnUserWithPasskeys: `	
			SELECT  
				user_handle,	
				display_name,
				passkey_id,
				public_key,
				attestation_type,
				transport,
				flags,
				authenticator_aaguid,
				sign_count
			FROM 
				user_passkeys
			WHERE 
				user_id = $1
		`,
		CreateAPublicKey: `
			INSERT INTO
				passkeys(passkey_id, public_key, attestation_type, transport, flags, authenticator_aaguid, user_id)
			VALUES( $1, $2, $3, $4, $5, $6, $7)
		`,
		UpdateAPublicKey: `
		UPDATE 
			passkeys
		SET
			attestation_type = $1, transport = $2, flags = $3, sign_count = $4
		WHERE
			passkey_id = $5	
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
			user_id::text = $1 AND hashed = crypt($2, hashed)	
		`,
		CreateAShop: `
		INSERT INTO
			shops(shop_id, name, tags, open_hour, closing_hour, contacts, operation_days, locations, user_id)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`,
		ReadShops: `
			SELECT
				shop_id, name, tags, open_hour, closing_hour, contacts, operation_days, locations, updated_at
			FROM
				shops
			WHERE
				user_id = $1
			LIMIT 1
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
type SessionCache struct {
	User    User                 `json:"user"`
	Session webauthn.SessionData `json:"session"`
}

func establishRedis() {
	rdHost := os.Getenv("RDS_HOST")
	if len(rdHost) == 0 {
		fmt.Println("[WARN] redis host isn't specified!")
		rdHost = "core-cache"
	}

	cache = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", rdHost, cachePort),
		Password: "",
		DB:       0,
		Protocol: 2,
	})

	fmt.Println("[INFO] cache established!")
}

func cacheAssertSession(ctx context.Context, session *webauthn.SessionData, user *User) error {
	key := fmt.Sprintf("asserts:%s", session.Challenge)

	cacheData := &SessionCache{
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

func checkTotalReAuthAttempts(ctx context.Context, userId uuid.UUID) error {
	attemptKey := fmt.Sprintf("reauths:attempts:%s", userId.String())
	totalAttemptsStr, err := cache.Get(ctx, attemptKey).Result()
	if err != nil {
		// NOTE: fresh reattempt
		return incrReAuthCounter(ctx, userId, time.Now().Add(time.Duration(passkeyDuration)*time.Second))
	}
	var totalAttempts int
	if totalAttempts, err = strconv.Atoi(totalAttemptsStr); err != nil {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	log.Printf("[INFO] total reauths attempts: %d\n", totalAttempts)
	if totalAttempts > 2 {
		return status.Error(codes.PermissionDenied, "[ERROR] reauth maxed; please login back")
	}
	return nil
}

func incrReAuthCounter(ctx context.Context, userId uuid.UUID, expiresAt time.Time) error {
	cacheKey := fmt.Sprintf("reauths:attempts:%s", userId.String())
	_, err := cache.Incr(ctx, cacheKey).Result()
	if err != nil {
		return err
	}
	var ok bool
	if ok, err = cache.ExpireAt(ctx, cacheKey, expiresAt).Result(); err != nil {
		return err
	}
	if !ok {
		return status.Errorf(codes.Internal, "[ERROR] unable to cache reauth session")
	}
	return nil
}

func clearReAuthCache(ctx context.Context, userId uuid.UUID) {
	attemptKey := fmt.Sprintf("reauths:attempts:%s", userId.String())
	cache.Del(ctx, attemptKey).Result()

	cacheKey := fmt.Sprintf("reauths:%s", userId.String())
	cache.JSONDel(ctx, cacheKey, "$")
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
				Timeout:    time.Second * time.Duration(passkeyDuration),
				TimeoutUVD: time.Second * time.Duration(passkeyDuration),
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * time.Duration(passkeyDuration),
				TimeoutUVD: time.Second * time.Duration(passkeyDuration),
			},
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
		},
		Debug: true,
	}

	var err error
	wbAuthn, err = webauthn.New(config)
	if err != nil {
		log.Println(err)
		// NOTE: don't close the server; user still able to sign up/in with password
	}

	fmt.Println("[INFO] webauthn configured!")
}
