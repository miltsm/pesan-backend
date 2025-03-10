package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"net/http"

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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NOTE: chapter - APPLICATION
var (
	db         *sql.DB
	statements map[StatementKey]*sql.Stmt
	cache      *redis.Client
	wbAuthn    *webauthn.WebAuthn
)

type pesanServer struct {
	stub.UnimplementedPesanServer
}

func newServer() *pesanServer {
	return &pesanServer{}
}

func main() {
	establishDb()
	establishRedis()
	configWebAuthn()
	port, err := strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		log.Fatalf("[WARN] %s", err.Error())
		port = 50051
	}
	var lis net.Listener
	lis, err = net.Listen("tcp", fmt.Sprintf("%s:%d", os.Getenv("HOST"), port))
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		defer db.Close()
		return
	}
	srv := grpc.NewServer()
	stub.RegisterPesanServer(srv, newServer())
	fmt.Printf("listening to port: %d..\n", port)
	err = srv.Serve(lis)
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		defer db.Close()
	}
}

// NOTE: chapter - DATABASE
type StatementKey int

const (
	CreateUser StatementKey = iota
	ReadUserByHandle
	ReadUserWithPublicKeys
	CreatePublicKey
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
	prepareStatements()
	//db.SetConnMaxLifetime(0)
	//db.SetMaxIdleConns(50)
	//db.SetMaxOpenConns(50)
}

func prepareStatements() {
	temp := make(map[StatementKey]*sql.Stmt)

	queries := map[StatementKey]string{
		CreateUser: `
			INSERT INTO
				users(user_id, user_handle, display_name)
			VALUES( $1, $2, $3)
		`,
		ReadUserByHandle: `
			SELECT 
				user_id, user_handle, display_name
			FROM
				users
			WHERE
				user_handle = $1
		`,
		ReadUserWithPublicKeys: `
			SELECT 
				u.user_id, u.user_handle, u.display_name,
				p.passkey_id,
				p.public_key,
				p.attestation_type,
				p.transport,
				p.flags,
				p.authenticator_aaguid,
				p.sign_count
			FROM 
				users u
			JOIN
				passkeys p ON u.user_id = p.user_id
			WHERE 
				u.user_handle = $1 
		`,
		CreatePublicKey: `
			INSERT INTO
				passkeys(passkey_id, public_key, attestation_type, transport, flags, authenticator_aaguid, user_id)
			VALUES( $1, $2, $3, $4, $5, $6, $7)
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
			return
		}
		temp[key] = stmt
	}

	fmt.Println("[INFO] sql statements prepared!")
	statements = temp
}

// NOTE: chapter - CACHE

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

func getUserFromAssertSession(ctx context.Context, key string) (*string, error) {
	result, err := cache.JSONGet(ctx, key, ".user").Result()
	if err != nil {
		return nil, status.Error(codes.DeadlineExceeded, "[ERROR] session ended")
	}
	return &result, nil
}

// NOTE: chapter - WEBAUTHN
func configWebAuthn() {
	androidOrigin, webHost := fmt.Sprintf("android:apk-key-hash:%s", os.Getenv("ANDROID_KEY_HASH")), os.Getenv("WBAUTHN_RP_ID")
	webOrigin := fmt.Sprintf("%s://%s", os.Getenv("WEB_SCHEME"), webHost)

	config := &webauthn.Config{
		RPDisplayName: "Pesan Authentication",
		RPID:          webHost,
		RPOrigins:     []string{webOrigin, androidOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
		},
	}

	var err error
	wbAuthn, err = webauthn.New(config)
	if err != nil {
		log.Println(err)
		// NOTE: don't close the server; user still able to sign up/in with password
	}
}

// NOTE: chapter - SESSIONS
type User struct {
	Id          uuid.UUID             `json:"id"`
	UserHandle  string                `json:"user_handle"`
	DisplayName string                `json:"display_name"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *User) WebAuthnID() []byte {
	return []byte(u.Id.String())
}

func (u *User) WebAuthnName() string {
	return u.UserHandle
}

func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (s *pesanServer) OnboardWithPublicKey(ctx context.Context, r *stub.OnboardRequest) (*stub.AssertSession, error) {
	if len(r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] user handle can't be empty!")
	}

	var displayName string
	if len(*r.DisplayName) == 0 {
		displayName = r.UserHandle
	}

	err := statements[ReadUserByHandle].QueryRow(r.UserHandle).Scan()
	if err != nil {
		// NOTE: Check if the user does not exist
		if errors.Is(err, sql.ErrNoRows) {
			tempUser := &User{
				Id:          uuid.New(),
				UserHandle:  r.UserHandle,
				DisplayName: displayName,
			}

			var creation *protocol.CredentialCreation
			var session *webauthn.SessionData
			creation, session, err = wbAuthn.BeginMediatedRegistration(tempUser, protocol.MediationOptional)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("[ERROR] %v", err))
			}

			// NOTE: Cache data
			if err = cacheAssertSession(ctx, session, tempUser); err != nil {
				return nil, status.Error(codes.Internal, "[ERROR] unable to cache your session")
			}

			var options []byte
			options, err = json.Marshal(creation.Response)
			if err != nil {
				return nil, status.Error(codes.Internal, "[ERROR] unable to marshal response")
			}

			return &stub.AssertSession{
				Challenge:  options,
				ValidUntil: timestamppb.New(session.Expires),
			}, nil
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] unable to create challenge:\n%v", err)
		}
	}

	// NOTE: Existing user, return error
	return nil, status.Error(codes.AlreadyExists, "[ERROR] user already exists with the given handle")
}

func (s *pesanServer) VerifyPublicKeyAndOnboard(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.UserSession, error) {
	parsedSignature, err := protocol.ParseCredentialCreationResponseBytes(r.Signed)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] unable to parse public key data")
	}

	challengeId := parsedSignature.Response.CollectedClientData.Challenge

	var tempUser *string
	tempUser, err = getUserFromAssertSession(ctx, fmt.Sprintf("asserts:%s", challengeId))
	if err != nil {
		return nil, err
	}

	var marshaledUser User
	if err = json.Unmarshal([]byte(*tempUser), &marshaledUser); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "[ERROR] session corrupted. please try again!")
	}

	verifyLink := fmt.Sprintf("http://localhost:3000/public-key/assert/%v", challengeId)

	var res *http.Response
	res, err = http.Post(verifyLink, "application/json", bytes.NewBuffer(r.Signed))
	if err != nil {
		return nil, status.Error(codes.Internal, "[ERROR] unable to verify public key")
	}
	defer res.Body.Close()

	var body []byte
	body, err = io.ReadAll(res.Body)

	switch res.StatusCode {
	case http.StatusAccepted:

		_, err = statements[CreateUser].Exec(marshaledUser.Id, marshaledUser.UserHandle, marshaledUser.DisplayName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		// NOTE: probably just cache the Sign Count; no need to keep in db
		_, err = statements[CreatePublicKey].Exec(
			parsedSignature.Raw.Credential.ID,
			parsedSignature.Raw.AttestationResponse.PublicKey,
			parsedSignature.Type,
			parsedSignature.Response.Transports,
			parsedSignature.Response.AttestationObject.AuthData.Flags,
			parsedSignature.Response.AttestationObject.AuthData.AttData.AAGUID,
		)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "pesan-backend",
			Subject:   marshaledUser.UserHandle,
			ID:        uuid.New().String(),
			Audience:  []string{"seller"},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		var accessToken string
		// TODO: use secret
		accessToken, err = token.SignedString("secret123")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		var totalPasskeys uint32 = 1
		return &stub.UserSession{
			AccessToken:  accessToken,
			UserHandle:   marshaledUser.UserHandle,
			DisplayName:  marshaledUser.DisplayName,
			TotalPasskey: &totalPasskeys,
		}, nil
	case http.StatusBadRequest:
		return nil, status.Error(codes.InvalidArgument, string(body))
	case http.StatusRequestTimeout:
		return nil, status.Error(codes.DeadlineExceeded, string(body))
	case http.StatusFailedDependency:
		return nil, status.Error(codes.FailedPrecondition, string(body))
	default:
		return nil, status.Error(codes.Internal, "[ERROR] unable to verify public key")
	}
}
