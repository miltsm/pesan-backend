package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"

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
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		defer db.Close()
		return
	}
	srv := grpc.NewServer()
	stub.RegisterPesanServer(srv, newServer())
	fmt.Printf("[INFO] listening to port: %d..\n", port)
	err = srv.Serve(lis)
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		defer db.Close()
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
			defer db.Close()
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

// NOTE: core - SESSIONS
const (
	// NOTE: 1 minute per assert & attest session
	PASSKEY_DURATION = 60
	// NOTE: 1 day lifespan for passkey sign up & login
	JWT_PASSKEY_LIFESPAN = 24
	// NOTE: 1 hour lifespan for password sign up & login
	JWT_PASSWORD_LIFESPAN = 1
)

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

// NOTE: core/pk/assert/challenge
func (s *pesanServer) OnboardWithPublicKey(ctx context.Context, r *stub.OnboardRequest) (*stub.AssertSession, error) {
	if len(r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] user handle can't be empty!")
	}

	var displayName string
	if len(*r.DisplayName) == 0 {
		displayName = r.UserHandle
	}

	var user User
	err := statements[ReadAnUserByHandle].QueryRow(r.UserHandle).Scan(&user.Id, &user.UserHandle, &user.DisplayName)
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
				cache.JSONClear(ctx, fmt.Sprintf("asserts:%s", session.Challenge), "$")
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

// NOTE: code/pk/assert/verify
func (s *pesanServer) VerifyPublicKeyAndOnboard(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.UserSession, error) {
	parsedSignature, err := protocol.ParseCredentialCreationResponseBytes(r.Signed)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] unable to parse public key data")
	}

	challengeId := parsedSignature.Response.CollectedClientData.Challenge

	var tempUser *string
	tempUser, err = getCachedUserFromAssertSession(ctx, challengeId)
	if err != nil {
		return nil, err
	}

	verifyLink := fmt.Sprintf("http://web:3000/public-key/assert/%v", challengeId)

	var res *http.Response
	res, err = http.Post(verifyLink, "application/json", bytes.NewBuffer(r.Signed))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] unable to verify public key:\n%v", err)
	}
	defer res.Body.Close()

	var body []byte
	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	switch res.StatusCode {
	case http.StatusAccepted:

		var user User
		if err = json.Unmarshal([]byte(*tempUser), &user); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "[ERROR] session corrupted. unable to unmarshal user\n%v", err)
		}

		// NOTE: might be better for client sent a similar indicator within request header
		//		clientMode := os.Getenv("CLIENT_MODE")
		//		if clientMode != "dev" {
		_, err = statements[CreateAnUser].Exec(user.Id, user.UserHandle, user.DisplayName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		_, err = statements[CreateAPublicKey].Exec(
			parsedSignature.Raw.Credential.ID,
			parsedSignature.Raw.AttestationResponse.PublicKey,
			parsedSignature.Type,
			parsedSignature.Response.Transports,
			parsedSignature.Response.AttestationObject.AuthData.Flags,
			parsedSignature.Response.AttestationObject.AuthData.AttData.AAGUID,
			user.Id,
		)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
		//		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_PASSKEY_LIFESPAN * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "pesan-backend",
			Subject:   user.Id.String(),
			ID:        uuid.New().String(),
			Audience:  []string{"seller"},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		var accessToken string
		accessToken, err = token.SignedString(apiSecret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		var totalPasskeys uint32 = 1
		return &stub.UserSession{
			AccessToken:  accessToken,
			UserHandle:   user.UserHandle,
			DisplayName:  user.DisplayName,
			TotalPasskey: &totalPasskeys,
		}, nil
	case http.StatusBadRequest:
		return nil, status.Error(codes.InvalidArgument, string(body))
	case http.StatusRequestTimeout:
		return nil, status.Error(codes.DeadlineExceeded, string(body))
	case http.StatusFailedDependency:
		return nil, status.Error(codes.FailedPrecondition, string(body))
	default:
		return nil, status.Error(codes.Internal, string(body))
	}
}

// NOTE: core/pk/attest/discover
func (s *pesanServer) DiscoverLogin(ctx context.Context, _ *emptypb.Empty) (*stub.AttestSession, error) {
	assertation, session, err := wbAuthn.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	err = cacheAttestDiscoverableSession(ctx, *session)
	if err != nil {
		return nil, err
	}

	var options []byte
	options, err = json.Marshal(assertation.Response)
	if err != nil {
		cache.JSONClear(ctx, fmt.Sprintf("attests:%s", session.Challenge), "$")
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &stub.AttestSession{
		Challenge:  options,
		ValidUntil: timestamppb.New(session.Expires),
	}, nil
}

// NOTE: core/pk/attest/verify
func (s *pesanServer) VerifyPublicKeyLogin(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.UserSession, error) {
	data, err := protocol.ParseCredentialRequestResponseBytes(r.Signed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	_, err = getCachedDiscoverableSessionFromAttestSession(ctx, data.Response.CollectedClientData.Challenge)
	if err != nil {
		return nil, err
	}

	verifyLink := fmt.Sprintf("http://web:3000/public-key/attest/discoverable/%v", data.Response.CollectedClientData.Challenge)
	var res *http.Response
	res, err = http.Post(verifyLink, "application/json", bytes.NewBuffer(r.Signed))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	defer res.Body.Close()

	var body []byte
	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	switch res.StatusCode {
	case http.StatusAccepted:

		var userId uuid.UUID
		userId, err = uuid.FromBytes(body)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		var userHandle, displayName string
		var totalPasskeys uint32
		var lastPasswordUpdated sql.NullTime
		err = statements[ReadAnUserProfile].QueryRow(userId).Scan(&userHandle, &displayName, &totalPasskeys, &lastPasswordUpdated)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_PASSKEY_LIFESPAN * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "pesan-backend",
			Subject:   userId.String(),
			ID:        uuid.New().String(),
			Audience:  []string{"seller"},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		var accessToken string
		accessToken, err = token.SignedString(apiSecret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		return &stub.UserSession{
			AccessToken:  accessToken,
			UserHandle:   userHandle,
			DisplayName:  displayName,
			TotalPasskey: &totalPasskeys,
		}, nil
	case http.StatusBadRequest:
		return nil, status.Error(codes.InvalidArgument, string(body))
	case http.StatusRequestTimeout:
		return nil, status.Error(codes.DeadlineExceeded, string(body))
	case http.StatusFailedDependency:
		return nil, status.Error(codes.FailedPrecondition, string(body))
	default:
		return nil, status.Error(codes.Internal, string(body))
	}
}

// NOTE: core/pw/register
func (s *pesanServer) OnboardWithPassword(ctx context.Context, r *stub.OnboardRequest) (*stub.UserSession, error) {
	if len(r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] 0userhandle")
	}

	var displayName string
	if r.DisplayName == nil || len(*r.DisplayName) == 0 {
		displayName = r.UserHandle
	}

	newPassword := r.NewPassword
	if newPassword == nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] 0newpassword")
	}

	if len(*newPassword) < 12 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] <12")
	}

	if !hasAtleastAnUppercase(*newPassword) {
		return nil, status.Errorf(codes.InvalidArgument, "[ERROR] 0uppercase")
	}

	if !hasAtleastADigit(*newPassword) {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] 0digit")
	}

	if !hasAtleastASymbol(*newPassword) {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] 0symbol")
	}

	var user User
	err := statements[ReadAnUserByHandle].QueryRow(r.UserHandle).Scan(&user.Id, &user.UserHandle, &user.DisplayName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.AlreadyExists, "[ERROR] user already exists with the given handle")
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	newId := uuid.New()

	_, err = statements[CreateAnUser].Exec(newId, r.UserHandle, displayName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] unable to create user:\n%v", err)
	}

	_, err = statements[CreateAPassword].Exec(newPassword, newId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] unable to create password:\n%v", err)
	}

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_PASSWORD_LIFESPAN * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-backend",
		Subject:   newId.String(),
		ID:        uuid.New().String(),
		Audience:  []string{"seller"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	var accessToken string
	accessToken, err = token.SignedString(apiSecret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	refreshToken := uuid.New().String()

	var totalPasskeys uint32 = 1
	return &stub.UserSession{
		AccessToken:  accessToken,
		RefreshToken: &refreshToken,
		UserHandle:   r.UserHandle,
		DisplayName:  displayName,
		TotalPasskey: &totalPasskeys,
	}, nil

}

func hasAtleastAnUppercase(str string) bool {
	for _, rune := range str {
		res := unicode.IsUpper(rune)
		if res {
			return res
		}
	}
	return false
}

func hasAtleastASymbol(str string) bool {
	for _, rune := range str {
		res := unicode.IsSymbol(rune)
		if res {
			return res
		}
	}
	return false
}

func hasAtleastADigit(str string) bool {
	for _, rune := range str {
		res := unicode.IsDigit(rune)
		if res {
			return res
		}
	}
	return false
}

// NOTE: core/pw/login
func (s *pesanServer) LoginWithPassword(ctx context.Context, r *stub.PasswordLoginRequest) (*stub.UserSession, error) {
	if len(r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] user handle can't be empty")
	}

	if len(r.Password) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] password can't be empty")
	}

	_, err := statements[ReadAPassword].Exec(r.Password)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "[INFO] combination doesn't match")
	}

	var user User
	var totalPasskey uint32
	var lastPwdUpdated sql.NullTime
	err = statements[ReadAnUserProfile].QueryRow(r.UserHandle).Scan(&user.UserHandle, &user.DisplayName, &totalPasskey, &lastPwdUpdated)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_PASSWORD_LIFESPAN * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-backend",
		Subject:   user.Id.String(),
		ID:        uuid.New().String(),
		Audience:  []string{"seller"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	var accessToken string
	accessToken, err = token.SignedString(apiSecret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &stub.UserSession{
		AccessToken:         accessToken,
		UserHandle:          user.UserHandle,
		DisplayName:         user.DisplayName,
		TotalPasskey:        &totalPasskey,
		LastPasswordUpdated: timestamppb.New(lastPwdUpdated.Time),
	}, nil

}
