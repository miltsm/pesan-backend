package main

import (
	"context"
	"database/sql"

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
	pesanAuth "github.com/miltsm/pesan-backend/proto/auth/v1"
	pesanDevice "github.com/miltsm/pesan-backend/proto/device/v1"
	pesanShop "github.com/miltsm/pesan-backend/proto/shop/v1"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/redis/go-redis/v9"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/metadata"

	"google.golang.org/grpc/status"

	"firebase.google.com/go"
	"firebase.google.com/go/messaging"
)

// NOTE: core - APPLICATION
// *nvim + vertical monitor setup; consider it as table of contents
var (
	port, dbPort, cachePort                                int
	db                                                     *sql.DB
	statements                                             map[StatementKey]*sql.Stmt
	cache                                                  *redis.Client
	wbAuthn                                                *webauthn.WebAuthn
	accessSecret, refreshSecret                            []byte
	passkeyDuration, accessJwtLifespan, refreshJwtLifespan int
	shopJetstream                                          jetstream.JetStream
	fb                                                     *firebase.App
	fbMsgClient                                            *messaging.Client
)

type onboardService struct {
	pesanAuth.UnimplementedOnboardServiceServer
}

type authService struct {
	pesanAuth.UnimplementedAuthServiceServer
}

type reAuthService struct {
	pesanAuth.UnimplementedReAuthServiceServer
}

type deviceService struct {
	pesanDevice.UnimplementedDeviceServiceServer
}

type shopService struct {
	pesanShop.UnimplementedShopServiceServer
}

func main() {
	setEnvs()
	establishDb()
	prepareStatements()
	establishRedis()
	configureWebAuthn()
	establishNats()
	establishFirebase()

	var lis net.Listener
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", os.Getenv("HOST"), port))
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
		db.Close()
		return
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(unaryInterceptor), grpc.StreamInterceptor(streamInterceptor))
	pesanAuth.RegisterOnboardServiceServer(srv, &onboardService{})
	pesanAuth.RegisterAuthServiceServer(srv, &authService{})
	pesanAuth.RegisterReAuthServiceServer(srv, &reAuthService{})
	pesanShop.RegisterShopServiceServer(srv, &shopService{})
	pesanDevice.RegisterDeviceServiceServer(srv, &deviceService{})

	initialiseShopWorkerPeriodicChecks()

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
	logger("[INFO] Method: %s\n", info.FullMethod)
	mctx, err := valid(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	ctx = *mctx

	// NOTE: Logger
	logger("[INFO] Request: %v", req)
	var resp any
	resp, err = handler(ctx, req)
	if err != nil {
		logger("[ERROR] %v", err)
	}
	logger("[INFO] %v", resp)

	return resp, err
}

func logger(format string, a ...any) {
	fmt.Printf("LOG:\t"+format+"\n", a...)
}

func valid(ctx context.Context, methodName string) (*context.Context, error) {
	if strings.HasPrefix(methodName, "/pesan.Public") {
		return &ctx, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.PermissionDenied, "[WARN] missing metadata")
	}

	auth := md["authorization"]

	if len(auth) < 1 {
		return nil, status.Errorf(codes.PermissionDenied, "[WARN] missing authorisation")
	}

	accessToken := strings.TrimPrefix(auth[0], "Bearer ")

	parsedToken, err := jwt.Parse(accessToken, func(*jwt.Token) (interface{}, error) {
		return []byte(accessSecret), nil
	})

	fmt.Printf("access token -> %s\n", accessToken)

	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return nil, status.Error(codes.Unauthenticated, "[WARN] not a token")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		// NOTE: prod wise this could be the sign of malintent
		return nil, status.Error(codes.Unauthenticated, "[ERROR] invalid token signature")
	case errors.Is(err, jwt.ErrTokenExpired):
		fmt.Println("session expired!")
		var userId *uuid.UUID
		userId, err = extractUserIdFromToken(parsedToken)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, "user_id", *userId)

		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		cancel(jwt.ErrTokenExpired)
		return &ctx, nil
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return nil, status.Error(codes.Unavailable, "[WARN] token yet valid")
	case parsedToken.Valid:
		fmt.Println("session valid!")
		var userId *uuid.UUID
		userId, err = extractUserIdFromToken(parsedToken)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, "user_id", *userId)
		return &ctx, nil
	default:
		return nil, status.Errorf(codes.Unauthenticated, "[ERROR] couldnt handle this token: %v", err)
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) RecvMsg(m any) error {
	logger("Receive a message (Type: %T) at %v", m, time.Now().Format(time.RFC3339))
	return w.ServerStream.RecvMsg(m)
}

func (w *wrappedStream) SendMsg(m any) error {
	logger("Send a message (Type: %T) at %v", m, time.Now().Format(time.RFC3339))

	return w.ServerStream.SendMsg(m)
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

func newWrappedStream(s grpc.ServerStream, mCtx context.Context) grpc.ServerStream {
	return &wrappedStream{s, mCtx}
}

func streamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := valid(ss.Context(), info.FullMethod)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "[ERROR] nope")
	}

	err = handler(srv, newWrappedStream(ss, *ctx))
	if err != nil {
		logger("[ERROR] RPC failed with error: %v", err)
	}
	return err
}

func extractUserIdFromToken(access *jwt.Token) (*uuid.UUID, error) {
	userIdStr, err := access.Claims.GetSubject()
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "[ERROR] unknown token owner")
	}
	var userId uuid.UUID
	userId, err = uuid.Parse(userIdStr)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "[ERROR] malformed user id")
	}
	return &userId, nil
}

// NOTE: core - DATABASE
type StatementKey int

const (
	CreateAPasswordUser StatementKey = iota
	CreateAPasskeyUser
	ReadAnUserByHandle
	ReadAnUserProfile
	ReadAnUserProfileByCredentialId
	ReadAnUserWithPasskeys
	CreateAPublicKey
	UpdateAPublicKey
	CreateAPassword
	ReadAPassword
	CreateAShopAndReturnDevices
	ReadAShop
	ReadShops
	ReadShopIds
	UpsertADevice
	ReadDeviceFcm
	UpdateDeviceFcm
	ReadDeviceNKey
	UpdateDeviceNKey
	CreateAShopDevice
	ReadAShopDevice
	UpdateAShopDevice
	DeleteAShopDevice
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
		CreateAPasswordUser: `
		WITH new_user AS (
			INSERT INTO
				users(user_handle, display_name)
			VALUES
				($1, $2)
			RETURNING
				user_id
		),
		new_password AS (
			INSERT INTO
				passwords(hashed, user_id)
			SELECT $3, user_id FROM new_user
		),
		new_device AS (
			INSERT INTO
				devices(name, platform, app_version)
			VALUES
				($4, $5, $6)
			RETURNING
				device_id
		),
		link_user_device AS (
			INSERT INTO
				user_devices(user_id, device_id)
			SELECT
				user_id, device_id
			FROM
				new_user, new_device
		)
		SELECT user_id, device_id FROM new_user, new_device
		`,
		CreateAPasskeyUser: `
		WITH new_user AS (
			INSERT INTO
				users(user_handle, display_name)
			VALUES
				($1, $2)
			RETURNING
				user_Id
		),
		new_public_key AS (
			INSERT INTO
				passkeys(passkey_id, public_key, attestation_type, transport, flags, authenticator_aaguid, user_id)
			SELECT $3, $4, $5, $6, $7, $8, user_id FROM new_user
		),
		new_device AS (
			INSERT INTO
				devices(name, platform, app_version)
			VALUES
				($9, $10, $11)
			RETURNING
				device_id
		),
		link_user_device AS (
			INSERT INTO
				user_devices(user_id, device_Id)
			SELECT
				user_id, device_id
			FROM
				new_user, new_device
		)
		SELECT user_id, device_id FROM new_user, new_device
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
		CreateAShopAndReturnDevices: `
		WITH new_shop as (
			INSERT INTO
			shops(name, tags, open_hour, closing_hour, contacts, operation_days, location, user_id)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING shop_id
		)
		SELECT new_shop.shop_id, devices.device_id, devices.fcm_token
		FROM user_devices
		CROSS JOIN new_shop
		JOIN devices ON devices.device_id = user_devices.device_id
		WHERE user_devices.user_id = $8
		`,
		ReadAShop: `
		SELECT
			name
		FROM
			shops
		WHERE
			shop_id = $1
		`,
		ReadShops: `
		SELECT
			shop_id, name, tags, open_hour, closing_hour, contacts, operation_days, location, role_id, edit_shop, open_close_shop, create_products, edit_products, delete_products, create_orders, edit_orders
		FROM
			shop_roles
		WHERE
			user_id = $1
		`,

		ReadShopIds: `
		SELECT
			shop_id
		FROM
			shop_roles
		WHERE
			user_id = $1
		`,
		UpsertADevice: `
		WITH device_upsert AS (
			INSERT INTO devices(device_id, name, platform, app_version)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (device_id)
			DO UPDATE SET
				name = COALESCE(EXCLUDED.name, devices.name),
				platform = COALESCE(EXCLUDED.platform, devices.platform),
				app_version = COALESCE(EXCLUDED.app_version, devices.app_version)
			WHERE
				(devices.name IS DISTINCT FROM EXCLUDED.name OR
				devices.platform IS DISTINCT FROM EXCLUDED.platform OR
				devices.app_version IS DISTINCT FROM EXCLUDED.app_version)
			RETURNING device_id
		),
		link_user_device AS (
			INSERT INTO
				user_devices(user_id, device_id)
			SELECT
				$5, device_id
			FROM
				device_upsert
			ON CONFLICT
				(user_id, device_id)
			DO NOTHING
		)
		SELECT device_id FROM device_upsert

		`,
		UpdateDeviceFcm: `
		UPDATE
			devices
		SET
			fcm_token = $1
		WHERE
			device_id = $2
		`,
		ReadDeviceNKey: `
		SELECT
			nats_pub_key
		FROM
			devices
		WHERE
			device_id = $1
		`,
		UpdateDeviceNKey: `
		UPDATE
			devices
		SET
			nats_pub_key = $1
		WHERE
			device_id = $2
		`,
		CreateAShopDevice: `
		INSERT INTO
			shop_devices(fcm_topic, shop_id, device_id)
		VALUES
			($1, $2, $3)
		ON CONFLICT
			(shop_id, device_id)
		DO NOTHING
		`,
		ReadAShopDevice: `
		SELECT
			status, last_active
		FROM
			shop_devices
		WHERE
			shop_id = $1 AND device_id = $2
		`,
		UpdateAShopDevice: `
		UPDATE
			shop_devices
		SET
			last_active = $1,
			status = $2
		WHERE
			shop_id = $3 AND device_id = $4
		`,
		DeleteAShopDevice: `
		DELETE FROM
			shop_devices
		WHERE
			shop_id = $1 AND device_id = $2
		`,
		//AND shop_updated_at > $2
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

// NOTE: core - NATS Jetstream
func establishNats() {
	nconn, err := nats.Connect("nats://o4b-nats:4222")
	if err != nil {
		log.Fatalf("[FATAL] Failed to connect to NATS: %v\n", err)
	}

	shopJetstream, err = jetstream.New(nconn)
	if err != nil {
		log.Fatalf("[FATAL] Failed to get Jetstream context: %v\n", err)
	}

	fmt.Println("[INFO] Connected to NATS + Jetstream")
}

// NOTE: core - Firebase
func establishFirebase() {
	opt := option.WithCredentialsFile(os.Getenv("FIREBASE_SDK_PATH"))
	var err error
	fb, err = firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("[FATAL] Failed to establish firebase: %v\n", err)
	}

	fbMsgClient, err = fb.Messaging(context.Background())
	if err != nil {
		log.Fatalf("[FATAL] Failed to setup fb messaging client")
	}

	fmt.Println("[INFO] Firebase Admin establish!")
}
