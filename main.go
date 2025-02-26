package main

import (
	"database/sql"

	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/jackc/pgx/v5/stdlib"
	pesan_backend "github.com/miltsm/pesan-backend/pesan/go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	db                                                                                                                                            *sql.DB
	readUserByUserHandleStmt, readUserWithCredentialsStmt, createProductStmt, createCategoryStmt, updateCategoryStmt, createProductCategoriesStmt *sql.Stmt
	cache                                                                                                                                         *redis.Client
)

func main() {
	// region db
	var port, pgPort int64
	var err error
	var pwd []byte
	pgPort, err = strconv.ParseInt(os.Getenv("POSTGRES_PORT"), 10, 32)
	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		pgPort = 5432
	}
	pwd, err = os.ReadFile(os.Getenv("POSTGRES_PASSWORD_FILE"))
	if err != nil {
		log.Fatalf("[ERROR] %v\n", err)
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		os.Getenv("POSTGRES_USER"),
		pwd,
		os.Getenv("POSTGRES_HOST"),
		pgPort,
		os.Getenv("POSTGRES_DB"))
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("[ERROR] unable to use data source name -\n%v\n", err)
	}
	fmt.Println("db connected!")
	//db.SetConnMaxLifetime(0)
	//db.SetMaxIdleConns(50)
	//db.SetMaxOpenConns(50)
	// endregion
	// region Cache
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
	// endregion
	// grpc
	port, err = strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		log.Fatalf("[WARN] %s", err.Error())
		port = 50051
	}
	var lis net.Listener
	lis, err = net.Listen("tcp", fmt.Sprintf("%s:%d", os.Getenv("HOST"), port))
	if err != nil {
		log.Fatalf("[ERROR] %s\n", err.Error())
		return
	}
	srv := grpc.NewServer()
	pesan_backend.RegisterPesanServer(srv, newServer())
	fmt.Printf("listening to port: %d..\n", port)
	err = srv.Serve(lis)
	if err != nil {
		log.Fatalf("[FATAL] %s\n", err.Error())
	}
	//
}

type pesanServer struct {
	pesan_backend.UnimplementedPesanServer
	wbAuthn *webauthn.WebAuthn
}

func newServer() *pesanServer {
	var err error

	// prepare statements
	readUserByUserHandleStmt, err = db.Prepare(`
		SELECT 
			user_id, user_handle, display_name
		FROM
			users
		WHERE
			user_handle = $1
		`)
	if err != nil {
		log.Fatal(err)
	}

	readUserWithCredentialsStmt, err = db.Prepare(`
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
		`)
	if err != nil {
		log.Fatal(err)
	}

	createProductStmt, err = db.Prepare(`INSERT INTO products(product_id, name, description, unit, price) VALUES( $1, $2, $3, $4, $5)`)
	if err != nil {
		log.Fatal(err)
	}

	// client will provide id on their side for an easy sync and redundant API refresh
	createCategoryStmt, err = db.Prepare(`INSERT INTO 
		categories(category_id, name, description, open_hour, closing_hour, weekly) 
		VALUES( $1, $2, $3, $4, $5, $6)`)
	if err != nil {
		log.Fatal(err)
	}

	updateCategoryStmt, err = db.Prepare(`UPDATE categories
		SET name = $2, description = $3, open_hour = $4, closing_hour = $5, weekly = $6
		WHERE category_id = $1`)
	if err != nil {
		log.Fatal(err)
	}

	createProductCategoriesStmt, err = db.Prepare(`INSERT INTO product_categories(product_id, category_id) VALUES( $1, $2)`)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: images
	// TODO: addons

	// Webauthn
	config := &webauthn.Config{
		RPDisplayName: "Pesan Authentication",
		RPID:          "localhost:50051",
		// TODO: include android's identifier
		RPOrigins: []string{"localhost:3000"},
	}

	var wba *webauthn.WebAuthn
	wba, err = webauthn.New(config)
	if err != nil {
		log.Fatal(err)
	}

	return &pesanServer{
		wbAuthn: wba,
	}
}

func (s *pesanServer) UploadProductPhotos(strm grpc.ClientStreamingServer[pesan_backend.NewPhoto, emptypb.Empty]) error {
	// TODO: kafka uploads queue
	return status.Error(codes.Unimplemented, "wip")
}
