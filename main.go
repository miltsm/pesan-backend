package main

import (
	"database/sql"

	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	_ "github.com/jackc/pgx/v5/stdlib"
	pesan_backend "github.com/miltsm/pesan-backend/pesan/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	db                                                                        *sql.DB
	newProductStmt, newCategoryStmt, updateCategoryStmt, newProductCategories *sql.Stmt
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
}

func newServer() *pesanServer {
	var err error
	newProductStmt, err = db.Prepare(`INSERT INTO products(product_id, name, description, unit, price) VALUES( $1, $2, $3, $4, $5)`)
	if err != nil {
		log.Fatal(err)
	}

	// client will provide id on their side for an easy sync and redundant API refresh
	newCategoryStmt, err = db.Prepare(`INSERT INTO 
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

	newProductCategories, err = db.Prepare(`INSERT INTO product_categories(product_id, category_id) VALUES( $1, $2)`)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: images
	// TODO: addons
	return &pesanServer{}
}

func (s *pesanServer) UploadProductPhotos(strm grpc.ClientStreamingServer[pesan_backend.NewPhoto, emptypb.Empty]) error {
	// TODO: kafka uploads queue
	return status.Error(codes.Unimplemented, "wip")
}
