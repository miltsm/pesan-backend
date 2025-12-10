# Pesan gRPC

## GO
```
protoc \
    --proto_path=. \
    --go_out=../backend/proto/ \
    --go_opt=paths=source_relative \
    --go-grpc_out=../backend/proto/ \
    --go-grpc_opt=paths=source_relative \
    $(find . -name "*.proto")
```

## Kotlin