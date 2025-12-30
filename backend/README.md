# SECRETs
## Access Token Secret (32 bytes → 256 bits)
```

ACCESS_TOKEN_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-44)
echo "ACCESS_TOKEN_SECRET=$ACCESS_TOKEN_SECRET"
```
## Refresh Token Secret (48 bytes → 384 bits, longer-lived)
```
REFRESH_TOKEN_SECRET=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
echo "REFRESH_TOKEN_SECRET=$REFRESH_TOKEN_SECRET"
```