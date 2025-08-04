package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"

	"strings"
	"time"

	"firebase.google.com/go/messaging"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	stub "github.com/miltsm/pesan-grpc-stubs/go"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

const (
	TOTAL_REAUTH_ATTEMPTS = 3
)

var upperCaseRegex, digitRegex, symbolsRegex = regexp.MustCompile(`[A-Z]`), regexp.MustCompile(`\d`), regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`)
var cacheCtx = context.Background()

func logError(line int, err error) {
	log.Printf("[DEBUG]l%d: %v\n", line, err)
}

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

// NOTE: might need to cache credentials, just incase user request on another device
type PublicKeyChallengeCache struct {
	User    *User                `json:"user,omitempty"`
	Session webauthn.SessionData `json:"session"`
	Options *[]byte              `json:"options,omitempty"`
}

type SessionExpiredError struct{}

func (sExpErr *SessionExpiredError) Error() string {
	return "[ERROR] session expired"
}

type RefreshSessionExpiredError struct{}

func (rSssnExpErr *RefreshSessionExpiredError) Error() string {
	return "[ERROR] refresh session expired"
}

// NOTE: gen-access-token
func newAccessToken(userId uuid.UUID) (*string, *time.Time, error) {
	accessExpiry := time.Now().Add(time.Duration(accessJwtLifespan) * time.Minute)

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(accessExpiry),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-backend",
		Subject:   userId.String(),
		ID:        uuid.New().String(),
		// NOTE: so far no one can reuse the same token; maybe in the future for staff system
		//Audience:  []string{"staff1"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessToken, err := token.SignedString(accessSecret)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &accessToken, &accessExpiry, nil
}

// NOTE: gen-refresh-token
func newRefreshToken(userId uuid.UUID) (*string, *time.Time, error) {
	refreshExpiry := time.Now().Add(time.Duration(refreshJwtLifespan) * time.Minute)

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(refreshExpiry),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-backend",
		Subject:   userId.String(),
		ID:        uuid.New().String(),
		// NOTE: so far no one can reuse the same token; maybe in the future for staff system
		//Audience:  []string{"staff1"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	refreshToken, err := token.SignedString(refreshSecret)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	return &refreshToken, &refreshExpiry, nil
}

// NOTE: attst
func cacheAttestation(session *webauthn.SessionData, user *User, options []byte) error {
	key := fmt.Sprintf("attests:%s", user.UserHandle)

	// NOTE: this might be modified again; create new passkey (logged in)
	cacheData := &PublicKeyChallengeCache{
		Session: *session,
		User:    user,
		Options: &options,
	}

	mrshld, err := json.Marshal(cacheData)
	if err != nil {
		return status.Errorf(codes.Internal, "[ERROR] json marshaling failed: %v", err)
	}

	fmt.Printf("caching: \n%v\n\n", string(mrshld))

	_, err = cache.JSONSet(cacheCtx, key, "$", mrshld).Result()
	if err != nil {
		return status.Errorf(codes.Internal, "[ERROR] unable to cache session: %v", err)
	}

	var res string
	res, err = cache.JSONGet(cacheCtx, key, "$").Result()
	fmt.Printf("get cache %s", res)

	var expiring bool
	expiring, err = cache.ExpireAt(cacheCtx, key, session.Expires).Result()
	if err != nil || !expiring {
		cache.JSONClear(cacheCtx, key, "$")
		return status.Error(codes.Internal, "[ERROR] setting cache expiration")
	}

	return nil
}

// NOTE: attst
func getCachedAttestation(userhandle string) (*PublicKeyChallengeCache, error) {
	key := fmt.Sprintf("attests:%s", userhandle)

	result, err := cache.JSONGet(cacheCtx, key, "$").Result()
	if err != nil {
		return nil, status.Error(codes.DeadlineExceeded, "[ERROR] session ended")
	}

	result = strings.TrimPrefix(result, "[")
	result = strings.TrimSuffix(result, "]")

	var cached PublicKeyChallengeCache
	if err = json.Unmarshal([]byte(result), &cached); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "[ERROR] session corrupted. unable to unmarshal cache data\n%v", err)
	}

	return &cached, nil
}

// NOTE: attst-onboard
func (s *publicSrvr) OnboardWithPublicKey(ctx context.Context, r *stub.OnboardRequest) (*stub.PublicKeyOptions, error) {
	if len(r.UserHandle) < 6 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] user handle needs to be at least 6 characters")
	}

	displayName := r.DisplayName
	if r.DisplayName == nil || len(*displayName) == 0 {
		displayName = &r.UserHandle
	}

	// NOTE: return still valid challenge (cached)
	cached, _ := getCachedAttestation(r.UserHandle)
	if cached != nil {
		return &stub.PublicKeyOptions{
			Challenge:  *cached.Options,
			ValidUntil: timestamppb.New(cached.Session.Expires),
		}, nil
	}

	var user User
	err := statements[ReadAnUserByHandle].QueryRow(r.UserHandle).Scan(&user.Id, &user.UserHandle, &user.DisplayName)
	if err != nil {
		// NOTE: Check if the user does not exist
		if errors.Is(err, sql.ErrNoRows) {
			tempUser := &User{
				UserHandle:  r.UserHandle,
				DisplayName: *displayName,
			}

			var creation *protocol.CredentialCreation
			var session *webauthn.SessionData
			creation, session, err = wbAuthn.BeginMediatedRegistration(tempUser, protocol.MediationOptional)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("[ERROR] %v", err))
			}

			var opts []byte
			opts, err = json.Marshal(creation.Response)
			if err != nil {
				return nil, status.Errorf(codes.Internal, fmt.Sprintf("[ERROR] %v", err))
			}

			// NOTE: Cache data
			if err = cacheAttestation(session, tempUser, opts); err != nil {
				return nil, status.Error(codes.Internal, "[ERROR] unable to cache your session")
			}

			var options []byte
			options, err = json.Marshal(creation.Response)
			if err != nil {
				cache.JSONClear(cacheCtx, fmt.Sprintf("asserts:%s", session.Challenge), "$")
				return nil, status.Error(codes.Internal, "[ERROR] unable to marshal response")
			}

			return &stub.PublicKeyOptions{
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

// NOTE: attst-onboard
func (s *publicSrvr) VerifyPublicKeyAndOnboard(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.UserSession, error) {
	if r.UserHandle == nil || len(*r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] missing user handle")
	}

	cached, err := getCachedAttestation(*r.UserHandle)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewBuffer(r.Signed)
	req := http.Request{
		Body: io.NopCloser(reader),
	}

	var cred *webauthn.Credential
	cred, err = wbAuthn.FinishRegistration(cached.User, cached.Session, &req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid signature")
	}

	//	var txn *sql.Tx
	//	txn, err = db.Begin()
	//	if err != nil {
	//		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	//	}
	//
	//	_, err = txn.Stmt(statements[CreateAnUser]).Exec(cached.User.Id, cached.User.UserHandle, cached.User.DisplayName)
	//	if err != nil {
	//		txn.Rollback()
	//		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	//	}
	//
	//	_, err = txn.Stmt(statements[CreateAPublicKey]).Exec(cred.ID, cred.PublicKey, cred.AttestationType, cred.Transport, cred.Flags, cred.Authenticator.AAGUID, cached.User.Id)
	//

	// NOTE: create device profile of this new user
	var dvcNm *string
	var pltfrm *stub.Platform
	var appVer *string
	if r.DeviceInfo != nil {
		dvcNm = r.DeviceInfo.DeviceName
		pltfrm = r.DeviceInfo.Platform
		appVer = r.DeviceInfo.AppVersion
	}

	var userId uuid.UUID
	var deviceId uuid.UUID
	err = statements[CreateAPasskeyUser].QueryRow(cached.User.UserHandle, cached.User.DisplayName, cred.ID, cred.PublicKey, cred.AttestationType, cred.Transport, cred.Flags, cred.Authenticator.AAGUID, dvcNm, pltfrm, appVer).Scan(&userId, &deviceId)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return nil, status.Error(codes.AlreadyExists, "[ERROR] user already exists")
			} else {
				return nil, status.Errorf(codes.Internal, "[ERROR] %v", pgErr)
			}
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	var accessToken, refreshToken *string
	var accessExpiry, refreshExpiry *time.Time
	accessToken, accessExpiry, err = newAccessToken(cached.User.Id)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExpiry, err = newRefreshToken(cached.User.Id)
	if err != nil {
		return nil, err
	}

	var totalPasskeys uint32 = 1
	return &stub.UserSession{
		AccessToken:           []byte(*accessToken),
		RefreshToken:          []byte(*refreshToken),
		UserHandle:            cached.User.UserHandle,
		DisplayName:           cached.User.DisplayName,
		TotalPasskey:          &totalPasskeys,
		AccessTokenExpiresAt:  timestamppb.New(*accessExpiry),
		RefreshTokenExpiresAt: timestamppb.New(*refreshExpiry),
		DeviceId: &stub.UuId{
			Id: []byte(deviceId.String()),
		},
	}, nil
}

// NOTE: pw-onboard
func (s *publicSrvr) OnboardWithPassword(ctx context.Context, r *stub.OnboardRequest) (*stub.UserSession, error) {
	if len(r.UserHandle) < 6 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] userhandle<6")
	}

	// NOTE: if user didnt provide displayName, we;ll use their userHandle instead
	var displayName string
	if r.DisplayName == nil || len(*r.DisplayName) == 0 {
		displayName = r.UserHandle
	} else {
		displayName = *r.DisplayName
	}

	newPassword := string(r.NewPassword)

	if len(newPassword) < 12 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] newpassword<12")
	}
	if !upperCaseRegex.MatchString(newPassword) {
		return nil, status.Errorf(codes.InvalidArgument, "[WARN] 0uppercase")
	}
	if !digitRegex.MatchString(newPassword) {
		return nil, status.Error(codes.InvalidArgument, "[WARN] 0digit")
	}
	if !symbolsRegex.MatchString(newPassword) {
		return nil, status.Error(codes.InvalidArgument, "[WARN] 0symbol")
	}

	// NOTE: create device profile of this new user
	var dvcNm *string
	var pltfrm *stub.Platform
	var appVer *string
	if r.DeviceInfo != nil {
		dvcNm = r.DeviceInfo.DeviceName
		pltfrm = r.DeviceInfo.Platform
		appVer = r.DeviceInfo.AppVersion
	}

	var userId uuid.UUID
	var deviceId uuid.UUID
	err := statements[CreateAPasswordUser].QueryRow(r.UserHandle, displayName, newPassword, dvcNm, pltfrm, appVer).Scan(&userId, &deviceId)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return nil, status.Error(codes.AlreadyExists, "[ERROR] user already exists")
			} else {
				return nil, status.Errorf(codes.Internal, "[ERROR] %v", pgErr)
			}
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	var accessToken, refreshToken *string
	var accessExpiry, refreshExpiry *time.Time
	accessToken, accessExpiry, err = newAccessToken(userId)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExpiry, err = newRefreshToken(userId)
	if err != nil {
		return nil, err
	}

	var totalPasskeys uint32 = 0
	return &stub.UserSession{
		AccessToken:           []byte(*accessToken),
		RefreshToken:          []byte(*refreshToken),
		UserHandle:            r.UserHandle,
		DisplayName:           displayName,
		TotalPasskey:          &totalPasskeys,
		LastPasswordUpdated:   timestamppb.New(time.Now()),
		AccessTokenExpiresAt:  timestamppb.New(*accessExpiry),
		RefreshTokenExpiresAt: timestamppb.New(*refreshExpiry),
		DeviceId: &stub.UuId{
			Id: []byte(deviceId.String()),
		},
	}, nil

}

// NOTE: assrt
func cacheAssertation(cacheId string, session webauthn.SessionData, user *User, options *[]byte) error {
	cacheKey := fmt.Sprintf("asserts:%s", cacheId)

	mrshd, err := json.Marshal(&PublicKeyChallengeCache{
		Session: session,
		User:    user,
		Options: options,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var res string
	res, err = cache.JSONSet(cacheCtx, cacheKey, "$", mrshd).Result()
	if err != nil || strings.Compare(res, "OK") != 0 {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var isExpiring bool
	isExpiring, err = cache.ExpireAt(cacheCtx, cacheKey, session.Expires).Result()
	if err != nil || !isExpiring {
		clearCachedAssertation(session.Challenge)
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return nil
}

// NOTE: assrt
// NOTE: challengeId can be userId
func getCachedAssertation(challengeId string) (*PublicKeyChallengeCache, error) {
	cacheKey := fmt.Sprintf("asserts:%s", challengeId)
	res, err := cache.JSONGet(cacheCtx, cacheKey, "$").Result()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	res = strings.TrimPrefix(res, "[")
	res = strings.TrimSuffix(res, "]")

	fmt.Printf("get cached assert: %s\n\n", res)

	var cached PublicKeyChallengeCache
	if err = json.Unmarshal([]byte(res), &cached); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "[ERROR] session corrupted. unable to unmarshal cache data\n%v", err)
	}

	return &cached, nil
}

// NOTE: assrt
func clearCachedAssertation(challengeId string) {
	cache.JSONClear(cacheCtx, fmt.Sprintf("asserts:%s", challengeId), "$")
}

// NOTE: assrt-login
func (s *publicSrvr) DiscoverLogin(ctx context.Context, _ *emptypb.Empty) (*stub.PublicKeyOptions, error) {
	assertation, session, err := wbAuthn.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var mrshlAssrt []byte
	mrshlAssrt, err = json.Marshal(assertation.Response)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] mrshl492")
	}

	err = cacheAssertation(session.Challenge, *session, nil, &mrshlAssrt)
	if err != nil {
		return nil, err
	}

	var options []byte
	options, err = json.Marshal(assertation.Response)
	if err != nil {
		clearCachedAssertation(session.Challenge)
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &stub.PublicKeyOptions{
		Challenge:  options,
		ValidUntil: timestamppb.New(session.Expires),
	}, nil
}

// NOTE: assrt-login
func (s *publicSrvr) VerifyPublicKeyLogin(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.UserSession, error) {
	data, err := protocol.ParseCredentialRequestResponseBytes(r.Signed)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] unable to parse signed challenge")
	}

	var cached *PublicKeyChallengeCache
	cached, err = getCachedAssertation(data.Response.CollectedClientData.Challenge)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewBuffer(r.Signed)
	req := http.Request{
		Body: io.NopCloser(reader),
	}

	var userId uuid.UUID
	var cred *webauthn.Credential
	cred, err = wbAuthn.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		//var userId uuid.UUID
		userId, err = uuid.Parse(string(userHandle))
		if err != nil {
			return nil, err
		}

		var rows *sql.Rows
		rows, err = statements[ReadAnUserWithPasskeys].Query(userId)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		var username, displayName string
		creds := []webauthn.Credential{}
		for rows.Next() {
			var cred webauthn.Credential
			var trnsprt string
			var flags []byte
			if err = rows.Scan(&username, &displayName, &cred.ID, &cred.PublicKey, &cred.AttestationType, &trnsprt, &flags, &cred.Authenticator.AAGUID, &cred.Authenticator.SignCount); err != nil {
				// TODO: log error
				continue
			}
			cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(trnsprt))
			err = json.Unmarshal(flags, &cred.Flags)
			creds = append(creds, cred)
		}

		return &User{
			Id:          userId,
			UserHandle:  username,
			DisplayName: displayName,
			Credentials: creds,
		}, nil
	}, cached.Session, &req)

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "[ERROR] %v", err)
	}

	// NOTE: create or update device profile of this existing user
	dvcId := uuid.New()
	var dvcNm *string
	var pltfrm *stub.Platform
	var appVer *string
	if r.DeviceInfo != nil {
		if r.DeviceInfo.DeviceId != nil && len(r.DeviceInfo.DeviceId.Id) > 0 {
			deviceId, err2 := uuid.ParseBytes(r.DeviceInfo.DeviceId.Id)
			if err2 != nil {
				fmt.Printf("[ERROR] invalid device id: %v\n", err)
			}
			dvcId = deviceId
		}

		if r.DeviceInfo.DeviceName != nil && len(*r.DeviceInfo.DeviceName) > 0 {
			dvcNm = r.DeviceInfo.DeviceName
		}

		if r.DeviceInfo.Platform != nil {
			pltfrm = r.DeviceInfo.Platform
		}

		if r.DeviceInfo.AppVersion != nil && len(*r.DeviceInfo.AppVersion) > 0 {
			appVer = r.DeviceInfo.AppVersion
		}
	}

	// NOTE: it's fine to ignore err here
	err2 := statements[UpsertADevice].QueryRow(dvcId, dvcNm, pltfrm, appVer, userId).Scan(&dvcId)
	if err2 != nil {
		fmt.Printf("[ERROR] unable to upsert a device:\n%v", err2)
	}

	//var userId uuid.UUID
	var userHandle, displayName string
	var totalPasskeys uint32
	var lastPasswordUpdated sql.NullTime
	err = statements[ReadAnUserProfileByCredentialId].QueryRow(cred.ID).Scan(&userId, &userHandle, &displayName, &totalPasskeys, &lastPasswordUpdated)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var accessToken, refreshToken *string
	var accessExpiry, refreshExpiry *time.Time
	accessToken, accessExpiry, err = newAccessToken(userId)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExpiry, err = newRefreshToken(userId)
	if err != nil {
		return nil, err
	}

	return &stub.UserSession{
		AccessToken:           []byte(*accessToken),
		RefreshToken:          []byte(*refreshToken),
		UserHandle:            userHandle,
		DisplayName:           displayName,
		TotalPasskey:          &totalPasskeys,
		LastPasswordUpdated:   timestamppb.New(lastPasswordUpdated.Time),
		AccessTokenExpiresAt:  timestamppb.New(*accessExpiry),
		RefreshTokenExpiresAt: timestamppb.New(*refreshExpiry),
		DeviceId: &stub.UuId{
			Id: []byte(dvcId.String()),
		},
	}, nil
}

// NOTE: pw-login
func (s *publicSrvr) LoginWithPassword(ctx context.Context, r *stub.PasswordLoginRequest) (*stub.UserSession, error) {
	if len(r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] user handle can't be empty")
	}

	if len(r.Password) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] password can't be empty")
	}

	var user User
	var totalPasskey uint32
	err := statements[ReadAnUserProfile].QueryRow(r.UserHandle).Scan(&user.Id, &user.UserHandle, &user.DisplayName, &totalPasskey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "[ERROR] user not found")
		}
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var lastPwdUpdated sql.NullTime
	err = statements[ReadAPassword].QueryRow(user.Id, r.Password).Scan(&lastPwdUpdated)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "[WARN] combination doesn't match")
	}

	dvcId := uuid.New()
	var dvcNm *string
	var pltfrm *stub.Platform
	var appVer *string
	if r.DeviceInfo != nil {
		if r.DeviceInfo.DeviceId != nil && len(r.DeviceInfo.DeviceId.Id) > 0 {
			deviceId, err2 := uuid.ParseBytes(r.DeviceInfo.DeviceId.Id)
			if err2 != nil {
				fmt.Printf("[ERROR] invalid device id: %v\n", err)
			}
			dvcId = deviceId
			fmt.Printf("device id: %v\n", dvcId)
		}

		if r.DeviceInfo.DeviceName != nil && len(*r.DeviceInfo.DeviceName) > 0 {
			dvcNm = r.DeviceInfo.DeviceName
		}

		if r.DeviceInfo.Platform != nil {
			pltfrm = r.DeviceInfo.Platform
		}

		if r.DeviceInfo.AppVersion != nil && len(*r.DeviceInfo.AppVersion) > 0 {
			appVer = r.DeviceInfo.AppVersion
		}
	}

	err3 := statements[UpsertADevice].QueryRow(dvcId, dvcNm, pltfrm, appVer, user.Id).Scan(&dvcId)
	if err3 != nil {
		fmt.Printf("[ERROR] unable to upsert a device:\n%v\n", err3)
	}

	var accessToken, refreshToken *string
	var accessExpiry, refreshExpiry *time.Time
	accessToken, accessExpiry, err = newAccessToken(user.Id)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExpiry, err = newRefreshToken(user.Id)
	if err != nil {
		return nil, err
	}

	return &stub.UserSession{
		AccessToken:           []byte(*accessToken),
		RefreshToken:          []byte(*refreshToken),
		UserHandle:            user.UserHandle,
		DisplayName:           user.DisplayName,
		TotalPasskey:          &totalPasskey,
		LastPasswordUpdated:   timestamppb.New(lastPwdUpdated.Time),
		AccessTokenExpiresAt:  timestamppb.New(*accessExpiry),
		RefreshTokenExpiresAt: timestamppb.New(*refreshExpiry),
		DeviceId: &stub.UuId{
			Id: []byte(dvcId.String()),
		},
	}, nil
}

// NOTE: refresh
func refreshSession(userId uuid.UUID, token []byte) (*stub.RefreshReply, error) {
	if len(token) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "[ERROR] refresh token missing")
	}

	prsdToken, err := jwt.Parse(string(token), func(*jwt.Token) (interface{}, error) {
		return []byte(refreshSecret), nil
	})

	switch {
	case prsdToken.Valid:
		aTkn, aExp, err := newAccessToken(userId)
		if err != nil {
			return nil, err
		}
		return &stub.RefreshReply{
			AccessToken:          []byte(*aTkn),
			AccessTokenExpiresAt: timestamppb.New(*aExp),
		}, nil
	case errors.Is(err, jwt.ErrTokenExpired):
		// NOTE: shouldnt use DeadlineExceeded; might conflict with actual timeout
		return nil, err
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return nil, status.Error(codes.Unavailable, "[WARN] token yet valid")
	default:
		return nil, status.Errorf(codes.PermissionDenied, "[ERROR] invalid token")
	}
}

// NOTE: refresh
func (s *publicSrvr) RefreshSession(ctx context.Context, r *stub.RefreshRequest) (*stub.RefreshReply, error) {
	usrId := ctx.Value("user_id").(uuid.UUID)
	return refreshSession(usrId, r.Token)
}

// NOTE: reauth
// NOTE: this an extension of auth middleware
func requiresRefreshOrReauth(ctx context.Context, refreshTkn []byte, reauthData *stub.ReAuthRequest) (*stub.RefreshReply, *stub.PublicKeyOptions, error) {
	userId := ctx.Value("user_id").(uuid.UUID)
	var freshSession *stub.RefreshReply
	err := context.Cause(ctx)
	if err != nil {
		// NOTE: access token expired
		if errors.Is(err, jwt.ErrTokenExpired) {
			var refreshErr, reauthErr, optsErr error
			switch {
			case reauthData != nil && len(reauthData.Password) > 0:
				freshSession, reauthErr = passwordReauthentication(userId, reauthData.Password)
				if reauthErr != nil {
					return nil, nil, reauthErr
				}
				return freshSession, nil, nil
			case reauthData != nil && len(reauthData.Signed) > 0:
				freshSession, reauthErr = validatePubKey(ctx, reauthData.Signed)
				if reauthErr != nil {
					return nil, nil, reauthErr
				}
				return freshSession, nil, nil
			default:
				freshSession, refreshErr = refreshSession(userId, refreshTkn)
				if refreshErr != nil {
					if errors.Is(refreshErr, jwt.ErrTokenExpired) {
						var opts *stub.PublicKeyOptions
						opts, optsErr = getLoginChallenge(userId)

						if optsErr != nil {
							return nil, nil, optsErr
						}
						return nil, &stub.PublicKeyOptions{
							Challenge:  opts.Challenge,
							ValidUntil: opts.ValidUntil,
						}, nil
					} else {
						return nil, nil, refreshErr
					}
				}

				return freshSession, nil, nil
			}
			// NOTE: proceed normally, but the only difference new accessToken & refreshToken will be returning to user along
		} else {
			return nil, nil, err
		}
	}
	// NOTE: if not proceed normally
	return nil, nil, nil
}

// NOTE: reauth
func checkTotalReAuthAttempts(userId uuid.UUID) error {
	attemptKey := fmt.Sprintf("reauths:attempts:%s", userId.String())
	totalAttemptsStr, err := cache.Get(cacheCtx, attemptKey).Result()
	if err != nil {
		// NOTE: fresh reattempt
		return incrReAuthCounter(userId, time.Now().Add(time.Duration(passkeyDuration)*time.Second))
	}
	var totalAttempts int
	if totalAttempts, err = strconv.Atoi(totalAttemptsStr); err != nil {
		return status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	if totalAttempts > 2 {
		return status.Error(codes.PermissionDenied, "[ERROR] reauth maxed; please login back")
	}
	return nil
}

// NOTE: reauth
func incrReAuthCounter(userId uuid.UUID, expiresAt time.Time) error {
	cacheKey := fmt.Sprintf("reauths:attempts:%s", userId.String())
	_, err := cache.Incr(cacheCtx, cacheKey).Result()
	if err != nil {
		return err
	}
	var ok bool
	if ok, err = cache.ExpireAt(cacheCtx, cacheKey, expiresAt).Result(); err != nil {
		return err
	}
	if !ok {
		return status.Errorf(codes.Internal, "[ERROR] unable to cache reauth session")
	}
	return nil
}

// NOTE: reauth
func clearReAuthCache(userId uuid.UUID) {
	attemptKey := fmt.Sprintf("reauths:attempts:%s", userId.String())
	cache.Del(cacheCtx, attemptKey).Result()
}

// NOTE: reauth
func getLoginChallenge(userId uuid.UUID) (*stub.PublicKeyOptions, error) {
	// NOTE: check cache first
	cached, _ := getCachedAssertation(userId.String())
	if cached != nil {
		return &stub.PublicKeyOptions{
			Challenge:  *cached.Options,
			ValidUntil: timestamppb.New(cached.Session.Expires),
		}, nil
	}

	// NOTE: create new
	user := &User{
		Id: userId,
	}

	rows, err := statements[ReadAnUserWithPasskeys].Query(userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	creds := []webauthn.Credential{}
	for rows.Next() {
		var cred webauthn.Credential
		var trnsprt string
		var flags []byte

		if err = rows.Scan(&user.UserHandle, &user.DisplayName, &cred.ID, &cred.PublicKey, &cred.AttestationType, &trnsprt, &flags, &cred.Authenticator.AAGUID, &cred.Authenticator.SignCount); err != nil {
			continue
		}

		cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(trnsprt))
		err = json.Unmarshal(flags, &cred.Flags)
		if err != nil {
			continue
		}
		creds = append(creds, cred)
	}
	user.Credentials = creds

	if len(user.UserHandle) == 0 {
		return nil, status.Error(codes.PermissionDenied, "[INFO] user doesnt exist")
	}

	if len(creds) == 0 {
		return nil, status.Error(codes.NotFound, "[WARN] user have no passkeys")
	}

	var crdAssrt *protocol.CredentialAssertion
	var sssn *webauthn.SessionData
	crdAssrt, sssn, err = wbAuthn.BeginMediatedLogin(user, protocol.MediationRequired)
	if err != nil {
		// NOTE: return at line 845 to avoid the needs below
		//if err == "Found no credentials for users"
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var opts []byte
	opts, err = json.Marshal(crdAssrt.Response)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	err = cacheAssertation(userId.String(), *sssn, user, &opts)
	if err != nil {
		return nil, err
	}

	return &stub.PublicKeyOptions{
		Challenge:  opts,
		ValidUntil: timestamppb.New(sssn.Expires),
	}, nil
}

// NOTE: reauth
func (s *protectedSrvr) ReAuth(ctx context.Context, _ *emptypb.Empty) (*stub.PublicKeyOptions, error) {
	userId := ctx.Value("user_id").(uuid.UUID)
	return getLoginChallenge(userId)
}

// NOTE: reauth
func (s *protectedSrvr) VerifyPublicKeyReAuth(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.RefreshReply, error) {
	return validatePubKey(ctx, r.Signed)
}

// NOTE: reauth
func validatePubKey(ctx context.Context, signed []byte) (*stub.RefreshReply, error) {
	userId := ctx.Value("user_id").(uuid.UUID)

	err := checkTotalReAuthAttempts(userId)
	if err != nil {
		return nil, err
	}

	var cached *PublicKeyChallengeCache
	cached, err = getCachedAssertation(userId.String())
	if err != nil {
		return nil, err
	}

	reader := bytes.NewBuffer(signed)

	req := http.Request{
		Body: io.NopCloser(reader),
	}

	var cred *webauthn.Credential
	cred, err = wbAuthn.FinishLogin(cached.User, cached.Session, &req)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "[ERROR] %v", err)
	}

	// NOTE: fine to ignore err
	_, err = statements[UpdateAPublicKey].Exec(cred.AttestationType, cred.Transport, cred.Flags, cred.Authenticator.SignCount, cred.ID)
	// TODO: log err

	var accessToken, refreshToken *string
	var accessExp, refreshExpiry *time.Time
	accessToken, accessExp, err = newAccessToken(userId)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExpiry, err = newRefreshToken(userId)
	if err != nil {
		return nil, err
	}

	clearReAuthCache(userId)

	return &stub.RefreshReply{
		AccessToken:           []byte(*accessToken),
		RefreshToken:          []byte(*refreshToken),
		AccessTokenExpiresAt:  timestamppb.New(*accessExp),
		RefreshTokenExpiresAt: timestamppb.New(*refreshExpiry),
	}, nil
}

// NOTE: reauth
func (s *protectedSrvr) ReAuthWithPassword(ctx context.Context, r *stub.ReAuthPasswordRequest) (*stub.RefreshReply, error) {
	userId := ctx.Value("user_id").(uuid.UUID)
	return passwordReauthentication(userId, r.Password)
}

// NOTE: reauth
func passwordReauthentication(userId uuid.UUID, pw []byte) (*stub.RefreshReply, error) {
	err := checkTotalReAuthAttempts(userId)
	if err != nil {
		return nil, err
	}

	var lastPwdUpdated sql.NullTime
	err = statements[ReadAPassword].QueryRow(userId, pw).Scan(&lastPwdUpdated)
	if err != nil {
		logError(1006, err)
		incrReAuthCounter(userId, time.Now().Add(time.Duration(passkeyDuration)*time.Second))
		return nil, status.Errorf(codes.Unauthenticated, "[WARN] combination doesnt match")
	}

	var accssTkn, rfshTkn *string
	var accssExp, rfshExp *time.Time
	accssTkn, accssExp, err = newAccessToken(userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	rfshTkn, rfshExp, err = newRefreshToken(userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	clearReAuthCache(userId)

	return &stub.RefreshReply{
		AccessToken:           []byte(*accssTkn),
		RefreshToken:          []byte(*rfshTkn),
		AccessTokenExpiresAt:  timestamppb.New(*accssExp),
		RefreshTokenExpiresAt: timestamppb.New(*rfshExp),
	}, nil
}

// NOTE: session update
func (s *protectedSrvr) SetFcmToken(ctx context.Context, r *stub.SetFcmRequest) (*emptypb.Empty, error) {
	fmt.Println("setting fcm token..")
	// TODO: need to revised this with uuid.Parse; it wont crash the server, would rather return an error
	userId := ctx.Value("user_id").(uuid.UUID)

	// NOTE: device_id is guarantee upon successful sign in/login
	deviceId, err := uuid.Parse(string(r.DeviceId.Id))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid device id")
	}
	if len(r.NewFcmToken) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid fcm token!")
	}

	// NOTE: update fcm-token first
	_, err2 := statements[UpdateDeviceFcm].Exec(r.NewFcmToken, deviceId)
	if err2 != nil {
		fmt.Printf("[ERROR] unable to update fcm: %v\n", err2)
		return &emptypb.Empty{}, nil
	}

	// NOTE: sub shop fcm topics
	var shops *sql.Rows
	shops, err = statements[ReadShopIds].Query(userId)
	if err != nil {
		// TODO: subscribe when they created a new shop
		return &emptypb.Empty{}, nil
	}
	defer shops.Close()

	fcmCtx := context.Background()
	for shops.Next() {
		var shopId uuid.UUID
		err3 := shops.Scan(&shopId)
		if err3 != nil {
			fmt.Printf("[WARN] Failed to scan shopId: %v\n", err3)
			continue
		}
		topic := fmt.Sprintf("shops_%s_itrnl", shopId.String())

		// NOTE: FCM subscription
		var res *messaging.TopicManagementResponse
		res, err3 = fbMsgClient.SubscribeToTopic(fcmCtx, []string{r.NewFcmToken}, topic)
		if err3 != nil {
			fmt.Printf("[WARN] unable to subscibe to %s\n%v", topic, err3)
			continue
		}

		if res.FailureCount > 0 {
			for idx := 0; idx < len(res.Errors); idx++ {
				fmt.Printf("[WARN] Failed subscribing to topic %s: %s\n", topic, res.Errors[idx].Reason)
			}
		}

		if res.SuccessCount == 1 {
			_, err3 = statements[CreateAShopDevice].Exec(topic, shopId, deviceId)
			if err3 != nil {
				fmt.Printf("[ERROR] unable to create shop device: %v", err3)
			}
		}
	}

	return &emptypb.Empty{}, nil
}
