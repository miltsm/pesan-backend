package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// NOTE: core-pk-assert-challenge
func (s *pesanServer) OnboardWithPublicKey(ctx context.Context, r *stub.OnboardRequest) (*stub.AssertSession, error) {
	if len(r.UserHandle) < 6 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] user handle needs to be at least 6 characters")
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

// NOTE: core-pk-assert-verify
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

		var accessToken, refreshToken *string
		var accessExpiry *time.Time
		accessToken, refreshToken, accessExpiry, err = newTokens(user.Id)
		if err != nil {
			return nil, err
		}

		var totalPasskeys uint32 = 1
		return &stub.UserSession{
			AccessToken:          []byte(*accessToken),
			RefreshToken:         []byte(*refreshToken),
			UserHandle:           user.UserHandle,
			DisplayName:          user.DisplayName,
			TotalPasskey:         &totalPasskeys,
			AccessTokenExpiresAt: timestamppb.New(*accessExpiry),
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

// NOTE: core-pk-attest-discover
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

// NOTE: core-pk-attest-verify
func (s *pesanServer) VerifyPublicKeyLogin(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.UserSession, error) {
	data, err := protocol.ParseCredentialRequestResponseBytes(r.Signed)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] unable to parse signed challenge")
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
		var userHandle, displayName string
		var totalPasskeys uint32
		var lastPasswordUpdated sql.NullTime
		err = statements[ReadAnUserProfileByCredentialId].QueryRow(body).Scan(&userId, &userHandle, &displayName, &totalPasskeys, &lastPasswordUpdated)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		var accessToken, refreshToken *string
		var accessExpiry *time.Time
		accessToken, refreshToken, accessExpiry, err = newTokens(userId)
		if err != nil {
			return nil, err
		}
		return &stub.UserSession{
			AccessToken:          []byte(*accessToken),
			RefreshToken:         []byte(*refreshToken),
			UserHandle:           userHandle,
			DisplayName:          displayName,
			TotalPasskey:         &totalPasskeys,
			LastPasswordUpdated:  timestamppb.New(lastPasswordUpdated.Time),
			AccessTokenExpiresAt: timestamppb.New(*accessExpiry),
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

// NOTE: core-pw-register
func (s *pesanServer) OnboardWithPassword(ctx context.Context, r *stub.OnboardRequest) (*stub.UserSession, error) {
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

	newId := uuid.New()

	_, err := statements[CreateAnUser].Exec(newId, r.UserHandle, displayName)
	if err != nil {
		if strings.ContainsAny(err.Error(), "SQLSTATE 23505") {
			return nil, status.Error(codes.AlreadyExists, "[ERROR] user already exists with the given handle")
		} else {

			return nil, status.Errorf(codes.Internal, "[ERROR] unable to create user:\n%v", err)
		}
	}

	_, err = statements[CreateAPassword].Exec(newPassword, newId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] unable to create password:\n%v", err)
	}

	var accessToken, refreshToken *string
	var accessExpiry *time.Time
	accessToken, refreshToken, accessExpiry, err = newTokens(newId)
	if err != nil {
		return nil, err
	}

	var totalPasskeys uint32 = 0
	return &stub.UserSession{
		AccessToken:          []byte(*accessToken),
		RefreshToken:         []byte(*refreshToken),
		UserHandle:           r.UserHandle,
		DisplayName:          displayName,
		TotalPasskey:         &totalPasskeys,
		LastPasswordUpdated:  timestamppb.New(time.Now()),
		AccessTokenExpiresAt: timestamppb.New(*accessExpiry),
	}, nil

}

// NOTE: core-pw-login
func (s *pesanServer) LoginWithPassword(ctx context.Context, r *stub.PasswordLoginRequest) (*stub.UserSession, error) {
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

	var accessToken, refreshToken *string
	var accessExpiry *time.Time
	accessToken, refreshToken, accessExpiry, err = newTokens(user.Id)
	if err != nil {
		return nil, err
	}

	return &stub.UserSession{
		AccessToken:          []byte(*accessToken),
		RefreshToken:         []byte(*refreshToken),
		UserHandle:           user.UserHandle,
		DisplayName:          user.DisplayName,
		TotalPasskey:         &totalPasskey,
		LastPasswordUpdated:  timestamppb.New(lastPwdUpdated.Time),
		AccessTokenExpiresAt: timestamppb.New(*accessExpiry),
	}, nil
}

func newTokens(userId uuid.UUID) (*string, *string, *time.Time, error) {
	accessExpiry := time.Now().Add(time.Duration(accessJwtLifespan) * time.Minute)
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(accessExpiry),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-backend",
		Subject:   userId.String(),
		ID:        uuid.New().String(),
		Audience:  []string{"seller"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessToken, err := token.SignedString(accessSecret)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	refreshExpiry := time.Now().Add(time.Duration(refreshJwtLifespan) * time.Minute)

	claims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(refreshExpiry),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-backend",
		Subject:   userId.String(),
		ID:        uuid.New().String(),
		Audience:  []string{"seller"},
	}

	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	var refreshToken string
	refreshToken, err = token.SignedString(refreshSecret)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &accessToken, &refreshToken, &accessExpiry, nil
}

func (s *pesanServer) RefreshSession(ctx context.Context, r *stub.RefreshRequest) (*stub.RefreshReply, error) {
	if len(r.Token) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] missing: refresh token")
	}

	parsedToken, err := jwt.Parse(string(r.Token), func(*jwt.Token) (interface{}, error) {
		return []byte(refreshSecret), nil
	})

	switch {
	case parsedToken.Valid:
		userId := ctx.Value("user_id").(uuid.UUID)
		accessToken, refreshToken, accessExpiry, err := newTokens(userId)
		if err != nil {
			return nil, err
		}
		return &stub.RefreshReply{
			AccessToken:          []byte(*accessToken),
			RefreshToken:         []byte(*refreshToken),
			AccessTokenExpiresAt: timestamppb.New(*accessExpiry),
		}, nil
	case errors.Is(err, jwt.ErrTokenMalformed):
		return nil, status.Error(codes.PermissionDenied, "[WARN] not a token")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return nil, status.Error(codes.PermissionDenied, "[ERROR] invalid token signature")
	case errors.Is(err, jwt.ErrTokenExpired):
		return nil, status.Error(codes.DeadlineExceeded, "[ERROR] session expired")
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return nil, status.Error(codes.Unavailable, "[WARN] token yet valid")
	default:
		return nil, status.Error(codes.PermissionDenied, "[ERROR] invalid refresh token")
	}
}

func (s *pesanServer) ReAuth(ctx context.Context, _ *emptypb.Empty) (*stub.AttestSession, error) {
	userId := ctx.Value("user_id").(uuid.UUID)
	user := &User{
		Id: userId,
	}

	err := checkTotalReAuthAttempts(ctx, userId)
	if err != nil {
		return nil, err
	}

	var rows *sql.Rows
	rows, err = statements[ReadAnUserWithPasskeys].Query(userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	defer rows.Close()

	creds := []webauthn.Credential{}
	for rows.Next() {
		var cred webauthn.Credential
		var transport string
		var flags []byte
		if err = rows.Scan(&user.UserHandle, &user.DisplayName, &cred.ID, &cred.PublicKey, &cred.AttestationType, &transport, &flags, &cred.Authenticator.AAGUID, &cred.Authenticator.SignCount); err != nil {
			continue
		}

		cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(transport))
		creds = append(creds, cred)
		err = json.Unmarshal(flags, &cred.Flags)
	}

	user.Credentials = creds

	var credAssert *protocol.CredentialAssertion
	var session *webauthn.SessionData
	credAssert, session, err = wbAuthn.BeginMediatedLogin(user, protocol.MediationRequired)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var options []byte
	options, err = json.Marshal(credAssert.Response)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	cacheSession := &SessionCache{
		User:    *user,
		Session: *session,
	}
	var jsonUnmarshCacheData []byte
	jsonUnmarshCacheData, err = json.Marshal(cacheSession)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	cacheKey := fmt.Sprintf("reauths:%s", userId.String())
	var res string
	if res, err = cache.JSONSet(ctx, cacheKey, "$", jsonUnmarshCacheData).Result(); err != nil || strings.Compare(res, "OK") != 0 {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var ok bool
	if ok, err = cache.ExpireAt(ctx, cacheKey, session.Expires).Result(); err != nil || !ok {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &stub.AttestSession{
		Challenge: options,
	}, nil
}

func (s *pesanServer) VerifyPublicKeyReAuth(ctx context.Context, r *stub.VerifyPublicKeyRequest) (*stub.RefreshReply, error) {
	userId := ctx.Value("user_id").(uuid.UUID)

	err := checkTotalReAuthAttempts(ctx, userId)
	if err != nil {
		return nil, err
	}

	cacheKey := fmt.Sprintf("reauths:%s", userId.String())

	var res string
	if res, err = cache.JSONGet(ctx, cacheKey, "$").Result(); err != nil {
		incrReAuthCounter(ctx, userId, time.Now().Add(time.Duration(passkeyDuration)*time.Second))
		return nil, status.Errorf(codes.DeadlineExceeded, "[WARN] session ended")
	}

	var cached SessionCache
	err = json.Unmarshal([]byte(res), &cached)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	reader := bytes.NewReader(r.Signed)
	bufReader := bufio.NewReader(reader)

	var req *http.Request
	req, err = http.ReadRequest(bufReader)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var cred *webauthn.Credential
	cred, err = wbAuthn.FinishLogin(&cached.User, cached.Session, req)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "[ERROR] %v", err)
	}

	// NOTE: fine to ignore err
	_, err = statements[UpdateAPublicKey].Exec(cred.AttestationType, cred.Transport, cred.Flags, cred.Authenticator.SignCount, cred.ID)
	// TODO: log err

	var accessToken, refreshToken *string
	var accessExp *time.Time
	accessToken, refreshToken, accessExp, err = newTokens(userId)
	if err != nil {
		return nil, err
	}

	clearReAuthCache(ctx, userId)

	return &stub.RefreshReply{
		AccessToken:          []byte(*accessToken),
		RefreshToken:         []byte(*refreshToken),
		AccessTokenExpiresAt: timestamppb.New(*accessExp),
	}, nil
}

func (s *pesanServer) ReAuthWithPassword(ctx context.Context, r *stub.ReAuthPasswordRequest) (*stub.RefreshReply, error) {
	userId := ctx.Value("user_id").(uuid.UUID)

	err := checkTotalReAuthAttempts(ctx, userId)
	if err != nil {
		return nil, err
	}

	var lastPwdUpdated sql.NullTime
	err = statements[ReadAPassword].QueryRow(userId, r.Password).Scan(&lastPwdUpdated)
	if err != nil {
		incrReAuthCounter(ctx, userId, time.Now().Add(time.Duration(passkeyDuration)*time.Second))
		return nil, status.Errorf(codes.Unauthenticated, "[WARN] combination doesn't match")
	}

	var accessToken, refreshToken *string
	var accessExp *time.Time
	accessToken, refreshToken, accessExp, err = newTokens(userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &stub.RefreshReply{
		AccessToken:          []byte(*accessToken),
		RefreshToken:         []byte(*refreshToken),
		AccessTokenExpiresAt: timestamppb.New(*accessExp),
	}, nil
}
