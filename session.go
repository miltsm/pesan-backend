package main

import (
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
	// NOTE: 1 minute per assert & attest session
	PASSKEY_DURATION = 60
	// NOTE: 5 minutes lifespan for passkey sign up & login
	JWT_LIFESPAN = 5 * 60
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

// NOTE: code-pk-assert-verify
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

		claimsExpiresAt := time.Now().Add(JWT_LIFESPAN * time.Second)
		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(claimsExpiresAt),
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
			AccessToken:          []byte(accessToken),
			UserHandle:           user.UserHandle,
			DisplayName:          user.DisplayName,
			TotalPasskey:         &totalPasskeys,
			AccessTokenExpiresAt: timestamppb.New(claimsExpiresAt),
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

		claimsExpiresAt := time.Now().Add(JWT_LIFESPAN * time.Second)
		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(claimsExpiresAt),
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
			AccessToken:          []byte(accessToken),
			UserHandle:           userHandle,
			DisplayName:          displayName,
			TotalPasskey:         &totalPasskeys,
			AccessTokenExpiresAt: timestamppb.New(claimsExpiresAt),
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

	claimsExpiresAt := time.Now().Add(JWT_LIFESPAN * time.Second)
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_LIFESPAN * time.Second)),
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

	var refreshToken []byte
	if refreshToken, err = uuid.New().MarshalBinary(); err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	var totalPasskeys uint32 = 0
	return &stub.UserSession{
		AccessToken:          []byte(accessToken),
		RefreshToken:         refreshToken,
		UserHandle:           r.UserHandle,
		DisplayName:          displayName,
		TotalPasskey:         &totalPasskeys,
		AccessTokenExpiresAt: timestamppb.New(claimsExpiresAt),
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

	_, err := statements[ReadAPassword].Exec(r.Password)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "[WARN] combination doesn't match")
	}

	var user User
	var totalPasskey uint32
	var lastPwdUpdated sql.NullTime
	err = statements[ReadAnUserProfile].QueryRow(r.UserHandle).Scan(&user.Id, &user.UserHandle, &user.DisplayName, &totalPasskey, &lastPwdUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "[ERROR] user not found")
		}
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	claimsExpiresAt := time.Now().Add(JWT_LIFESPAN * time.Second)
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(claimsExpiresAt),
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
		AccessToken:          []byte(accessToken),
		UserHandle:           user.UserHandle,
		DisplayName:          user.DisplayName,
		TotalPasskey:         &totalPasskey,
		LastPasswordUpdated:  timestamppb.New(lastPwdUpdated.Time),
		AccessTokenExpiresAt: timestamppb.New(claimsExpiresAt),
	}, nil

}
