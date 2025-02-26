package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	pesan_backend "github.com/miltsm/pesan-backend/pesan/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type User struct {
	Id          uuid.UUID
	UserHandle  string
	DisplayName string
	Credentials []webauthn.Credential
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

type OnboardCache struct {
	User
	Session webauthn.SessionData
}

func (s *pesanServer) Onboard(ctx context.Context, r *pesan_backend.CredentialRequest) (*pesan_backend.ChallengeReply, error) {
	if len(r.UserHandle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "user handle can't be empty!")
	}

	err := readUserByUserHandleStmt.QueryRow(r.UserHandle).Scan()
	if err != nil {
		// Check if the user does not exist
		if errors.Is(err, sql.ErrNoRows) {
			key := fmt.Sprintf("users:%s", r.UserHandle)
			var displayName string
			if r.DisplayName == nil {
				displayName = "-"
			} else {
				displayName = *r.DisplayName
			}
			tempUser := &User{
				UserHandle:  r.UserHandle,
				DisplayName: displayName,
			}

			var creation *protocol.CredentialCreation
			var session *webauthn.SessionData
			creation, session, err = s.wbAuthn.BeginMediatedRegistration(tempUser, protocol.MediationOptional)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("Error during registration: %v", err))
			}

			// Cache data
			cacheData := &OnboardCache{
				Session: *session,
				User:    *tempUser,
			}
			jsonCacheData, err := json.Marshal(cacheData)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("JSON marshaling failed: %v", err))
			}

			_, err = cache.JSONSet(ctx, key, "$", jsonCacheData).Result()
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Sprintf("Error setting cache: %v", err))
			}

			var expiredAt = session.Expires.Local().Sub(time.Now().Local())
			var expiring bool
			expiring, err = cache.Expire(ctx, key, expiredAt).Result()
			if err != nil || !expiring {
				return nil, status.Error(codes.Internal, "error setting cache expiration")
			}

			var options []byte
			options, err = json.Marshal(creation.Response)
			if err != nil {
				return nil, status.Error(codes.Internal, "unexpected error!")
			}

			return &pesan_backend.ChallengeReply{
				Challenge: options,
			}, nil
		} else {
			return nil, status.Error(codes.Internal, "unable to create challenge")
		}
	}

	// Existing user, return error
	return nil, status.Error(codes.AlreadyExists, "user already exists with the given handle")
}

func (s *pesanServer) RegisterPublicKey(ctx context.Context, r *pesan_backend.AssertRequest) (*pesan_backend.AssertReply, error) {
	return nil, nil
}
