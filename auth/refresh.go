package auth

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
)

// RefreshTokenIssuer issues a token that a client can use to issue a new token for a subject without presenting credentials again.
// TODO: add service as a parameter.
type RefreshTokenIssuer interface {
	IssueRefreshToken(ctx context.Context, subject Subject) (string, error)
}

// RefreshTokenAuthenticator authenticates a refresh token.
// TODO: add service as a parameter.
type RefreshTokenAuthenticator interface {
	Authenticate(ctx context.Context, refreshToken string) (Subject, error)
}

// DefaultRefreshTokenIssuer is a naive random string generator.
type DefaultRefreshTokenIssuer struct {
	repository RefreshTokenRepository
}

func NewDefaultRefreshTokenIssuer(repository RefreshTokenRepository) DefaultRefreshTokenIssuer {
	return DefaultRefreshTokenIssuer{
		repository: repository,
	}
}

func (i DefaultRefreshTokenIssuer) IssueRefreshToken(ctx context.Context, subject Subject) (string, error) {
	token := newRefreshToken()

	err := i.repository.SaveSubject(ctx, token, subject)
	if err != nil {
		return "", err
	}

	return token, nil
}

type DefaultRefreshTokenAuthenticator struct {
	repository RefreshTokenRepository
}

func NewDefaultRefreshTokenAuthenticator(repository RefreshTokenRepository) DefaultRefreshTokenAuthenticator {
	return DefaultRefreshTokenAuthenticator{
		repository: repository,
	}
}

func (a DefaultRefreshTokenAuthenticator) Authenticate(ctx context.Context, refreshToken string) (Subject, error) {
	subject, err := a.repository.FindSubject(ctx, refreshToken)
	if err != nil {
		return Subject{}, err
	}

	return subject, nil
}

var refreshCharacters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

const refreshTokenLength = 15

func newRefreshToken() string {
	s := make([]rune, refreshTokenLength)
	max := int64(len(refreshCharacters))
	for i := range s {
		randInt, err := rand.Int(rand.Reader, big.NewInt(max))
		// let '0' serves the failure case
		if err != nil {
			randInt = big.NewInt(0)
		}
		s[i] = refreshCharacters[randInt.Int64()]
	}
	return string(s)
}

type RefreshTokenRepository interface {
	FindSubject(ctx context.Context, refreshTokenID string) (Subject, error)
	SaveSubject(ctx context.Context, refreshTokenID string, subject Subject) error
}

type InMemoryRefreshTokenRepository struct {
	entries map[string]Subject

	initOnce sync.Once
	mu       sync.RWMutex
}

func (r *InMemoryRefreshTokenRepository) init() {
	r.initOnce.Do(func() {
		if r.entries == nil {
			r.entries = make(map[string]Subject)
		}
	})
}

func (r *InMemoryRefreshTokenRepository) FindSubject(_ context.Context, refreshTokenID string) (Subject, error) {
	r.init()
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.entries[refreshTokenID], nil
}

func (r *InMemoryRefreshTokenRepository) SaveSubject(_ context.Context, refreshTokenID string, subject Subject) error {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries[refreshTokenID] = subject

	return nil
}

// RefreshTokenVerifier verifies a token and returns a token ID.
type RefreshTokenVerifier interface {
	VerifyRefreshToken(ctx context.Context, refreshToken string) (string, error)
}
