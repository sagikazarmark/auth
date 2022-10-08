package jwt

import (
	"context"

	"github.com/distribution-auth/auth/auth"
	"github.com/docker/libtrust"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jonboulle/clockwork"
)

// RefreshTokenIssuer issues a refresh token.
type RefreshTokenIssuer struct {
	issuer     string
	signingKey libtrust.PrivateKey

	clock Clock
}

// NewRefreshTokenIssuer returns a new RefreshTokenIssuer.
func NewRefreshTokenIssuer(issuer string, signingKey libtrust.PrivateKey, opts ...RefreshTokenIssuerOption) RefreshTokenIssuer {
	i := RefreshTokenIssuer{
		issuer:     issuer,
		signingKey: signingKey,
	}

	for _, opt := range opts {
		opt.applyRefreshTokenIssuer(&i)
	}

	if i.clock == nil {
		i.clock = clockwork.NewRealClock()
	}

	return i
}

// IssueRefreshToken implements auth.RefreshTokenIssuer.
func (i RefreshTokenIssuer) IssueRefreshToken(ctx context.Context, service string, subject auth.Subject) (string, error) {
	alg, err := detectSigningMethod(i.signingKey)
	if err != nil {
		return "", err
	}

	now := i.clock.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    i.issuer,
		Subject:   string(subject.ID()),
		Audience:  []string{service},
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(alg, claims)

	signedToken, err := token.SignedString(i.signingKey.CryptoPrivateKey())
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// VerifyRefreshToken implements authn.RefreshTokenVerifier.
func (i RefreshTokenIssuer) VerifyRefreshToken(ctx context.Context, service string, refreshToken string) (auth.SubjectID, error) {
	var claims jwt.RegisteredClaims

	token, err := jwt.ParseWithClaims(refreshToken, &claims, nil)
	if err != nil {
		return "", err
	}
	// TODO: validate audience/service/issuer?

	if !token.Valid {
		// TODO: return error?
	}

	claims.VerifyAudience(service, true)
	claims.VerifyIssuer(i.issuer, true)

	return auth.SubjectID(claims.Subject), nil
}
