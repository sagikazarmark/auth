package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/docker/libtrust"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sagikazarmark/registry-auth/auth"
)

type idGeneratorStub struct {
	id string
}

func (g idGeneratorStub) GenerateID() (string, error) {
	return g.id, nil
}

func TestAccessTokenIssuer_IssueAccessToken(t *testing.T) {
	signingKey, err := libtrust.LoadKeyFile("testdata/private.pem")
	require.NoError(t, err)

	const (
		id         = "vb86v87g87g87g87bb897vcw2367fv723vc8236"
		issuer     = "issuer.example.com"
		service    = "service.example.com"
		expiration = 15 * time.Minute
	)

	now := time.UnixMicro(1257894000000)
	idGenerator := idGeneratorStub{id}
	clock := clockwork.NewFakeClockAt(now)

	tokenIssuer := NewAccessTokenIssuer(issuer, signingKey, expiration, WithClock(clock), WithIDGenerator(idGenerator))

	subject := subjectStub{
		id: "id",
	}

	scopes := []auth.Scope{
		{
			Resource: auth.Resource{
				Type: "repository",
				Name: "path/to/repo",
			},
			Actions: []string{"pull", "push"},
		},
	}

	token, err := tokenIssuer.IssueAccessToken(context.Background(), service, subject, scopes)
	require.NoError(t, err)

	expected := auth.AccessToken{
		Payload:   "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImtpZCI6IjdCVE06NllVRDpYSE00OjRNWUY6Qk1RWTo2N05YOkFTWVE6VVVBRjo2N1FaOlA3SjY6SktJMjpaT0FBIiwia3R5IjoiUlNBIiwibiI6Ind0bDROcC1YM3Z0cUotZU1oaXc5SWhkRzkyclR5Ukg1c05QVmZsZmZGUHlvZnMyLWtJT0R2bVlOWmFwckRMNHlBU2lvR2k2SkFHamlIcVV5d1JyMUtmTGhsX3RpWGt3YndNalBkZmxwUURuMXpjTC1uWjdkRU1VZVU4WTN0ekN3TVg2bHBVLVd2MDFmNERHNk85eFAzQXJnN0lCNVM0ZmdTXzhCTE5tREhZaUZmSFlzSHBhMFI2Wk10UV9VcG9yTXJDcDlnR0VaYkswbkVnTnZyWTFCel9ZRUtRUFZZNUxRTTdfZFoxMWcwS3hibGpBa3hmZnVoY0RUNE9rN1FTdnRGWHVTbFBINktNbDdtYjRJaERkaHRzbHU3YnExV3lkdmEwSmtwajQ5QlFuci13VkJHZU5ROFJHSUhXaGJqWE5uNzVMdF9rNGZCOUxnRGViQmRTNkpiSUlEUUNheHU3dmpnUE9EN2tDcUVxRVFYR0VjMHdzNlZ3MlAzLUF0NXhzNHJnVFhNYVU4NmdpVXExVXFGOE0zWFRDcEtXLTgyaHN6NjRIZk1IVUNpbVpiX2pnM205N3A2Wm9oU0tSaHlSWjRyLW05U0hzMnVBSXJkZmYzOGhLcEVGUWJCTWs1SkN5a05sTDViQWxNbjItZmpQZHdjMV9TWi1Db3hIQjlrVlhoZTRIRTdYU185bXJhTUdwZlVEOGY0OTBwZFZOVkd2NHVyenJSMDMxZ3RRbzg4SWRsb2ZkRTBGOFpBQWp6a3dUS1c3WGRpMzJXTUdRNlE1b3F6amxfc1V2OUV4Qy1pc2R6MklHX3RHU184M0gxN1N0RERsd0Jpa21iMEYxQUZNM2s2RzB1SzhzVFg5RElhS1pEVXFJU1BrM1ZaV1JCR0s1N3l1MEk5S3haeFRVIn0sInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5jb20iLCJzdWIiOiJpZCIsImF1ZCI6WyJzZXJ2aWNlLmV4YW1wbGUuY29tIl0sImV4cCI6MTI1ODc5NCwibmJmIjoxMjU3ODk0LCJpYXQiOjEyNTc4OTQsImp0aSI6InZiODZ2ODdnODdnODdnODdiYjg5N3ZjdzIzNjdmdjcyM3ZjODIzNiIsImFjY2VzcyI6W3siVHlwZSI6InJlcG9zaXRvcnkiLCJDbGFzcyI6IiIsIk5hbWUiOiJwYXRoL3RvL3JlcG8iLCJBY3Rpb25zIjpbInB1bGwiLCJwdXNoIl19XX0.sgoVSS0tFns-PbJdYhQ48QzsCE70L_5L_Vv8rwkvWXOjUuRdsxcAU1uaHB676avcU5ThGWSxAJVhbBXCXFQfV0Jk8DKI6Laj6OpcHxXL6o4p1pfjMh7mss22p44zvgAM36mri1C_ANPw9mJHC3A-bwZ38GihUj4ySBlAaPhI0HeYPpuvsle4f5SY07Fb1be1vxMbXeph39zKXapTYw6H1H_y0QEuIPTU0CCNauGU4xKiemRtKDOrROS4a6qourkdNE-YSSdjvaYIlOfK6x6ZiGBRYDdmicpghVqrxGJs_zJof5LJWsE99Fx-nHBQM6I6EjjphpqqdHpFkrSEQORYPSojH6S_JNVKfx5_ixTotFERXtLuyMK3B-MGLTLmVNzhw66qP6zczGdcg4KIQnze1qccQo5dPDbCrLtJpm_JlhbXSXPJGBJPbEWt-bGo62mIez9YRGB4uDeaRMLDyi8tOo5FUJhPHICLOaNysWj1otpZ9jNLvJwiMoy-0sq2dtlOSDwkZcgkIZxBV78b0J8jlAzi-pQJgHmG1M-upCxT8BQU58iPK9XjdedOcrPhwDl-4rLmGMhoyB7vOUNG1ovnyceZ8qBy2nX25-GFPB9YNMKbtDXD3UOhp8rflVB4vGPCQQOwFpewF7JPaNuhujHnE1qHiAihrGUil0L6p4cDa1o",
		ExpiresIn: expiration,
		IssuedAt:  now,
	}

	assert.Equal(t, expected, token)
}
