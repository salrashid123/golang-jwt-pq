package jwtpqc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/circl/pki"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestDSA44(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("example/certs/ml-dsa-44-private.pem")
	require.NoError(t, err)

	pr, err := pki.UnmarshalPEMPrivateKey(privatePEM)
	require.NoError(t, err)

	publicPEM, err := os.ReadFile("example/certs/ml-dsa-44-public.pem")
	require.NoError(t, err)

	pu, err := pki.UnmarshalPEMPublicKey(publicPEM)
	require.NoError(t, err)

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(SigningMethodMLDSA44, claims)

	keyctx, err := NewSignerContext(ctx, &SignerConfig{
		PrivateKey: pr,
	})
	require.NoError(t, err)

	token.Header["kid"] = "1212"
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := SignerVerfiyKeyfunc(context.Background(), &SignerConfig{
		PublicKey: pu,
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestDSA65(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("example/certs/ml-dsa-65-private.pem")
	require.NoError(t, err)

	pr, err := pki.UnmarshalPEMPrivateKey(privatePEM)
	require.NoError(t, err)

	publicPEM, err := os.ReadFile("example/certs/ml-dsa-65-public.pem")
	require.NoError(t, err)

	pu, err := pki.UnmarshalPEMPublicKey(publicPEM)
	require.NoError(t, err)

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(SigningMethodMLDSA65, claims)

	keyctx, err := NewSignerContext(ctx, &SignerConfig{
		PrivateKey: pr,
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := SignerVerfiyKeyfunc(context.Background(), &SignerConfig{
		PublicKey: pu,
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
