package jwtpqc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	MLDSA = "ML-DSA"
)

type SignerConfig struct {
	PrivateKey sign.PrivateKey
	PublicKey  sign.PublicKey
}

type signerConfigKey struct{}

func (k *SignerConfig) GetPublicKey() crypto.PublicKey {
	return k.PublicKey
}

var (
	SigningMethodMLDSA44 *SigningMethodPQ
	SigningMethodMLDSA65 *SigningMethodPQ
	errMissingConfig     = errors.New("signer: missing configuration in provided context")
)

type SigningMethodPQ struct {
	alg    string
	family string
}

func NewSignerContext(parent context.Context, val *SignerConfig) (context.Context, error) {
	if val.PublicKey == nil && val.PrivateKey != nil {
		val.PublicKey = val.PrivateKey.Public().(sign.PublicKey)
	}
	return context.WithValue(parent, signerConfigKey{}, val), nil
}

func SignerFromContext(ctx context.Context) (*SignerConfig, bool) {
	val, ok := ctx.Value(signerConfigKey{}).(*SignerConfig)
	return val, ok
}

func init() {
	// ML-DSA-44
	SigningMethodMLDSA44 = &SigningMethodPQ{
		"ML-DSA-44",
		MLDSA,
	}
	jwt.RegisterSigningMethod(SigningMethodMLDSA44.Alg(), func() jwt.SigningMethod {
		return SigningMethodMLDSA44
	})

	// ML-DSA-65
	SigningMethodMLDSA65 = &SigningMethodPQ{
		"ML-DSA-65",
		MLDSA,
	}
	jwt.RegisterSigningMethod(SigningMethodMLDSA65.Alg(), func() jwt.SigningMethod {
		return SigningMethodMLDSA65
	})
}

// Attempts to get a standard [JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
func GetThumbPrintFromContext(ctx context.Context) (string, error) {
	sctx, ok := SignerFromContext(ctx)
	if !ok {
		return "", errors.New("error getting thumbprint; invalid context")
	}

	b, err := sctx.PublicKey.MarshalBinary()
	if err != nil {
		return "", err
	}
	bc := base64.URLEncoding.EncodeToString(b)

	var jsonString string
	switch sctx.PublicKey.Scheme().Name() {
	case "ML-DSA-44":
		kty := "ML-DSA"
		jsonString = fmt.Sprintf(`{"alg":"%s","kty":"%s","pub":"%s"}`, sctx.PublicKey.Scheme().Name(), kty, bc)
	case "ML-DSA-65":
		kty := "ML-DSA"
		jsonString = fmt.Sprintf(`{"alg":"%s","kty":"%s","pub":"%s"}`, sctx.PublicKey.Scheme().Name(), kty, bc)
	default:
		return "", fmt.Errorf("unknown key type %s", sctx.PublicKey.Scheme().Name())
	}

	hash := sha256.Sum256([]byte(jsonString))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func (s *SigningMethodPQ) Alg() string {
	return s.alg
}

func (s *SigningMethodPQ) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}
	config, ok := SignerFromContext(ctx)
	if !ok {
		return nil, errMissingConfig
	}

	if config.PrivateKey == nil {
		return nil, errors.New("private key must be specified for Sign")
	}
	signedBytes, err := config.PrivateKey.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return signedBytes, nil
}

func SignerVerfiyKeyfunc(ctx context.Context, config *SignerConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.GetPublicKey(), nil
	}, nil
}

func (s *SigningMethodPQ) Verify(signingString string, signature []byte, key interface{}) error {
	switch key.(type) {
	case *mldsa44.PublicKey:
		ok := mldsa44.Verify(key.(*mldsa44.PublicKey), []byte(signingString), nil, signature)
		if !ok {
			return errors.New("error verifying with mldsa44")
		}
		return nil
	case *mldsa65.PublicKey:
		ok := mldsa65.Verify(key.(*mldsa65.PublicKey), []byte(signingString), nil, signature)
		if !ok {
			return errors.New("error verifying with mldsa65")
		}
		return nil
	default:
		return jwt.ErrInvalidKey
	}
}
