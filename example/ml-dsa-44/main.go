package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

var ()

func main() {

	ctx := context.Background()

	// load existing public/private keys

	privKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-private.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	pr, err := pki.UnmarshalPEMPrivateKey(privKeyPEMBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	pu, err := pki.UnmarshalPEMPublicKey(pubKeyPEMBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// issue the jwt
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA44, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		PrivateKey: pr,
		//PublicKey:  pu,
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}

	// get the thumbprint
	kid, err := jwtsigner.GetThumbPrintFromContext(keyctx)
	if err != nil {
		log.Fatalf("Unable to get keyid: %v", err)
	}

	token.Header["kid"] = kid

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	log.Printf("TOKEN: %s\n", tokenString)

	// // verify with embedded publickey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(ctx, &jwtsigner.SignerConfig{
		PublicKey: pu,
	})
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("verified with Signer PublicKey")
	}

	//

	v, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return pu, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("verified with PubicKey")
	}

	// use a JWK json as keyfunc

	vr, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kidInter, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("could not find kid in JWT header")
		}
		kid, ok := kidInter.(string)
		if !ok {
			return nil, fmt.Errorf("could not convert kid in JWT header to string")
		}

		// read from a file; you can read from a JWK url too
		jwkBytes, err := os.ReadFile("certs/jwk.json")
		if err != nil {
			return nil, fmt.Errorf("%w: error reading jwk", err)
		}

		// find the key by keyid
		var keyset jwtsigner.JSONWebKeySet
		if err := json.Unmarshal(jwkBytes, &keyset); err != nil {
			return nil, fmt.Errorf("%w: error Unmarshal keyset", err)
		}

		// unmarshal the binary forward
		for _, k := range keyset.Keys {
			if k.Kid == kid {
				switch k.Alg {
				case mldsa44.Scheme().Name():
					pu, err := mldsa44.Scheme().UnmarshalBinaryPublicKey(k.Pub)
					if err != nil {
						return nil, fmt.Errorf("%w: error UnmarshalBinaryPublicKey ", err)
					}
					return pu, nil
				case mldsa65.Scheme().Name():
					pu, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(k.Pub)
					if err != nil {
						return nil, fmt.Errorf("%w: error UnmarshalBinaryPublicKey ", err)
					}
					return pu, nil
				default:
					return nil, fmt.Errorf("error unsupported key alg: %s", k.Alg)
				}
			}
		}
		return nil, fmt.Errorf("keyset not found for key %s", kid)
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if vr.Valid {
		log.Println("verified with JWK KeyFunc URL")
	}

}
