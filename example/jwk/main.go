package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/cloudflare/circl/pki"
	jwtpq "github.com/salrashid123/golang-jwt-pqc"
)

var ()

func main() {

	//ctx := context.Background()

	// privKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-private.pem")
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	// pr, err := pki.UnmarshalPEMPrivateKey(privKeyPEMBytes)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	pu, err := pki.UnmarshalPEMPublicKey(pubKeyPEMBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}

	pubin, err := pu.MarshalBinary()
	if err != nil {
		log.Fatalf("%v", err)
	}

	k := fmt.Sprintf(`{"alg":"%s","kty":"%s","pub":"%s"}`, "ML-DSA-44", "ML-DSA", base64.URLEncoding.EncodeToString(pubin))
	hash := sha256.Sum256([]byte(k))
	kid := base64.StdEncoding.EncodeToString(hash[:])

	ks := &jwtpq.JSONWebKeySet{
		Keys: []jwtpq.JSONWebKey{{
			Kty: "ML-DSA",
			Alg: "ML-DSA-44",
			Kid: kid,
			Pub: pubin,
		},
		},
	}

	jsonData, err := json.Marshal(ks)
	if err != nil {
		log.Fatalf("%v", err)
	}
	jsonString := string(jsonData)
	fmt.Println(jsonString)
}
