package jwtpqc

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// https://github.com/go-jose/go-jose/blob/main/jwk.go#L42C1-L68C2
type JSONWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Pub []byte `json:"pub,omitempty"`
}

// from https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
