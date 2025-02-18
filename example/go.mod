module main

go 1.22.0

toolchain go1.23.4

require (
	github.com/cloudflare/circl v1.6.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/salrashid123/golang-jwt-pqc v0.0.0
)

require (
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
)

replace github.com/salrashid123/golang-jwt-pqc => ../
