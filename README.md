
# golang-jwt for post quantum cryptography

Another extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) that allows creating and verifying JWT tokens where the signature schemes uses a set of [post quantum cryptography signature algorithms](https://blog.cloudflare.com/another-look-at-pq-signatures/).

Specifically, this implement `ML-DSA` family and a TODO would be `SLH-DSA` when thats available.

A sample JWT generated is in the form:

```json
{
  "alg": "ML-DSA-44",
  "kid": "EMHG0l4cWeRqdIdxtHAYbzoxjLZsyaweF9NMIIDI6hU=",
  "typ": "JWT"
}
{
  "iss": "test",
  "exp": 1739907597
}
```

Note, this library uses cloudflare's implementation.  A TODO is to use upstream go after [issues/64537](https://github.com/golang/go/issues/64537) implements `ML-DSA` and other algorithms (eg `SLH-DSA`)

**critically**, the standards aren't complete yet so this is just a toy and will possibly change.  See draft [Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/)

>> This code is NOT supported by google and is just experimental

For other references, see:

* [Cloudflare: A look at the latest post-quantum signature standardization candidates](https://blog.cloudflare.com/another-look-at-pq-signatures/)
* [A Long Goodbye to RSA and ECDSA, and Quick Hello to SLH-DSA](https://medium.com/asecuritysite-when-bob-met-alice/a-long-goodbye-to-rsa-and-ecdsa-and-quick-hello-to-slh-dsa-3e53e36a941b)
* [CRYSTALS Cryptographic Suite for Algebraic Lattices](https://pq-crystals.org/dilithium/)
* [Open Quantum Safe](https://openquantumsafe.org/)
* [crypto: post-quantum support roadmap](https://github.com/golang/go/issues/64537)

* [Quantum doomsday planning (2/2): The post-quantum technology landscape](https://www.taurushq.com/blog/quantum-doomsday-planning-2-2-the-post-quantum-technology-landscape/)

* [X25519MLKEM768 client server in go](https://github.com/salrashid123/ml-kem-tls-keyexchange)
* [golang-jwt for Trusted Platform Module TPM](https://github.com/salrashid123/golang-jwt-tpm)

### Supported Algorithms

* `ML-DSA-44`
* `ML-DSA-65`

TODO: `SLH-DSA`

Also, the `alg` field is simply one derived from the draft: [ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) and may change later (since its still draft)

### Usage

Using this is really easy...you just need something that surfaces that interface.

I've written some simple ones here...the `examples/` folder

```golang
package main

import (
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	"github.com/cloudflare/circl/pki"
)

var ()

func main() {

	ctx := context.Background()

	// load and initialize the public and private keys
	privKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-private.pem")
	pr, err := pki.UnmarshalPEMPrivateKey(privKeyPEMBytes)

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	pu, err := pki.UnmarshalPEMPublicKey(pubKeyPEMBytes)

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA44, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		PrivateKey: pr,
		// PublicKey:  pu,
	})

	tokenString, err := token.SignedString(keyctx)

	fmt.Printf("TOKEN: %s\n", tokenString)

	// // verify with embedded publickey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(ctx, &jwtsigner.SignerConfig{
		PublicKey: pu,
	})

	vtoken, err := jwt.Parse(tokenString, keyFunc)

	if vtoken.Valid {
		fmt.Println("verified")
	}
}
```

The output is a signed JWT

```bash
$ cd examples/

$ go run ml-dsa-44/main.go 
2025/02/18 14:38:57 TOKEN: eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJFTUhHMGw0Y1dlUnFkSWR4dEhBWWJ6b3hqTFpzeWF3ZUY5Tk1JSURJNmhVPSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzM5OTA3NTk3fQ.flKEYHjzRNDQjQZEuA4eeW_jAM2atqrXcCcxh-cKk-UBdIDA4sppgIvaJWVl46JLT-2rkrthCQ4uzVrp3hp9iuV93l9q8fhjwFTRfNUNDsm4H3Qi6jNd-y2vvbXnpRH5sQA0g9Q09d58-o7eZFTe5vGzPfnaLnnm3-gcIsqe8gxTMhu0qJAh7OVCIxpOF6Qtn7iBHJh1X1jUQ9kDtjWYxS2QvvxZ0deo_o33nfyi5YMd6GI4xwylpvusmBbEqbt8qIyE8bx3T8NR1zrrrWeir-8C_gvS4nLacPU8ihkgMM8rRlhkfXiknf8pMtj-NIFPTEmHjDkCGukHEQQ0vg6kks3qt254V2IJgFobceUgi4AaKijEV_v-heSg56ZyLidCVDwP1M-3vUM2X3HhlOT05bDHx1Grvx4ghchLNnnRrJtvN7ESS6DvnKCG-pO7UKTB_fiaRFGTZ5zTT7LhXwZcCLzIm1U_5Od7OFLSowSM1mR7vdY7Ft4V9_OIItO3Ka1LK7V_8n2EFAFu__vDc5Y5PSjA1xY2SudLVLRYRWefa8fYSxYqqLzG0--lDD0WjFfdk3PXh5D_whbPPXSUDBuZOf6OFI6_w1HwnumTXKEEv-tXF5RaxDMhRHmmmqUO3O7ulHkEmBWNDW4a6k4CpxGoTrlO-XubRbghQ6hG3E_PA8cuUUuLXZ6TaO63TB4V1lTuQKOHZH4YWx7wsVwlnVOM69oeFrB1OaVvHwwAU5zHUXsviUZk7yTnD9GKktDMfpSNQ_TTEpuJ-cGfrccCajCw42tzRrPAMVOpRYImzWQ1G3ztrTJjqDGSETENxEwtCfdfZ_cA20N00I5b3Ylz03tkaPOXhYds-JQQFoIxcOo_0mkCLvIb4tmlaU1RCQYFLT2ZWhmMMQdOXul5W3tsskAaEN9Y3TZccsknLGvB1DpxYu-b2kyptYvxYu0wKLGBZ4TDntuEHUc9n2N9LG5syE9sTQ5j_B-4Clu1EQBMr2cS0i0xHW5_qUoC-n8XZgcE-i7XHNh4XX-D0W8q5aXGyQQY_oBbd4u4QD0YbcAXN033AYfdHCE_vusMMk-gamLi7wC9s3cu2YA8VCZBrH_YrCTVo8GATxQq7aJVHLlBoL4FuT24BeUQFg5oGK7dxUcu9_1bebBydeaclgs6v048uQkkur2FKQLCX6f76S92KcPesXXOFPYYpvOR7WONZcJr2tJXMH5TH70DYRNhJp6XCXSc76vZMeaS4kQR-Bh6Vha_OZgP1iqGCE41zwNSVtTaE8H8ai52uizBaL6vQqxtPrh2lRtM7swUnFC6FbTDLmp_JxRLe_fkV7P-3SVDdF2nK_mduN9f9HkpjTvbdMGs8wM5SLf2kN7x4eQmtS5gEozjRawPDoCPtoe02wsDnf2RkFMS1ai0JInKD4Q8SBjQmeACAJGBUrWE3B1VciQ-9kWtQB6_MWC0Wk_0lEXSycW9o9zFtzdZ3EGDk66hdXakm0MC_KE-u5UOI6KYGt2-2y5jdZlylnn4amVQc3uzKdblOcm8wqJUcRHPY1ahTrMbAOwLLm1b97SDBvuYy05wmUGoyTEKEkteUCbyc3b_9ZW5772Q13PiwU1_IScS9Vb3klHEtSd-4alKShocSLm-A7Kmk8kYeaFZX-pZZGcxmAtMfhE68ppND_0LrlgIYCc0oCsRZavOiltWXpP4JLlkIZLbx0PYXk0Oa4Q7DhrWjDrKkxUREUpsqkpGTD1Tdh_lcaGoAsg3h6-RFMFqpbFGW69zBs9T9s--aUQN8koMKvz5Fm_Pp-mPJn8EU2yqFlhZGkzqV363YVSX3Cnl1DFaQqxAVgRRg6xLzbRvRXUCxVMcUrCS0EDMeCmlQ3eKQFmUEMYh3mMR6brGZH0nlfNHLJ2t-LP7PfQzDBH7Z5bXU5FczhSx3zJSEdj5kQGbzZJeSDA5mS5RaXJFEm_WEIVS0I_-vr2kJVXi1yfxJ1kRzLMCoPqUc7W3thT3zGsfbV7GYGTTpIRxNsPYTKCnRhHD-sPNZjUjfMkUbDmyApSH86d1Y3RMaqmtHTLfqE-NKmJklTJ40boYzoTvQogJA31EfJSweMwcjJHaqGJ8jaou6jMadTCJBNj663hkSST0B7_skl0uexlKcDymwy2599xtfPkKiKDeMkCyAitD2Ru0daDdXbn39Ecso4eQJnEt4stStO-z2IVBTqMNDnGMPkVtb4y216XKUIbIsH6eDNeWONCMxcd977Yc9Dtx9IOlNZkG66YSNaXFUfsSAT_jpbLBplg5dtKUoUF2Xke89pIoZO_42La5nKhR2HVfVPySu4lciX7u6Wc4_AtQJjM0nCKjAVtypioVLn6gktNfHSqh6WEg3n45ukjBl9NFwPXDfv2JdVoVCViiC-yd5KDGR4VeeMPcQIgsvBW00SUDNNS-qx0cp3KymA5_MYF-obGnWxkRmJ2Exs6jG8SBPhLIl6Ln66SzBHTLASSLPJFXwiVaQyinAmdkQMc0RnU2Fg5g0y2aMlwgE_46087k3OWeX8g5OnIyNOBp0LuiKJlKDVVEbsKcuVzvstY8cwxo8b_0DUvlJpMevEZJlpBNse1yeIC39HDpOKXDnwB5G2sOUs6bnGUB-IzKcE9WZHBb7g2QDdZ7XzhhalGt2OU7wwgngj-ul0qeHfZVmtDzdB_xboDerS7WTjPsTRAZvQpMhhQzIx5JKN47pN9lodlkDr8YIX6QIZY-IRgnft_bn6nUJTljOeXeItYkzH_AeT2Uu1dajKPSd28cfxicVrNLWcHwJKz_eHk0mEEjExuHzTVj4TwPqzeWpz3Art59P2L9lmFxkoOsORvLeKZQ0Iba2MMP1w0C_LITHUkYb2QXsPv0yNGAgZ4LBxQ-f4ezd1jAZvYmFOK7NhqUCHwbm-VEJ0ANJjUGp4vVHarWGK8npFczpD1-Lk57Ia5-tTotDEqsWPb190YP9OZSMhW1mg82ZS3Zo7ANvAO3QUMy0GMOTPP1qYU2e1i2iMUnW87gL5_U1G6hBX37w2Smeve9P9cRPPd14YkLpd9Rk0O65v82FQwxQ9bjPiZwe5y-0AwM1rnLYXaPL1EXKwN5193xR8QI_gqaQdCXH0YZBAMMJi9FV2l1h4uWuLm60uswMj5NVoWQm6u4vcrb3uTm8QgLEy00R1FdcoaMoavxARATVGyWl5mbpuLv9_kAAAAAAAAAAAAAAAAAAAAAAAAAAA8gLjw
2025/02/18 14:38:57 verified with Signer PublicKey
2025/02/18 14:38:57 verified with PubicKey
2025/02/18 14:38:57 verified with JWK KeyFunc URL
```


#### JWK Parsing

Also, note that  `GetThumbPrintFromContext()` function generates a keyID consistent with [JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html).  The `pub` field is base64urlencoded:


```json
{
  "keys": [
    {
      "kty": "ML-DSA",
      "kid": "EMHG0l4cWeRqdIdxtHAYbzoxjLZsyaweF9NMIIDI6hU=",
      "alg": "ML-DSA-44",
      "pub": "wNA5o465+iisEdUKdpIsuGwW+ojAAOSw6FMNiuxU9nPb3fd1Lg/3awgi+5akk+lypJ6ixNmO4rRIA9KXb7iP+hcefFzJwG9bOxiFg5JB31hgzq7MFO18o3RM9+9FLONwes2bj0iwUwG2au6QoXpzXbwUqjqUxGIUoTP+wKpoxF/f1jEasG18yeaq+ikaSMxiPLmdTcluR8h99CpHY+K02I9c9Um7IAGb35r6/v4ChCbDDXXGUY1q33frq6zS4+pyhCESp0rnVdimbthRvn0DOh7KFrL30DKxz8j1FSHJndqwC/t22TmPNcsarayBNL3PLXv72i+4pRwIZuzBDykTo2OGECVsvFCvuEfHfltyPYWYFCTtdKGqWHHFRY/hsxo3ia/kkQvYdaxZ+k6uUrH5mZASSUfOeys6s3rSOY+/pqkLFYQOjxXM1vT83kKx53D0i4RCbolzCgPvW0dw94aOJyj5L6qsSmV3G32ZEqMXDip0yOJI128YgaJzLSbniNkgHVOPbn018lQxw+41kJkkLnDOCKOkzAsSXirvK2QmkA9qgVpIYVSO/NBAY9uUtZgdoJBjc634r0k59idyTimVQK/JrYBU6d22xi854taD4j+bMbXxsPttzVARGFGrbsjQNQ2ITHNivWQdeUB2evGoxv6ARAaDvjSz9M9oVGW/OZOnx9g/yd2Aq2UO13nlHHrW+hunqunhDnnL84cL3rPjBIctRBpcmc1WX2DVS4kI1MLfUzwphfgMOwUNa8DNwNEWEofL2HQbahcJkLViDtzGvhzqTtUk9dV6Da1XCtocxwWweXz/yQxc1wqfjRlwvaxzjsG9GnuWxq9YBANAFjacN1DpxXk0g4Bf3B19RkHyOJxbdbch+OdVqndtkrkoUcGbAsFC+aOGokingAlrSpbSEUblZf5rmIUu533+tA6yK/gQEkP+NGCCDWTmvSy68TLp5CH3bRaPBfZiolyrmhxEwqQRWMW5gLq7ahft6O8SFjhH0kh8+YkGXEDd7u3DrHdJNRfvePcfsjaN4/15We7qTDbDCJwAjqDlqPz7tpRWgmwfQWlSYTfsbZ+mEcqC7JaEZlfkWdisJqAJpwNaMiiB8V5NT1UCFHPuF950DuM5SZYD4mtgMUMXuNlo+0felges4eF/byKD9/5EHu2vIlmdkrVGTsK2bOd1ZU19xCw4roIRregBpKxDnMBtswAHJAxr7OECrCT2vO+fJ1wGQh20QffLtMDUQX9XZ9HcJy6CliqQyXAUNi2K4m+FL6oHSMiKxV4YOzYO/A5okozO+N4YYnc64ymdlQwHSwRGdjerLf1oSlwZaXzGI2Hq5RZnkMHVDaBDStEnFTb7h31qXFVVrMZs6X+Wsr6JwDGcfvLRougcXGhoY0oq7F3CjwPEZjehCMP4qNErXGVCXmEyNdM4zNHMR+D21cHzz6efSZuvMOI61ZbDKAt3gZqUWESUPDrs5fC3WIGYtJGcyFnzErLOCNTBNo63YbNwfRbAKVl0KGqB8P+9IL2aFpS2UcJ7pIroXajth+nlJUVNkxLh4TFxJG4k/mOj7OlbZDRHgWCUEmQ/fm405JgnjTEDrrDWx28EUnCk7eiwBirlfKNkVsBS7tru/ed2llRzFs6k0CqhmK48H/L6+7Pcnx01op5f0k6FAWOK2z4MYeCMs1iy1/QufdF/bx8c+tyo2STGMJaPBXi7ZFu37l7gR8m/JRFQ5xq0FDhcma9HjvTNisQvJT7x7A=="
    },
    {
      "kty": "ML-DSA",
      "kid": "JSs1QLnP64IvTd00Tsy4FSJq4loJ5dDHJWeIcA5nky0=",
      "alg": "ML-DSA-65",
      "pub": "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"
    }
  ]
}
```

If you want to read the JWK from a url or file directly, you can recall it using a custom `keyFunc`

```golang
	vr, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kidInter, ok := token.Header["kid"]

		kid, ok := kidInter.(string)

		jwkBytes, err := os.ReadFile("certs/jwk.json")

		var keyset jwtsigner.JSONWebKeySet

		for _, k := range keyset.Keys {
			if k.Kid == kid {
				switch k.Alg {
				case "ML-DSA-44":
					pu, err := mldsa44.Scheme().UnmarshalBinaryPublicKey(k.Pub)
					return pu, nil
				case "ML-DSA-65":
					pu, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(k.Pub)
					return pu, nil
				default:
					return nil, fmt.Errorf("error unsupported key alg: %s", k.Alg)
				}
			}
		}
		return nil, fmt.Errorf("keyset not found for key %s", kid)
	})
```

#### Openssl Compatibility

Note, as of writing, the `ML-DSA` keys generated by openssl is inconsistent with this library

* [cloudflare/circl/issues/535](https://github.com/cloudflare/circl/issues/535)