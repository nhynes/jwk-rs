# jsonwebkey

[![crates.io](https://img.shields.io/crates/v/jsonwebkey.svg?color=fc8d62&logo=rust)](https://crates.io/crates/jsonwebkey)
[![docs.rs](https://img.shields.io/badge/docs.rs-jsonwebkey-66c2a5?labelColor=555555&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K)](https://docs.rs/jsonwebkey)
[![codecov](https://codecov.io/gh/nhynes/jwk-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/nhynes/jwk-rs)

*[JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517#section-4.3) (de)serialization, generation, and conversion.*

Note: requires rustc nightly >= 1.45 for conveniences around fixed-size arrays.

**Goals**

tl;dr: get keys into a format that can be used by other crates; be as safe as possible while doing so.

- Serialization and deserialization of _Required_ and _Recommended_ key types (HS256, RS256, ES256)
- Conversion to PEM for interop with existing JWT libraries (e.g., [jsonwebtoken](https://crates.io/crates/jsonwebtoken))
- Key generation (particularly useful for testing)

**Non-goals**

- be a fully-featured JOSE framework

## Examples

### Deserializing from JSON

```rust
extern crate jsonwebkey as jwk;
// Generated using https://mkjwk.org/.
let jwt_str = r#"{
   "kty": "oct",
   "use": "sig",
   "kid": "my signing key",
   "k": "Wpj30SfkzM_m0Sa_B2NqNw",
   "alg": "HS256"
}"#;
let jwk: jwk::JsonWebKey = jwt_str.parse().unwrap();
println!("{:#?}", jwk); // looks like `jwt_str` but with reordered fields.
```

### Using with other crates

```rust
extern crate jsonwebtoken as jwt;
extern crate jsonwebkey as jwk;

#[derive(serde::Serialize, serde::Deserialize)]
struct TokenClaims {}

let mut my_jwk = jwk::JsonWebKey::new(jwk::Key::generate_p256());
my_jwk.set_algorithm(jwk::Algorithm::ES256);

let encoding_key = jwt::EncodingKey::from_ec_der(&my_jwk.key.to_der().unwrap());
let token = jwt::encode(
    &jwt::Header::new(my_jwk.algorithm.unwrap().into()),
    &TokenClaims {},
    &encoding_key,
).unwrap();

let public_pem = my_jwk.key.to_public().unwrap().to_pem().unwrap();
let decoding_key = jwt::DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap();
let mut validation = jwt::Validation::new(my_jwk.algorithm.unwrap().into());
validation.validate_exp = false;
jwt::decode::<TokenClaims>(&token, &decoding_key, &validation).unwrap();
```

## Features

* `convert` - enables `Key::{to_der, to_pem}`.
              This pulls in the [yasna](https://crates.io/crates/yasna) crate.
* `generate` - enables `Key::{generate_p256, generate_symmetric}`.
               This pulls in the [p256](https://crates.io/crates/p256) and [rand](https://crates.io/crates/rand) crates.
* `jsonwebtoken` - enables conversions to types in the [jsonwebtoken](https://crates.io/crates/jsonwebtoken) crate.
