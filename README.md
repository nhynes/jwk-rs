# jsonwebkey

*[JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517#section-4.3) (de)serialization, generation, and conversion.*

Note: requires rustc nightly >= 1.45 for conveniences around fixed-size arrays.

**Goals**

tl;dr: get keys into a format that can be used by other crates; be as safe as possible while doing so.

- [x] Serialization and deserialization of _Required_ and _Recommended_ key types (HS256, RS256, ES256)
- [x] Conversion to PEM for interop with existing JWT libraries (e.g., [jsonwebtoken](https://crates.io/crates/jsonwebtoken))
- [ ] Key generation (particularly for testing)

**Non-goals**

* be a fully-featured JOSE framework

## Example

```rust
extern crate jsonwebtoken as jwt;
extern crate jsonwebkey as jwk;

fn main() {
    let jwk_str = r#"{
        "kty": "EC",
        "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
        "crv": "P-256",
        "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
        "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k"
    }"#;
    let jwk = jwk::JsonWebKey::from_str(jwk_str).unwrap();
    let encoding_key = jwk::EncodingKey::from_ec_der(jwk.to_der().unwrap());
    let token = jwt::encode(&jwt::Header::default(), &() /* claims */, encoding_key).unwrap();
}
```

## Features

* `convert` - enables `Key::{to_der, to_pem}`.
              This pulls in the [yasna](https://crates.io/crates/yasna) crate.
* `jsonwebtoken` - enables conversions to types in the [jsonwebtoken](https://crates.io/crates/jsonwebtoken) crate.
