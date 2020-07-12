# jsonwebkey

**JSON Web Key (JWK) (de)serialization, generation, and conversion.**

This library aims to be [spec](https://tools.ietf.org/html/rfc7517#section-4.3) compliant and secure.

Features:
- [x] Serialization and deserialization of _Required_ and _Recommended_ key types (HS256, RS256, ES256)
- [ ] Conversion to PEM for interop with existing JWT libraries (e.g., [jsonwebtoken](https://crates.io/crates/jsonwebtoken))
- [ ] Key generation (particularly for testing)
