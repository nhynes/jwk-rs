use super::*;

use std::str::FromStr;

#[test]
fn deserialize_es256() {
    // Generated using https://mkjwk.org
    let jwk_str = r#"{
        "kty": "EC",
        "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
        "use": "enc",
        "crv": "P-256",
        "kid": "a key",
        "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
        "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k",
        "alg": "ES256"
    }"#;
    let jwk = JsonWebKey::from_str(jwk_str).unwrap();
    assert_eq!(
        jwk,
        JsonWebKey {
            key: box Key::EC {
                // The parameters were decoded using a 10-liner Rust script.
                params: Curve::P256 {
                    d: Some(
                        [
                            102, 130, 144, 246, 62, 29, 132, 128, 101, 49, 21, 107, 191, 228, 6,
                            240, 255, 211, 246, 203, 173, 191, 127, 253, 229, 232, 168, 244, 203,
                            105, 128, 168
                        ]
                        .into()
                    ),
                    x: [
                        64, 227, 7, 154, 255, 122, 181, 89, 73, 191, 235, 141, 170, 154, 231, 13,
                        34, 136, 143, 144, 34, 45, 53, 202, 70, 137, 151, 98, 118, 175, 208, 221
                    ]
                    .into(),
                    y: [
                        78, 54, 25, 160, 121, 220, 181, 171, 68, 19, 163, 66, 172, 169, 151, 65,
                        210, 73, 62, 115, 115, 100, 69, 252, 156, 25, 153, 117, 237, 192, 99, 137
                    ]
                    .into(),
                },
            },
            algorithm: Some(JsonWebAlgorithm::ES256),
            key_id: Some("a key".into()),
            key_ops: KeyOps::empty(),
            key_use: Some(KeyUse::Encryption),
        }
    );
}

#[test]
fn serialize_es256() {
    let jwk = JsonWebKey {
        key: box Key::EC {
            params: Curve::P256 {
                d: None,
                x: [1u8; 32].into(),
                y: [2u8; 32].into(),
            },
        },
        key_id: None,
        algorithm: None,
        key_ops: KeyOps::empty(),
        key_use: None,
    };
    assert_eq!(
        jwk.to_string(),
        r#"{"kty":"EC","crv":"P-256","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","y":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}"#
    );
}

#[test]
fn deserialize_hs256() {
    let jwk_str = r#"{
        "kty": "oct",
        "k": "tAON6Q",
        "alg": "HS256",
        "key_ops": ["verify", "sign"]
    }"#;
    let jwk = JsonWebKey::from_str(jwk_str).unwrap();
    assert_eq!(
        jwk,
        JsonWebKey {
            key: box Key::Symmetric {
                // The parameters were decoded using a 10-liner Rust script.
                key: vec![180, 3, 141, 233].into(),
            },
            algorithm: Some(JsonWebAlgorithm::HS256),
            key_id: None,
            key_ops: KeyOps::SIGN | KeyOps::VERIFY,
            key_use: None,
        }
    );
}

#[test]
fn serialize_hs256() {
    let jwk = JsonWebKey {
        key: box Key::Symmetric {
            key: vec![42; 16].into(),
        },
        key_id: None,
        algorithm: None,
        key_ops: KeyOps::empty(),
        key_use: None,
    };
    assert_eq!(
        jwk.to_string(),
        r#"{"kty":"oct","k":"KioqKioqKioqKioqKioqKg=="}"#
    );
}

#[test]
fn deserialize_rs256() {
    let jwk_str = r#"{
        "p": "_LSip5o4eaGf25uvwyUq9ubRtKemrCaoCxumoj63Au0",
        "kty": "RSA",
        "q": "l20iLpicEW3uja0Zg2xP6DjZa86bD4IQ3wFXCcKCf1c",
        "d": "Xo0VAHtfV38HwJbAI6X-Fu7vuyoQjnuiSlQhcSjxn0BZfLP_DKxdJ2ANgTGVE0x243YHqhWRHLobbmDcnUuMOQ",
        "e": "AQAB",
        "qi": "2mzAaSr7I1D3vDtOhbWKS9-9ELRHKbAHz4dhn4DSCBo",
        "dp": "-kyswxeVEpyM6wdU2xRobu-HDMn145PSZFY6AX_e460",
        "alg": "RS256",
        "dq": "OqMWE3khJlatg8s-D_hHUSOCfg65WN4C7ng0XiEmK20",
        "n": "lXpGmBoIxj56TpptApaac6V19_7WWbq0a14a5UHBBlkc54NwIUa2X4p9OeK2sy6rLQ_1g1AcSwfsVUy8MP-Riw"
    }"#;
    let jwk = JsonWebKey::from_str(jwk_str).unwrap();
    assert_eq!(
        jwk,
        JsonWebKey {
            key: box Key::RSA {
                public: RsaPublic {
                    e: PublicExponent,
                    n: vec![
                        149, 122, 70, 152, 26, 8, 198, 62, 122, 78, 154, 109, 2, 150, 154, 115,
                        165, 117, 247, 254, 214, 89, 186, 180, 107, 94, 26, 229, 65, 193, 6, 89,
                        28, 231, 131, 112, 33, 70, 182, 95, 138, 125, 57, 226, 182, 179, 46, 171,
                        45, 15, 245, 131, 80, 28, 75, 7, 236, 85, 76, 188, 48, 255, 145, 139
                    ]
                    .into()
                },
                private: Some(RsaPrivate {
                    d: vec![
                        94, 141, 21, 0, 123, 95, 87, 127, 7, 192, 150, 192, 35, 165, 254, 22, 238,
                        239, 187, 42, 16, 142, 123, 162, 74, 84, 33, 113, 40, 241, 159, 64, 89,
                        124, 179, 255, 12, 172, 93, 39, 96, 13, 129, 49, 149, 19, 76, 118, 227,
                        118, 7, 170, 21, 145, 28, 186, 27, 110, 96, 220, 157, 75, 140, 57
                    ]
                    .into(),
                    p: Some(
                        vec![
                            252, 180, 162, 167, 154, 56, 121, 161, 159, 219, 155, 175, 195, 37, 42,
                            246, 230, 209, 180, 167, 166, 172, 38, 168, 11, 27, 166, 162, 62, 183,
                            2, 237
                        ]
                        .into()
                    ),
                    q: Some(
                        vec![
                            151, 109, 34, 46, 152, 156, 17, 109, 238, 141, 173, 25, 131, 108, 79,
                            232, 56, 217, 107, 206, 155, 15, 130, 16, 223, 1, 87, 9, 194, 130, 127,
                            87
                        ]
                        .into()
                    ),
                    dp: Some(
                        vec![
                            250, 76, 172, 195, 23, 149, 18, 156, 140, 235, 7, 84, 219, 20, 104,
                            110, 239, 135, 12, 201, 245, 227, 147, 210, 100, 86, 58, 1, 127, 222,
                            227, 173
                        ]
                        .into()
                    ),
                    dq: Some(
                        vec![
                            58, 163, 22, 19, 121, 33, 38, 86, 173, 131, 203, 62, 15, 248, 71, 81,
                            35, 130, 126, 14, 185, 88, 222, 2, 238, 120, 52, 94, 33, 38, 43, 109
                        ]
                        .into()
                    ),
                    qi: Some(
                        vec![
                            218, 108, 192, 105, 42, 251, 35, 80, 247, 188, 59, 78, 133, 181, 138,
                            75, 223, 189, 16, 180, 71, 41, 176, 7, 207, 135, 97, 159, 128, 210, 8,
                            26
                        ]
                        .into()
                    )
                })
            },
            algorithm: Some(JsonWebAlgorithm::RS256),
            key_id: None,
            key_ops: KeyOps::empty(),
            key_use: None,
        }
    );
}

#[test]
fn serialize_rs256() {
    let jwk = JsonWebKey {
        key: box Key::RSA {
            public: RsaPublic {
                e: PublicExponent,
                n: vec![105, 183, 62].into(),
            },
            private: Some(RsaPrivate {
                d: vec![105, 183, 63].into(),
                p: None,
                q: None,
                dp: None,
                dq: None,
                qi: None,
            }),
        },
        key_id: None,
        algorithm: None,
        key_ops: KeyOps::empty(),
        key_use: None,
    };
    assert_eq!(
        jwk.to_string(),
        r#"{"kty":"RSA","e":"AQAB","n":"abc-","d":"abc_"}"#
    );
}

#[test]
fn mismatched_algorithm() {
    macro_rules! assert_mismatched_alg {
        ($jwk_str:literal) => {
            match JsonWebKey::from_str($jwk_str) {
                Err(Error::MismatchedAlgorithm) => {}
                v => panic!("expected MismatchedAlgorithm, got {:?}", v),
            }
        };
    }

    assert_mismatched_alg!(r#"{ "kty": "oct", "k": "tAON6Q", "alg": "ES256" }"#);
    assert_mismatched_alg!(r#"{ "kty": "oct", "k": "tAON6Q", "alg": "RS256" }"#);

    assert_mismatched_alg!(
        r#"{
            "kty": "EC",
            "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
            "crv": "P-256",
            "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
            "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k",
            "alg": "RS256"
        }"#
    );
    assert_mismatched_alg!(
        r#"{
            "kty": "EC",
            "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
            "crv": "P-256",
            "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
            "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k",
            "alg": "HS256"
        }"#
    );
}

#[cfg(feature = "conversion")]
#[test]
fn es256_to_pem() {
    let jwk_str = r#"{
        "kty": "EC",
        "d": "ZoKQ9j4dhIBlMRVrv-QG8P_T9sutv3_95eio9MtpgKg",
        "crv": "P-256",
        "x": "QOMHmv96tVlJv-uNqprnDSKIj5AiLTXKRomXYnav0N0",
        "y": "TjYZoHnctatEE6NCrKmXQdJJPnNzZEX8nBmZde3AY4k"
    }"#;
    let jwk = JsonWebKey::from_str(jwk_str).unwrap();
    #[rustfmt::skip]
    assert_eq!(
        base64::encode(jwk.key.to_pem().unwrap()),
"-----BEGIN PRIVATE KEY-----
MHcCAQEEIGaCkPY+HYSAZTEVa7/kBvD/0/bLrb9//eXoqPTLaYCooAoGCCqGSM49
AwEHoUQDQgAEQOMHmv96tVlJv+uNqprnDSKIj5AiLTXKRomXYnav0N1ONhmgedy1
q0QTo0KsqZdB0kk+c3NkRfycGZl17cBjiQ==
-----END PRIVATE KEY-----"
    );
}
