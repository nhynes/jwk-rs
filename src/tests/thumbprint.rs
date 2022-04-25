use super::*;

#[test]
fn rsa_thumbprint() {
    // This one is from https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    let fixture_jwk = r#"
    {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
        "someOtherStuffToBeIgnored": "ignore this, please"
    }
    "#;
    let jwk = JsonWebKey::from_str(fixture_jwk).unwrap();
    assert_eq!(
        jwk.key.thumbprint(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

#[test]
fn ec_thumbprint() {
    let jwk = JsonWebKey::from_str(P256_JWK_FIXTURE).unwrap();
    assert_eq!(
        jwk.key.thumbprint(),
        // Calculated using NPM `jose` package:
        // `await require('jose').calculateJwkThumbprint($P256_JWK_FIXTURE)`
        "uDOpncDU2IMkMNkErJcTEvkGAQTOS8JOkiNf0Vq11Zw"
    );
}

#[test]
fn symmetric_thumbprint() {
    let jwk = JsonWebKey::from_str(OCT_JWK_FIXTURE).unwrap();
    assert_eq!(
        jwk.key.thumbprint(),
        // Calculated using NPM `jose` package:
        // `await require('jose').calculateJwkThumbprint($OCT_JWK_FIXTURE)`
        "sxDMVVoC3IvFLAi0Dlyjgo3-pxSqMyQXYHA7cw0LWiI"
    );
}
