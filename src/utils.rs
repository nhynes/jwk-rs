use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::Zeroizing;

fn base64_config() -> base64::Config {
    base64::Config::new(base64::CharacterSet::UrlSafe, false /* pad */)
}

pub(crate) fn base64_encode(bytes: impl AsRef<[u8]>) -> String {
    base64::encode_config(bytes, base64_config())
}

fn base64_decode(b64: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(b64, base64_config())
}

pub(crate) mod serde_base64 {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        bytes: impl AsRef<[u8]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        base64_encode(bytes).serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64_str = Zeroizing::new(String::deserialize(d)?);
        base64_decode(&*base64_str).map_err(|e| {
            #[cfg(debug_assertions)]
            let err_msg = e.to_string().to_lowercase();
            #[cfg(not(debug_assertions))]
            let err_msg = "invalid base64";
            de::Error::custom(err_msg.strip_suffix('.').unwrap_or(&err_msg))
        })
    }
}

#[cfg(feature = "pkcs-convert")]
pub(crate) mod pkcs8 {
    use yasna::{
        models::{ObjectIdentifier, TaggedDerValue},
        DERWriter, DERWriterSeq,
    };

    fn write_oids(writer: &mut DERWriterSeq<'_>, oids: &[Option<&ObjectIdentifier>]) {
        for oid in oids {
            match oid {
                Some(oid) => writer.next().write_oid(oid),
                None => writer.next().write_null(),
            }
        }
    }

    pub(crate) fn write_private(
        oids: &[Option<&ObjectIdentifier>],
        body_writer: impl FnOnce(&mut DERWriterSeq<'_>),
    ) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_i8(0); // version
                writer
                    .next()
                    .write_sequence(|writer| write_oids(writer, oids));

                let body = yasna::construct_der(|writer| writer.write_sequence(body_writer));
                writer
                    .next()
                    .write_tagged_der(&TaggedDerValue::from_octetstring(body));
            })
        })
    }

    pub(crate) fn write_public(
        oids: &[Option<&ObjectIdentifier>],
        body_writer: impl FnOnce(DERWriter<'_>),
    ) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer
                    .next()
                    .write_sequence(|writer| write_oids(writer, oids));
                body_writer(writer.next());
            })
        })
    }
}
