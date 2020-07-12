use std::{array::FixedSizeArray, fmt};

use derive_more::{AsRef, Deref, From};
use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::{Zeroize, Zeroizing};

use crate::utils::{deserialize_base64, serialize_base64};

#[derive(Clone, Zeroize, Deref, AsRef, From)]
#[zeroize(drop)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for ByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "{}", base64::encode(self.0.as_slice()))
        } else {
            write!(f, "ByteArray<{}>", N)
        }
    }
}

impl<const N: usize> PartialEq for ByteArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl<const N: usize> Eq for ByteArray<N> {}

impl<const N: usize> ByteArray<N> {
    pub fn try_from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, String> {
        let mut arr = Self([0u8; N]);
        let bytes = bytes.as_ref();
        if bytes.len() != N {
            Err(format!("expected {} bytes but got {}", N, bytes.len()))
        } else {
            arr.0.copy_from_slice(bytes);
            Ok(arr)
        }
    }
}

impl<const N: usize> Serialize for ByteArray<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_base64(self.0.as_slice(), s)
    }
}

impl<'de, const N: usize> Deserialize<'de> for ByteArray<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Zeroizing::new(deserialize_base64(d)?);
        Self::try_from_slice(&*bytes).map_err(|_| {
            de::Error::invalid_length(bytes.len(), &format!("{} base64-encoded bytes", N).as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static BYTES: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
    static BASE64_JSON: &str = "\"AQIDBAUGBw==\"";

    fn get_de() -> serde_json::Deserializer<serde_json::de::StrRead<'static>> {
        serde_json::Deserializer::from_str(&BASE64_JSON)
    }

    #[test]
    fn test_serde_byte_array_good() {
        let arr = ByteArray::<7>::try_from_slice(BYTES).unwrap();
        let b64 = serde_json::to_string(&arr).unwrap();
        assert_eq!(b64, BASE64_JSON);
        let bytes: ByteArray<7> = serde_json::from_str(&b64).unwrap();
        assert_eq!(bytes.as_ref(), BYTES);
    }

    #[test]
    fn test_serde_deserialize_byte_array_invalid() {
        let mut de = serde_json::Deserializer::from_str("\"Z\"");
        ByteArray::<0>::deserialize(&mut de).unwrap_err();
    }

    #[test]
    fn test_serde_base64_deserialize_array_long() {
        ByteArray::<6>::deserialize(&mut get_de()).unwrap_err();
    }

    #[test]
    fn test_serde_base64_deserialize_array_short() {
        ByteArray::<8>::deserialize(&mut get_de()).unwrap_err();
    }
}
