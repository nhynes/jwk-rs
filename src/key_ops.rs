use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, SerializeSeq, Serializer},
};

macro_rules! impl_key_ops {
    ($(($key_op:ident, $i:literal)),+,) => {
        paste::item! {
            bitflags::bitflags! {
                #[derive(Default)]
                pub struct KeyOps: u16 {
                    $(const [<$key_op:upper>] = $i;)*
                }
            }
        }

        impl Serialize for KeyOps {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut seq = s.serialize_seq(Some(self.bits().count_ones() as usize))?;
                $(
                    if self.contains(paste::expr! { KeyOps::[<$key_op:upper>] }) {
                        seq.serialize_element(stringify!($key_op))?;
                    }
                )+
                seq.end()
            }
        }

        impl<'de> Deserialize<'de> for KeyOps {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<KeyOps, D::Error> {
                let op_strs: Vec<String> = Deserialize::deserialize(d)?;
                let mut ops = KeyOps::default();
                for op_str in op_strs {
                    $(
                        if op_str == stringify!($key_op) {
                            ops |= paste::expr! { KeyOps::[<$key_op:upper>] };
                            continue;
                        }
                    )+
                        return Err(de::Error::custom(&format!("invalid key op: `{}`", op_str)));
                }
                Ok(ops)
            }
        }
    };
}

#[rustfmt::skip]
impl_key_ops!(
    (sign,       0b00000001),
    (verify,     0b00000010),
    (encrypt,    0b00000100),
    (decrypt,    0b00001000),
    (wrapKey,    0b00010000),
    (unwrapKey,  0b00100000),
    (deriveKey,  0b01000000),
    (deriveBits, 0b10000000),
);
