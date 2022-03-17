use tiny_keccak::{Hasher as _, Keccak};

pub(crate) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

/// Helper function to optionally remove `0x` prefix from hex strings.
pub(crate) fn trim_hex_prefix(str: &str) -> &str {
    if str.len() >= 2 && (&str[..2] == "0x" || &str[..2] == "0X") {
        &str[2..]
    } else {
        str
    }
}
