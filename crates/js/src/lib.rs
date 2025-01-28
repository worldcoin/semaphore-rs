use ruint::aliases::U256;
use semaphore_rs_proof::{compression::CompressedProof, Proof};
use wasm_bindgen::prelude::*;

/// Compresses a Groth16 proof
/// Input data must be an array of 8 hex encoded strings representing a valid proof
/// 0x prefixes are optional
///
/// Returns an array of 8 hex encoded (0x prefixed) strings representing a compressed proof
#[wasm_bindgen(js_name = "compressProof")]
pub fn compress_proof(proof: js_sys::Array) -> Result<js_sys::Array, JsError> {
    let proof = from_array(proof)?;
    let proof = Proof::from_flat(proof);

    let proof = semaphore_rs_proof::compression::compress_proof(proof)
        .ok_or_else(|| JsError::new("Failed to compress proof"))?;
    let proof = proof.flatten();

    Ok(to_array(proof))
}

/// Decompresses a Groth16 proof
/// Input data must be an array of 4 hex encoded strings representing a valid compressed proof
/// 0x prefixes are optional
///
/// Returns an array of 8 hex encoded (0x prefixed) strings
#[wasm_bindgen(js_name = "decompressProof")]
pub fn decompress_proof(proof: js_sys::Array) -> Result<js_sys::Array, JsError> {
    let proof = from_array(proof)?;
    let proof = CompressedProof::from_flat(proof);

    let proof = semaphore_rs_proof::compression::decompress_proof(proof)
        .ok_or_else(|| JsError::new("Failed to decompress proof"))?;
    let proof = proof.flatten();

    Ok(to_array(proof))
}

fn from_array<const N: usize>(proof: js_sys::Array) -> Result<[U256; N], JsError> {
    if proof.length() as usize != N {
        return Err(JsError::new(&format!("Proof length must be {N}")));
    }

    let mut proof_vals: Vec<U256> = Vec::with_capacity(N);
    for i in 0..N {
        let v = proof.get(i as u32);
        let v = v
            .as_string()
            .ok_or_else(|| JsError::new("Proof items must be hex encoded strings"))?;

        let v: U256 = U256::from_str_radix(v.trim_start_matches("0x"), 16)
            .map_err(|err| JsError::new(&err.to_string()))?;

        proof_vals.push(v);
    }

    let proof: [U256; N] = proof_vals.try_into().unwrap();

    Ok(proof)
}

fn to_array<const N: usize>(arr: [U256; N]) -> js_sys::Array {
    let ret = js_sys::Array::new();
    for v in arr {
        let bytes: [u8; 32] = v.to_be_bytes();
        let s = hex::encode(&bytes);
        let s = format!("0x{s}");
        ret.push(&JsValue::from_str(&s));
    }
    ret
}
