use js_sys::Array;
use ruint::aliases::U256;
use semaphore_rs_proof::{compression::CompressedProof, Proof};
use wasm_bindgen::prelude::*;

/// Compresses a Groth16 proof
#[wasm_bindgen(js_name = "compressProof")]
pub fn compress_proof(proof: Array) -> Result<Array, JsError> {
    let proof: Vec<String> = proof
        .iter()
        .map(|v| v.as_string().unwrap_or_default())
        .collect();

    let proof = from_vec(proof)?;
    let proof = Proof::from_flat(proof);

    let proof = semaphore_rs_proof::compression::compress_proof(proof)
        .ok_or_else(|| JsError::new("Failed to compress proof"))?
        .flatten();

    Ok(to_js_array(proof))
}

/// Decompresses a Groth16 proof
#[wasm_bindgen(js_name = "decompressProof")]
pub fn decompress_proof(compressed_proof: Array) -> Result<Array, JsError> {
    let compressed_proof: Vec<String> = compressed_proof
        .iter()
        .map(|v| v.as_string().unwrap_or_default())
        .collect();

    let proof = from_vec(compressed_proof)?;
    let proof = CompressedProof::from_flat(proof);

    let proof = semaphore_rs_proof::compression::decompress_proof(proof)
        .ok_or_else(|| JsError::new("Failed to decompress proof"))?;
    let proof = proof.flatten();

    Ok(to_js_array(proof))
}

fn from_vec<const N: usize>(proof: Vec<String>) -> Result<[U256; N], JsError> {
    if proof.len() != N {
        return Err(JsError::new(&format!("Proof length must be {N}")));
    }

    let proof: Vec<U256> = proof
        .into_iter()
        .map(|s| {
            U256::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|err| JsError::new(&err.to_string()))
        })
        .collect::<Result<_, _>>()?;

    let proof: [U256; N] = proof.try_into().unwrap();

    Ok(proof)
}

fn to_js_array<const N: usize>(arr: [U256; N]) -> Array {
    let js_array = Array::new();
    arr.iter().take(N).for_each(|v| {
        js_array.push(&JsValue::from_str(&format!("{:#066x}", v)));
    });
    js_array
}
