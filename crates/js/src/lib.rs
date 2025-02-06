use ruint::aliases::U256;
use semaphore_rs_proof::{compression::CompressedProof, Proof};
use wasm_bindgen::prelude::*;

/// Compresses a Groth16 proof
#[wasm_bindgen(
    js_name = "compressProof",
    unchecked_return_type = "[string, string, string, string]",
    return_description = "An array of 4 0x prefixed, hex encoded strings represeting a compressed proof"
)]
pub fn compress_proof(
    #[wasm_bindgen(
        unchecked_param_type = "[string, string, string, string, string, string, string, string]",
        param_description = "An array of 8 hex encoded strings (with optional 0x prefixes) that represent an uncompressed proof"
    )]
    proof: Vec<String>,
) -> Result<Vec<String>, JsError> {
    let proof = from_vec(proof)?;
    let proof = Proof::from_flat(proof);

    let proof = semaphore_rs_proof::compression::compress_proof(proof)
        .ok_or_else(|| JsError::new("Failed to compress proof"))?;
    let proof = proof.flatten();

    Ok(to_vec(proof))
}

/// Decompresses a Groth16 proof
#[wasm_bindgen(
    js_name = "decompressProof",
    unchecked_return_type = "[string, string, string, string, string, string, string, string]",
    return_description = "An array of 8 0x prefixed, hex encoded strings representing an uncompressed proof"
)]
pub fn decompress_proof(
    #[wasm_bindgen(
        js_name = "compressedProof",
        unchecked_param_type = "[string, string, string, string]",
        param_description = "An array of 4 hex encoded strings (with optional 0x prefixes) that represent a compressed proof"
    )]
    compressed_proof: Vec<String>,
) -> Result<Vec<String>, JsError> {
    let proof = from_vec(compressed_proof)?;
    let proof = CompressedProof::from_flat(proof);

    let proof = semaphore_rs_proof::compression::decompress_proof(proof)
        .ok_or_else(|| JsError::new("Failed to decompress proof"))?;
    let proof = proof.flatten();

    Ok(to_vec(proof))
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

fn to_vec<const N: usize>(arr: [U256; N]) -> Vec<String> {
    arr.iter().map(|v| format!("{v:#066x}")).collect()
}
