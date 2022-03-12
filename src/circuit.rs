use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::Lazy;
use std::io::{Cursor, Write};
use tempfile::NamedTempFile;

const ZKEY_BYTES: &[u8] = include_bytes!("../semaphore/build/snark/semaphore_final.zkey");
const WASM: &[u8] = include_bytes!("../semaphore/build/snark/semaphore.wasm");

pub static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    let mut reader = Cursor::new(ZKEY_BYTES);
    read_zkey(&mut reader).expect("zkey should be valid")
});

pub static WITNESS_CALCULATOR: Lazy<WitnessCalculator> = Lazy::new(|| {
    // HACK: ark-circom requires a file, so we make one!
    let mut tmpfile = NamedTempFile::new().expect("Failed to create temp file");
    let written = tmpfile.write(WASM).expect("Failed to write to temp file");
    assert_eq!(written, WASM.len());
    let path = tmpfile.into_temp_path();
    let result = WitnessCalculator::new(&path).expect("Failed to create witness calculator");
    path.close().expect("Could not remove tempfile");
    result
});
