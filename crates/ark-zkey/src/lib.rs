use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use color_eyre::eyre::{Result, WrapErr};
use semaphore_rs_ark_circom::read_zkey;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableProvingKey(pub ProvingKey<Bn254>);

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableMatrix<F: Field> {
    pub data: Vec<Vec<(F, usize)>>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableConstraintMatrices<F: Field> {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a_num_non_zero: usize,
    pub b_num_non_zero: usize,
    pub c_num_non_zero: usize,
    pub a: SerializableMatrix<F>,
    pub b: SerializableMatrix<F>,
    pub c: SerializableMatrix<F>,
}

// TODO: Return ProvingKey<Bn254>, ConstraintMatrices<Fr>?
pub fn read_arkzkey_from_bytes(
    arkzkey_bytes: &[u8],
) -> Result<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    let mut cursor = std::io::Cursor::new(arkzkey_bytes);

    let serialized_proving_key =
        SerializableProvingKey::deserialize_compressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize proving key")?;

    let serialized_constraint_matrices =
        SerializableConstraintMatrices::deserialize_compressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize constraint matrices")?;

    // Get on right form for API
    let proving_key: ProvingKey<Bn254> = serialized_proving_key.0;
    let constraint_matrices: ConstraintMatrices<Fr> = ConstraintMatrices {
        num_instance_variables: serialized_constraint_matrices.num_instance_variables,
        num_witness_variables: serialized_constraint_matrices.num_witness_variables,
        num_constraints: serialized_constraint_matrices.num_constraints,
        a_num_non_zero: serialized_constraint_matrices.a_num_non_zero,
        b_num_non_zero: serialized_constraint_matrices.b_num_non_zero,
        c_num_non_zero: serialized_constraint_matrices.c_num_non_zero,
        a: serialized_constraint_matrices.a.data,
        b: serialized_constraint_matrices.b.data,
        c: serialized_constraint_matrices.c.data,
    };

    Ok((proving_key, constraint_matrices))
}

pub fn read_proving_key_and_matrices_from_zkey(
    zkey_path: &str,
) -> Result<(SerializableProvingKey, SerializableConstraintMatrices<Fr>)> {
    let zkey_file_path = PathBuf::from(zkey_path);
    let zkey_file = File::open(zkey_file_path).wrap_err("Failed to open zkey file")?;

    let mut buf_reader = BufReader::new(zkey_file);

    let (proving_key, matrices) =
        read_zkey(&mut buf_reader).wrap_err("Failed to read zkey file")?;

    let serializable_proving_key = SerializableProvingKey(proving_key);
    let serializable_constrain_matrices = SerializableConstraintMatrices {
        num_instance_variables: matrices.num_instance_variables,
        num_witness_variables: matrices.num_witness_variables,
        num_constraints: matrices.num_constraints,
        a_num_non_zero: matrices.a_num_non_zero,
        b_num_non_zero: matrices.b_num_non_zero,
        c_num_non_zero: matrices.c_num_non_zero,
        a: SerializableMatrix { data: matrices.a },
        b: SerializableMatrix { data: matrices.b },
        c: SerializableMatrix { data: matrices.c },
    };

    Ok((serializable_proving_key, serializable_constrain_matrices))
}

pub fn convert_zkey(
    proving_key: SerializableProvingKey,
    constraint_matrices: SerializableConstraintMatrices<Fr>,
    arkzkey_path: &str,
) -> Result<()> {
    let arkzkey_file_path = PathBuf::from(arkzkey_path);

    let mut file = File::create(&arkzkey_file_path)
        .wrap_err("Failed to create serialized proving key file")?;

    proving_key
        .serialize_compressed(&mut file)
        .wrap_err("Failed to serialize proving key")?;

    constraint_matrices
        .serialize_compressed(&mut file)
        .wrap_err("Failed to serialize constraint matrices")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_read_arkzkey_from_bytes() -> Result<()> {
        const ARKZKEY_BYTES: &[u8] = include_bytes!("./semaphore.16.arkzkey");

        println!("Reading arkzkey from bytes (keccak)");
        let now = Instant::now();
        let (_deserialized_proving_key, _deserialized_constraint_matrices) =
            read_arkzkey_from_bytes(ARKZKEY_BYTES)?;
        println!("Time to read arkzkey: {:?}", now.elapsed());

        Ok(())
    }
}
