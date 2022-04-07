// See <https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom>
// See <https://github.com/arkworks-rs/sponge>
// See <https://github.com/arnaucube/poseidon-rs>
// See <https://github.com/filecoin-project/neptune>
// See <https://github.com/dusk-network/poseidon252>
// See <https://github.com/arkworks-rs/sponge/blob/master/src/poseidon/mod.rs>

use crate::Field;
use ark_bn254::Fr as ArkField;
use ark_sponge::{
    poseidon::{PoseidonParameters, PoseidonSponge},
    CryptographicSponge,
};
use once_cell::sync::Lazy;

impl ark_sponge::Absorb for Field {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        ArkField::from(*self).to_sponge_bytes(dest);
    }

    fn to_sponge_field_elements<F: ark_ff::PrimeField>(&self, dest: &mut Vec<F>) {
        ArkField::from(*self).to_sponge_field_elements(dest)
    }
}

#[must_use]
pub fn poseidon_hash(input: &[Field]) -> Field {
    let mds = Vec::new();
    let ark = Vec::new();

    // See <https://github.com/iden3/circomlib/blob/875013143bfbacd6254446fb88f53de6afb941ae/circuits/poseidon.circom#L71>
    let params = PoseidonParameters::<ArkField>::new(8, 57, 5, mds, ark);

    let mut sponge = PoseidonSponge::new(&params);

    sponge.absorb(&input);

    sponge
        .squeeze_field_elements::<ArkField>(1)
        .pop()
        .unwrap()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_poseidon_hash() {
        assert_eq!(
            poseidon_hash(&[Field::from(0)]),
            Field::from_be_bytes_mod_order(&hex!(
                "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c"
            ))
        );
        assert_eq!(
            poseidon_hash(&[Field::from(1)]),
            Field::from_be_bytes_mod_order(&hex!(
                "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133"
            ))
        );
        assert_eq!(
            poseidon_hash(&[Field::from(0), Field::from(0)]),
            Field::from_be_bytes_mod_order(&hex!(
                "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
            ))
        );
        assert_eq!(
            poseidon_hash(&[Field::from(0), Field::from(1)]),
            Field::from_be_bytes_mod_order(&hex!(
                "1bd20834f5de9830c643778a2e88a3a1363c8b9ac083d36d75bf87c49953e65e"
            ))
        );
        assert_eq!(
            poseidon_hash(&[Field::from(123), Field::from(456)]),
            Field::from_be_bytes_mod_order(&hex!(
                "2b60bf8caa91452f000be587c441f6495f36def6fc4c36f5cc7b5d673f59fd0f"
            ))
        );
    }
}
