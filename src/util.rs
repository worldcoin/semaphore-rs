use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use poseidon_rs::{Fr, FrRepr};

#[must_use]
#[allow(clippy::missing_panics_doc)] // TODO: Remove panics
pub fn fr_to_bigint(fr: Fr) -> BigInt {
    let mut bytes = [0_u8; 32];
    fr.into_repr().write_be(&mut bytes[..]).unwrap();
    BigInt::from_bytes_be(Sign::Plus, &bytes)
}

#[must_use]
#[allow(clippy::missing_panics_doc)] // TODO: Remove panics
pub fn bigint_to_fr(bi: &BigInt) -> Fr {
    // dirty: have to force the point into the field manually, otherwise you get an
    // error if bi not in field
    let q = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();
    let m = bi.modpow(&BigInt::from(1), &q);

    let mut repr = FrRepr::default();
    let (_, mut res) = m.to_bytes_be();

    // prepend zeros
    res.reverse();
    res.resize(32, 0);
    res.reverse();

    repr.read_be(&res[..]).unwrap();
    Fr::from_repr(repr).unwrap()
}
