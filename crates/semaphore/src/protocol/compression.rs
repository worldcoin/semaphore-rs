//! Groth16 proof compression
//!
//! Ported from https://github.com/worldcoin/world-id-state-bridge/blob/main/src/SemaphoreVerifier.sol
//!
//! Based upon work in https://xn--2-umb.com/23/bn254-compression/

use ruint::aliases::U256;
use ruint::uint;

use super::{Proof, G1, G2};
use lazy_static::lazy_static;

/// Base field Fp order P
pub const P: U256 =
    uint! { 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_U256 };

// A helper for a frequently used constants
pub const ONE: U256 = uint! { 1_U256 };
pub const TWO: U256 = uint! { 2_U256 };
pub const THREE: U256 = uint! { 3_U256 };

lazy_static! {
    /// Exponent for the square root in Fp
    pub static ref EXP_SQRT_FP: U256 = (P + ONE) / U256::from(4);

    /// Exponent for the inverse in Fp
    pub static ref EXP_INVERSE_FP: U256 = P - TWO;
}

pub struct CompressedProof(pub U256, pub (U256, U256), pub U256);

impl CompressedProof {
    pub const fn from_flat(flat: [U256; 4]) -> Self {
        let [a, b0, b1, c] = flat;

        Self(a, (b0, b1), c)
    }

    pub const fn flatten(self) -> [U256; 4] {
        let Self(a, (b0, b1), c) = self;
        [a, b0, b1, c]
    }
}

pub fn compress_proof(proof: Proof) -> Option<CompressedProof> {
    let Proof(g1a, g2, g1b) = proof;

    // NOTE: Order of real and imaginary parts in the proof data is flipped
    let ([x0, x1], [y0, y1]) = g2;
    let g2 = ([x1, x0], [y1, y0]);

    let a = compress_g1(g1a)?;
    let c = compress_g2(g2)?;
    let b = compress_g1(g1b)?;

    Some(CompressedProof(a, c, b))
}

pub fn decompress_proof(compressed: CompressedProof) -> Option<Proof> {
    let CompressedProof(a, c, b) = compressed;

    let g1a = decompress_g1(a)?;
    let g2 = decompress_g2(c)?;
    let g1b = decompress_g1(b)?;

    // Unswap
    let ([x1, x0], [y1, y0]) = g2;
    let g2 = ([x0, x1], [y0, y1]);

    Some(Proof(g1a, g2, g1b))
}

pub fn compress_g1((x, y): G1) -> Option<U256> {
    if x >= P || y >= P {
        return None; // Point not in field
    }
    if x == U256::ZERO && y == U256::ZERO {
        return Some(U256::ZERO); // Point at infinity
    }
    let y_pos = sqrt_fp(x.pow_mod(THREE, P).add_mod(THREE, P))?;
    if y == y_pos {
        Some(x.wrapping_shl(1))
    } else if y == neg_fp(y_pos) {
        Some(x.wrapping_shl(1) | ONE)
    } else {
        None
    }
}

pub fn decompress_g1(c: U256) -> Option<G1> {
    if c == U256::ZERO {
        return Some((U256::ZERO, U256::ZERO)); // Point at infinity
    }

    let negate = c & ONE == ONE;
    let x: U256 = c >> 1;
    if x >= P {
        return None;
    }

    let y2 = x.pow_mod(THREE, P).add_mod(THREE, P);
    let mut y = sqrt_fp(y2)?;

    if negate {
        y = neg_fp(y);
    }
    Some((x, y))
}

/// Compresses the
pub fn compress_g2(([x0, x1], [y0, y1]): G2) -> Option<(U256, U256)> {
    if x0 >= P || x1 >= P || y0 >= P || y1 >= P {
        return None; // Point not in field
    }
    if (x0 | x1 | y0 | y1) == U256::ZERO {
        return Some((U256::ZERO, U256::ZERO)); // Point at infinity
    }

    // Compute y^2
    let n3ab = x0.mul_mod(x1, P).mul_mod(P - THREE, P);
    let a_3 = x0.pow_mod(THREE, P);
    let b_3 = x1.pow_mod(THREE, P);

    let y0_pos = U256::from(27)
        .mul_mod(U256::from(82).inv_mod(P).unwrap(), P)
        .add_mod(a_3.add_mod(n3ab.mul_mod(x1, P), P), P);

    let y1_pos = neg_fp(
        THREE
            .mul_mod(U256::from(82).inv_mod(P).unwrap(), P)
            .add_mod(b_3.add_mod(n3ab.mul_mod(x0, P), P), P),
    );

    // Determine hint bit
    let d = sqrt_fp(
        y0_pos
            .mul_mod(y0_pos, P)
            .add_mod(y1_pos.mul_mod(y1_pos, P), P),
    )?;
    let hint = !is_square_fp(y0_pos.add_mod(d, P).mul_mod(TWO.inv_mod(P).unwrap(), P));

    // Recover y
    let (new_y0_pos, new_y1_pos) = sqrt_fp2(y0_pos, y1_pos, hint)?;

    let hint = if hint { TWO } else { U256::from(0) };
    if y0 == new_y0_pos && y1 == new_y1_pos {
        Some(((x0 << 2) | hint, x1))
    } else if y0 == neg_fp(new_y0_pos) && y1 == neg_fp(new_y1_pos) {
        Some(((x0 << 2) | hint | ONE, x1))
    } else {
        None
    }
}

pub fn decompress_g2((c0, c1): (U256, U256)) -> Option<G2> {
    if c0 == U256::ZERO && c1 == U256::ZERO {
        return Some(([U256::ZERO, U256::ZERO], [U256::ZERO, U256::ZERO])); // Point at infinity
    }

    let negate = c0 & ONE == ONE;
    let hint = c0 & TWO == TWO;

    let x0: U256 = c0 >> 2;
    let x1 = c1;

    if x0 >= P || x1 >= P {
        return None;
    }

    let n3ab = x0.mul_mod(x1, P).mul_mod(P - THREE, P);
    let a_3 = x0.pow_mod(THREE, P);
    let b_3 = x1.pow_mod(THREE, P);

    let y0 = U256::from(27)
        .mul_mod(U256::from(82).inv_mod(P)?, P)
        .add_mod(a_3.add_mod(n3ab.mul_mod(x1, P), P), P);
    let y1 = neg_fp(
        THREE
            .mul_mod(U256::from(82).inv_mod(P)?, P)
            .add_mod(b_3.add_mod(n3ab.mul_mod(x0, P), P), P),
    );

    let (mut y0, mut y1) = sqrt_fp2(y0, y1, hint)?;
    if negate {
        y0 = neg_fp(y0);
        y1 = neg_fp(y1);
    }

    Some(([x0, x1], [y0, y1]))
}

fn sqrt_fp(a: U256) -> Option<U256> {
    let x = a.pow_mod(*EXP_SQRT_FP, P);
    if x.mul_mod(x, P) == a {
        Some(x)
    } else {
        None
    }
}

fn sqrt_fp2(a0: U256, a1: U256, hint: bool) -> Option<(U256, U256)> {
    let mut d = sqrt_fp(a0.pow_mod(TWO, P).add_mod(a1.pow_mod(TWO, P), P))?;

    if hint {
        d = neg_fp(d);
    }

    let frac_1_2 = ONE.mul_mod(TWO.inv_mod(P)?, P);
    let x0 = sqrt_fp(a0.add_mod(d, P).mul_mod(frac_1_2, P))?;
    let x1 = a1.mul_mod(invert_fp(x0.mul_mod(TWO, P))?, P);

    if a0 != x0.pow_mod(TWO, P).add_mod(neg_fp(x1.pow_mod(TWO, P)), P)
        || a1 != TWO.mul_mod(x0.mul_mod(x1, P), P)
    {
        return None;
    }

    Some((x0, x1))
}

fn is_square_fp(a: U256) -> bool {
    let x = a.pow_mod(*EXP_SQRT_FP, P);
    x.mul_mod(x, P) == a
}

/// Inversion in Fp
///
/// Returns a number x such that a * x = 1 in Fp
/// Returns None if the inverse does not exist
fn invert_fp(a: U256) -> Option<U256> {
    let x = a.pow_mod(*EXP_INVERSE_FP, P);

    if a.mul_mod(x, P) != ONE {
        return None;
    }

    Some(x)
}

fn neg_fp(a: U256) -> U256 {
    P.wrapping_sub(a % P) % P
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inversion() {
        let v = uint! { 4598362786468342265918458423096940256393720972438048893356218087518821823203_U256 };
        let inverted = invert_fp(v).unwrap();
        let exp_inverted = uint! { 4182222526301715069940346543278816173622053692765626450942898397518664864041_U256 };

        assert_eq!(exp_inverted, inverted);
    }

    #[test]
    fn square_root_fp() {
        let v = uint! { 14471043194638943579446425262583282548539507047061604313953794288955195726209_U256 };
        let exp_sqrt = uint! { 13741342543520938546471415319044405232187715299443307089577869276344592329757_U256 };

        let sqrt = sqrt_fp(v).unwrap();
        assert_eq!(exp_sqrt, sqrt);
    }

    #[test]
    fn square_root_fp_2() {
        let (a, b) = sqrt_fp2(uint!{17473058728477435457299093362519578563618705081729024467362715416915525458528_U256}, uint!{17683468329848516541101685027677188007795188556813329975791177956431310972350_U256}, false).unwrap();

        let exp_a = uint! {10193706077588260514783319931179623845729747565730309463634080055351233087269_U256};
        let exp_b = uint! {2911435556167431587172450261242327574185987927358833959334220021362478804490_U256};

        assert_eq!(exp_a, a);
        assert_eq!(exp_b, b);
    }

    // The literal values below are taken from the proof in the following tx: https://etherscan.io/tx/0x53309842294be8c2b9fd694c4e86a5ab031c0d58750978fb3d6f60de16eaa897
    // Raw proof data is:
    // 20565048055856194013099208963146657799256893353279242520150547463020687826541
    // 16286013012747852737396822706018267259565592188907848191354824303311847109059
    // 4348608846293503080802796983494208797681981448804902149317789801083784587558
    // 6172488348732750834133346196464201580503416389945891763609808290085997580078
    // 3229429189805934086496276224876305383924675874777054942516982958483565949767
    // 944252930093106871283598150477854448876343937304805759422971930315581301659
    // 18318130744212307125672524358864792312717149086464333958791498157127232409959
    // 8256141885907329266852096557308020923997215847794048916749940281741155521604
    //
    // Note that for the G2 compression test the order of real and imaginary is flipped

    #[test]
    fn proof_compression() {
        let flat_proof: [U256; 8] = uint! { [
            20565048055856194013099208963146657799256893353279242520150547463020687826541_U256,
            16286013012747852737396822706018267259565592188907848191354824303311847109059_U256,
            4348608846293503080802796983494208797681981448804902149317789801083784587558_U256,
            6172488348732750834133346196464201580503416389945891763609808290085997580078_U256,
            3229429189805934086496276224876305383924675874777054942516982958483565949767_U256,
            944252930093106871283598150477854448876343937304805759422971930315581301659_U256,
            18318130744212307125672524358864792312717149086464333958791498157127232409959_U256,
            8256141885907329266852096557308020923997215847794048916749940281741155521604_U256,
        ]};
        let proof = Proof::from_flat(flat_proof);

        let compressed = compress_proof(proof).unwrap();
        let decompressed = decompress_proof(compressed).unwrap();

        assert_eq!(proof, decompressed);
    }

    #[test]
    fn g1_compression() {
        let point: G1 = uint! {
            (
                0x19ded61ab5c58fdb12367526c6bc04b9186d0980c4b6fd48a44093e80f9b4206_U256,
                0x2e619a034be10e9aab294f1c77a480378e84782c8519449aef0c8f6952382bda_U256
            )
        };
        let exp_compressed =
            uint! { 0x33bdac356b8b1fb6246cea4d8d78097230da1301896dfa91488127d01f36840c_U256 };

        let compressed = compress_g1(point).unwrap();
        assert_eq!(exp_compressed, compressed);

        let decompressed = decompress_g1(compressed).unwrap();
        assert_eq!(point, decompressed);
    }

    #[test]
    fn g2_compression() {
        let point: G2 = uint! {
            (
                [
                    0x077484BC4068C81CDAA598B2B15E4A5559DDFEB4F9E20AC08B52E8C9873C536D_U256,
                    0x25E744163329AABFB40086C09E0B54D09DFBD302CE975E71150133E46E75F0AA_U256,
                ],
                [
                    0x20AF3E3AFED950A86937F4319100B19A1141FF59DA42B9670CFA57E5D83BE618_U256,
                    0x089C901AA5603652F8CC748F04907233C63A75302244D67FF974B05AF09948D2_U256,
                ]
            )
        };

        let compressed = compress_g2(point).unwrap();
        let decompressed = decompress_g2(compressed).unwrap();

        assert_eq!(point, decompressed);
    }
}
