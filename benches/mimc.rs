use criterion::{
    black_box,
    criterion_group,
    criterion_main,
    BenchmarkId,
    Criterion,
};
use hex_literal::hex;
use semaphore::{
    hash::Hash,
    mimc_hash,
    mimc_tree,
};
use zkp_u256::U256;

// TODO: Randomize trees and indices
// TODO: Bench over a range of depths

const DEPTH: usize = 20;
const INDEX: usize = 354_184;
const LEAF: Hash = Hash::from_bytes_be(hex!(
        "352aa0818e138060d93b80393828ef8cdc104f331799b3ea647907481e51cce9"
        ));

fn mix(criterion: &mut Criterion) {
    let left = U256::ONE;
    let right = U256::ZERO;
    criterion.bench_with_input(
        BenchmarkId::new("mimc hash mix", "left one, right zero"),
        &(left, right),
        |bencher, input| {
            let mut left = input.0.clone();
            let mut right = input.1.clone();
            bencher.iter(move || mimc_hash::mix(&mut left, &mut right));
        }
    );
}

fn tree_set(criterion: &mut Criterion) {
    let mut tree = mimc_tree::MimcTree::new(DEPTH, LEAF);
    let hash = Hash::from_bytes_be([0_u8; 32]);
    criterion.bench_function("mimc tree set", move |bencher| {
        bencher.iter(|| tree.set(INDEX, black_box(hash)));
    });
}

fn proof(criterion: &mut Criterion) {
    let tree = mimc_tree::MimcTree::new(DEPTH, LEAF);
    criterion.bench_function("mimc tree proof", move |bencher| {
        bencher.iter(|| tree.proof(black_box(INDEX)));
    });
}

fn verify(criterion: &mut Criterion) {
    let tree = mimc_tree::MimcTree::new(DEPTH, LEAF);
    let proof = tree.proof(INDEX).expect("proof should exist");
    let hash = Hash::from_bytes_be([0_u8; 32]);
    criterion.bench_function("mimc verify", move |bencher| {
        bencher.iter(|| proof.root(black_box(hash)));
    });
}

criterion_group!(benches, mix, proof, tree_set, verify);
criterion_main!(benches);
