use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use semaphore::{
    hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, protocol::generate_proof,
    Field,
};

fn proof(criterion: &mut Criterion) {
    let leaf = Field::from(0);

    // Create tree
    let id = Identity::from_seed(b"hello");
    let mut tree = PoseidonTree::new(21, leaf);
    tree.set(0, id.commitment());
    let merkle_proof = tree.proof(0).expect("proof should exist");

    // change signal and external_nullifier here
    let signal_hash = hash_to_field(b"xxx");
    let external_nullifier_hash = hash_to_field(b"appId");

    criterion.bench_function("generate proof", move |b| {
        b.iter(|| {
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();
        });
    });
}

criterion_group!(benches, proof);
criterion_main!(benches);
