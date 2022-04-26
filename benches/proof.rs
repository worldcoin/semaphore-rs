use ark_bn254::Bn254;
use ark_circom::CircomReduction;
use ark_groth16::{
    create_proof_with_reduction_and_matrices,
    Proof,
};
use ark_std::UniformRand;
use criterion::{
    BenchmarkId,
    Criterion,
    criterion_group,
    criterion_main,
};
use semaphore::{
    circuit::{
        witness_calculator,
        zkey,
    },
    hash_to_field,
    identity::Identity,
    merkle_tree,
    poseidon_tree::{
        PoseidonHash,
        PoseidonTree,
    },
    protocol::{
        generate_proof,
        merkle_proof_to_vec,
    },
    Field,
};

fn init() -> (Identity, merkle_tree::Proof<PoseidonHash>, Field, Field) {
    let leaf = Field::from(0);

    // Create tree
    let id = Identity::from_seed(b"hello");
    let mut tree = PoseidonTree::new(21, leaf);
    tree.set(0, id.commitment());
    let merkle_proof = tree.proof(0).expect("proof should exist");

    // change signal and external_nullifier here
    let signal_hash = hash_to_field(b"xxx");
    let external_nullifier_hash = hash_to_field(b"appId");

    (id, merkle_proof, external_nullifier_hash, signal_hash)
}

fn inputs() -> [(&'static str, Vec<Field>); 6] {
    let (id, merkle_proof, external_nullifier_hash, signal_hash) = init();
    [
        ("identityNullifier", vec![id.nullifier]),
        ("identityTrapdoor", vec![id.trapdoor]),
        ("treePathIndices", merkle_proof.path_index()),
        ("treeSiblings", merkle_proof_to_vec(&merkle_proof)),
        ("externalNullifier", vec![external_nullifier_hash]),
        ("signalHash", vec![signal_hash]),
    ]
}

fn calculate_witness_element(criterion: &mut Criterion) {
    let inputs = inputs();

    criterion.bench_with_input(
        BenchmarkId::new("calculate witness element", "standard inputs"),
        &inputs,
        |bencher, inputs| {
            let inputs = inputs.clone();
            bencher.iter(|| {
                let inputs = inputs.iter().map(|(name, values)| {
                    (
                        name.to_string(),
                        values.iter().copied().map(Into::into).collect::<Vec<_>>(),
                    )
                });
                witness_calculator()
                    .lock()
                    .expect("witness_calculator mutex should not get poisoned")
                    .calculate_witness_element::<Bn254, _>(inputs, false)
                    .unwrap()
            });
        }
    );
}

fn create_proof(criterion: &mut Criterion) {
    let inputs = inputs();
    let inputs = inputs.iter().map(|(name, values)| {
        (
            name.to_string(),
            values.iter().copied().map(Into::into).collect::<Vec<_>>(),
        )
    });
    let full_assignment = witness_calculator()
        .lock()
        .expect("witness_calculator mutex should not get poisoned")
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .unwrap();

    let r = ark_bn254::Fr::rand(&mut rand::thread_rng());
    let s = ark_bn254::Fr::rand(&mut rand::thread_rng());

    criterion.bench_function(
        "create proof with reduction and matrices",
        |bencher| bencher.iter(|| {
            let zkey = zkey();
            let ark_proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
                &zkey.0,
                r,
                s,
                &zkey.1,
                zkey.1.num_instance_variables,
                zkey.1.num_constraints,
                full_assignment.as_slice(),
            ).unwrap();
            Into::<Proof<_>>::into(ark_proof)
        }),
    );
}

fn full_proof(criterion: &mut Criterion) {
    let (id, merkle_proof, external_nullifier_hash, signal_hash) = init();

    criterion.bench_function(
        "generate full proof",
        move |b| {
        b.iter(|| {
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();
        });
    });
}

criterion_group!(benches, calculate_witness_element, create_proof, full_proof);
criterion_main!(benches);
