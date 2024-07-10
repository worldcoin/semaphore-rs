use semaphore::{merkle_tree::Hasher, poseidon_tree::PoseidonHash, Field};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
#[allow(clippy::wildcard_imports)]
use semaphore::lazy_merkle_tree::*;

criterion_main!(lazy_merkle_tree);
criterion_group!(
    lazy_merkle_tree,
    bench_create_dense_tree,
    bench_create_dense_mmap_tree,
    bench_restore_dense_mmap_tree,
    bench_dense_tree_reads,
    bench_dense_mmap_tree_reads,
    bench_dense_tree_writes,
    bench_dense_mmap_tree_writes,
);

struct TreeValues<H: Hasher> {
    depth:          usize,
    prefix_depth:   usize,
    empty_value:    H::Hash,
    initial_values: Vec<H::Hash>,
}

fn bench_create_dense_tree(criterion: &mut Criterion) {
    let tree_values = vec![
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_create_dense_tree");

    for value in tree_values.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(format!("create_dense_tree_depth_{}", value.depth)), value, |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let _tree = LazyMerkleTree::<PoseidonHash, Canonical>::new_with_dense_prefix_with_initial_values(value.depth, value.prefix_depth, &value.empty_value, &value.initial_values);
                    let _root = _tree.root();
                });
            });
    }
    group.finish();
}

fn bench_create_dense_mmap_tree(criterion: &mut Criterion) {
    let tree_values = vec![
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_create_dense_mmap_tree");

    for value in tree_values.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(format!("create_dense_mmap_tree_depth_{}", value.depth)), value, |bencher: &mut criterion::Bencher, value| {
                let file = tempfile::NamedTempFile::new().unwrap();
                let path = file.path().to_str().unwrap();
                bencher.iter(|| {
                    let _tree = LazyMerkleTree::<PoseidonHash, Canonical>::new_mmapped_with_dense_prefix_with_init_values(value.depth, value.prefix_depth, &value.empty_value, &value.initial_values, path).unwrap();
                    let _root = _tree.root();
                });
            });
    }
    group.finish();
    // remove created mmap file
    let _ = std::fs::remove_file("./testfile");
}

fn bench_restore_dense_mmap_tree(criterion: &mut Criterion) {
    let tree_values = vec![
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];


    let mut group = criterion.benchmark_group("bench_restore_dense_mmap_tree");

    (0..3).zip(tree_values).for_each(|(id, value)| {
        
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        {
            let _tree = LazyMerkleTree::<PoseidonHash, Canonical>::new_mmapped_with_dense_prefix_with_init_values(value.depth, value.prefix_depth, &value.empty_value, &value.initial_values, path).unwrap();
            let _root = _tree.root();
        }
        
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("restore_dense_mmap_tree_depth_{}", value.depth)),
            &(id, value),
            |bencher: &mut criterion::Bencher, (_id, value)| {
                bencher.iter(|| {
                    let _tree =
                        LazyMerkleTree::<PoseidonHash, Canonical>::attempt_dense_mmap_restore(
                            value.depth,
                            value.depth,
                            &value.empty_value,
                            path,
                        )
                        .unwrap();
                    let _root = _tree.root();
                });
            },
        );
    });
    group.finish();
}

#[allow(unused)]
fn bench_dense_tree_reads(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let tree = LazyMerkleTree::<PoseidonHash>::new_with_dense_prefix_with_initial_values(
        tree_value.depth,
        tree_value.prefix_depth,
        &tree_value.empty_value,
        &tree_value.initial_values,
    );

    criterion.bench_function("dense tree reads", |b| {
        b.iter(|| {
            // read all leaves, and compare to ones in tree value
            ((1 << (tree_value.depth - 1))..(1 << tree_value.depth)).for_each(|index| {
                let _proof = tree.proof(index);
            })
        })
    });
}

#[allow(unused)]
fn bench_dense_mmap_tree_reads(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();

    let tree = LazyMerkleTree::<PoseidonHash>::new_mmapped_with_dense_prefix_with_init_values(
        tree_value.depth,
        tree_value.prefix_depth,
        &tree_value.empty_value,
        &tree_value.initial_values,
        path,
    )
    .unwrap();

    criterion.bench_function("dense mmap tree reads", |b| {
        b.iter(|| {
            // read all leaves, and compare to ones in tree value
            ((1 << (tree.depth() - 1))..(1 << tree.depth())).for_each(|index| {
                let _proof = tree.proof(index);
            })
        })
    });
}

fn bench_dense_tree_writes(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let value = Field::from(123_456);

    criterion.bench_function("dense tree writes", |b| {
        b.iter_batched(
            || {
                LazyMerkleTree::<PoseidonHash>::new_with_dense_prefix_with_initial_values(
                    tree_value.depth,
                    tree_value.prefix_depth,
                    &tree_value.empty_value,
                    &tree_value.initial_values,
                )
            },
            |tree| {
                let _new_tree = tree.update_with_mutation(9000, &value);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_dense_mmap_tree_writes(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();

    let value = Field::from(123_456);

    criterion.bench_function("dense mmap tree writes", |b| {
        b.iter_batched(
            || {
                LazyMerkleTree::<PoseidonHash>::new_mmapped_with_dense_prefix_with_init_values(
                    tree_value.depth,
                    tree_value.prefix_depth,
                    &tree_value.empty_value,
                    &tree_value.initial_values,
                    path,
                )
                .unwrap()
            },
            |tree| {
                let _new_tree = tree.update_with_mutation(9000, &value);
            },
            BatchSize::SmallInput,
        );
    });
}

fn create_values_for_tree(depth: usize) -> TreeValues<PoseidonHash> {
    let prefix_depth = depth;
    let empty_value = Field::from(0);

    let initial_values: Vec<ruint::Uint<256, 4>> = (0..(1 << depth)).map(Field::from).collect();

    TreeValues {
        depth,
        prefix_depth,
        empty_value,
        initial_values,
    }
}
