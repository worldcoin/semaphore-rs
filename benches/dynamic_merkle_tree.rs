use semaphore::{merkle_tree::Hasher, poseidon_tree::PoseidonHash, Field};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
#[allow(clippy::wildcard_imports)]
use semaphore::dynamic_merkle_tree::*;

criterion_main!(dynamic_merkle_tree);
criterion_group!(
    dynamic_merkle_tree,
    bench_dynamic_create_dense_tree,
    bench_dynamic_create_dense_mmap_tree,
    bench_dynamic_restore_dense_mmap_tree,
    bench_dynamic_dense_tree_reads,
    bench_dynamic_dense_mmap_tree_reads,
    bench_dynamic_dense_tree_writes,
    bench_dynamic_dense_mmap_tree_writes,
);

struct TreeValues<H: Hasher> {
    depth:          usize,
    empty_value:    H::Hash,
    initial_values: Vec<H::Hash>,
}

fn bench_dynamic_create_dense_tree(criterion: &mut Criterion) {
    let tree_values = [
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_dynamic_create_dense_tree");

    for value in tree_values.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("create_dense_tree_depth_{}", value.depth)),
            value,
            |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let _tree = DynamicMerkleTree::<PoseidonHash>::new_with_leaves(
                        (),
                        value.depth,
                        &value.empty_value,
                        &value.initial_values,
                    );
                    let _root = _tree.root();
                });
            },
        );
    }
    group.finish();
}

fn bench_dynamic_create_dense_mmap_tree(criterion: &mut Criterion) {
    let tree_values = [
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_dynamic_create_dense_mmap_tree");

    for value in tree_values.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("create_dense_mmap_tree_depth_{}", value.depth)),
            value,
            |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let config = unsafe { MmapTreeStorageConfig::new("./testfile".into()) };
                    let _tree =
                        DynamicMerkleTree::<PoseidonHash, MmapVec<PoseidonHash>>::new_with_leaves(
                            config,
                            value.depth,
                            &value.empty_value,
                            &value.initial_values,
                        );
                    let _root = _tree.root();
                });
            },
        );
    }
    group.finish();
    // remove created mmap file
    std::fs::remove_file("./testfile").unwrap();
}

fn bench_dynamic_restore_dense_mmap_tree(criterion: &mut Criterion) {
    let tree_values = vec![
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    // create 3 trees with different sizes, that are immediately dropped, but mmap
    // file should be saved
    (0..3).zip(&tree_values).for_each(|(id, value)| {
        let config = unsafe { MmapTreeStorageConfig::new(format!("./testfile{}", id).into()) };
        let _tree = DynamicMerkleTree::<PoseidonHash, MmapVec<PoseidonHash>>::new_with_leaves(
            config,
            value.depth,
            &value.empty_value,
            &value.initial_values,
        );
        let _root = _tree.root();
    });

    let mut group = criterion.benchmark_group("bench_dynamic_restore_dense_mmap_tree");

    (0..3).zip(tree_values).for_each(|(id, value)| {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("restore_dense_mmap_tree_depth_{}", value.depth)),
            &(id, value),
            |bencher: &mut criterion::Bencher, (id, value)| {
                bencher.iter(|| {
                    let config =
                        unsafe { MmapTreeStorageConfig::new(format!("./testfile{}", id).into()) };
                    let _tree = DynamicMerkleTree::<PoseidonHash, MmapVec<PoseidonHash>>::restore(
                        config,
                        value.depth,
                        &value.empty_value,
                    )
                    .unwrap();
                    let _root = _tree.root();
                });
            },
        );
    });
    group.finish();
    // remove created mmap files
    std::fs::remove_file("./testfile0").unwrap();
    std::fs::remove_file("./testfile1").unwrap();
    std::fs::remove_file("./testfile2").unwrap();
}

#[allow(unused)]
fn bench_dynamic_dense_tree_reads(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let tree = DynamicMerkleTree::<PoseidonHash>::new_with_leaves(
        (),
        tree_value.depth,
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
fn bench_dynamic_dense_mmap_tree_reads(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let config = unsafe { MmapTreeStorageConfig::new("./testfile".into()) };
    let tree = DynamicMerkleTree::<PoseidonHash, MmapVec<PoseidonHash>>::new_with_leaves(
        config,
        tree_value.depth,
        &tree_value.empty_value,
        &tree_value.initial_values,
    );

    criterion.bench_function("dense mmap tree reads", |b| {
        b.iter(|| {
            // read all leaves, and compare to ones in tree value
            ((1 << (tree.depth() - 1))..(1 << tree.depth())).for_each(|index| {
                let _proof = tree.proof(index);
            })
        })
    });
    // remove mmap file
    std::fs::remove_file("./testfile");
}

fn bench_dynamic_dense_tree_writes(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let value = Field::from(123_456);

    criterion.bench_function("dense tree writes", |b| {
        b.iter_batched_ref(
            || {
                DynamicMerkleTree::<PoseidonHash>::new_with_leaves(
                    (),
                    tree_value.depth,
                    &tree_value.empty_value,
                    &tree_value.initial_values,
                )
            },
            |tree| {
                tree.set_leaf(9000, value);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_dynamic_dense_mmap_tree_writes(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let value = Field::from(123_456);

    criterion.bench_function("dense mmap tree writes", |b| {
        b.iter_batched_ref(
            || {
                let config = unsafe { MmapTreeStorageConfig::new("./testfile".into()) };
                DynamicMerkleTree::<PoseidonHash, MmapVec<PoseidonHash>>::new_with_leaves(
                    config,
                    tree_value.depth,
                    &tree_value.empty_value,
                    &tree_value.initial_values,
                )
            },
            |tree| {
                tree.set_leaf(9000, value);
            },
            BatchSize::SmallInput,
        );
    });
    // remove mmap file
    std::fs::remove_file("./testfile").unwrap();
}

fn create_values_for_tree(depth: usize) -> TreeValues<PoseidonHash> {
    let empty_value = Field::from(0);

    let initial_values: Vec<ruint::Uint<256, 4>> = (0..(1 << depth)).map(Field::from).collect();

    TreeValues {
        depth,
        empty_value,
        initial_values,
    }
}
