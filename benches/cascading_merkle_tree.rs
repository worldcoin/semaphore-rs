use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
#[allow(clippy::wildcard_imports)]
use semaphore::cascading_merkle_tree::*;
use semaphore::{
    generic_storage::MmapVec, merkle_tree::Hasher, poseidon_tree::PoseidonHash, Field,
};

criterion_main!(cascading_merkle_tree);
criterion_group!(
    cascading_merkle_tree,
    bench_cascading_validate,
    bench_cascading_create_dense_tree,
    bench_cascading_create_dense_mmap_tree,
    bench_cascading_restore_dense_mmap_tree,
    bench_cascading_dense_tree_reads,
    bench_cascading_dense_mmap_tree_reads,
    bench_cascading_dense_tree_writes,
    bench_cascading_dense_mmap_tree_writes,
    bench_cascading_proof_from_hash
);

struct TreeValues<H: Hasher> {
    depth: usize,
    empty_value: H::Hash,
    initial_values: Vec<H::Hash>,
}

fn bench_cascading_proof_from_hash(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    criterion.bench_function("bench_cascading_proof_from_hash", |b| {
        let leaf = Field::from(234123412341usize);
        b.iter_batched_ref(
            || {
                let mut tree = CascadingMerkleTree::<PoseidonHash>::new_with_leaves(
                    vec![],
                    tree_value.depth,
                    &tree_value.empty_value,
                    &tree_value.initial_values,
                );
                tree.set_leaf(1 << 13, leaf);
                tree
            },
            |tree| {
                let _ = tree.proof_from_hash(leaf);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_cascading_validate(criterion: &mut Criterion) {
    let tree_values = [
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_cascading_validate");

    for value in tree_values.iter() {
        let tree = CascadingMerkleTree::<PoseidonHash>::new_with_leaves(
            vec![],
            value.depth,
            &value.empty_value,
            &value.initial_values,
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("validate_{}", value.depth)),
            value,
            |bencher: &mut criterion::Bencher, _| {
                bencher.iter(|| {
                    tree.validate().unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_cascading_create_dense_tree(criterion: &mut Criterion) {
    let tree_values = [
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_cascading_create_dense_tree");

    for value in tree_values.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("create_dense_tree_depth_{}", value.depth)),
            value,
            |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let _tree = CascadingMerkleTree::<PoseidonHash>::new_with_leaves(
                        vec![],
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

fn bench_cascading_create_dense_mmap_tree(criterion: &mut Criterion) {
    let tree_values = [
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_cascading_create_dense_mmap_tree");

    for value in tree_values.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("create_dense_mmap_tree_depth_{}", value.depth)),
            value,
            |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let tempfile = tempfile::tempfile().unwrap();
                    let storage: MmapVec<_> = unsafe { MmapVec::create(tempfile).unwrap() };
                    let _tree: CascadingMerkleTree<PoseidonHash, _> =
                        CascadingMerkleTree::new_with_leaves(
                            storage,
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

fn bench_cascading_restore_dense_mmap_tree(criterion: &mut Criterion) {
    let tree_values = vec![
        create_values_for_tree(4),
        create_values_for_tree(10),
        create_values_for_tree(14),
    ];

    let mut group = criterion.benchmark_group("bench_cascading_restore_dense_mmap_tree");

    (0..3).zip(tree_values).for_each(|(id, value)| {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        let path = tempfile.path();
        let storage: MmapVec<_> = unsafe { MmapVec::create_from_path(path).unwrap() };
        {
            let tree: CascadingMerkleTree<PoseidonHash, _> = CascadingMerkleTree::new_with_leaves(
                storage,
                value.depth,
                &value.empty_value,
                &value.initial_values,
            );
            let _ = tree.root();
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("restore_dense_mmap_tree_depth_{}", value.depth)),
            &(id, value),
            |bencher: &mut criterion::Bencher, (_id, value)| {
                bencher.iter(|| {
                    let storage = unsafe { MmapVec::restore_from_path(path).unwrap() };
                    let _tree: CascadingMerkleTree<PoseidonHash, _> =
                        CascadingMerkleTree::restore(storage, value.depth, &value.empty_value)
                            .unwrap();
                    let _root = _tree.root();
                });
            },
        );
    });
    group.finish();
}

#[allow(unused)]
fn bench_cascading_dense_tree_reads(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let tree = CascadingMerkleTree::<PoseidonHash>::new_with_leaves(
        vec![],
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
fn bench_cascading_dense_mmap_tree_reads(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);
    let file = tempfile::tempfile().unwrap();

    let storage = unsafe { MmapVec::create(file).unwrap() };
    let tree = CascadingMerkleTree::<PoseidonHash, _>::new_with_leaves(
        storage,
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
}

fn bench_cascading_dense_tree_writes(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let value = Field::from(123_456);

    criterion.bench_function("dense tree writes", |b| {
        b.iter_batched_ref(
            || {
                CascadingMerkleTree::<PoseidonHash>::new_with_leaves(
                    vec![],
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

fn bench_cascading_dense_mmap_tree_writes(criterion: &mut Criterion) {
    let tree_value = create_values_for_tree(14);

    let value = Field::from(123_456);

    criterion.bench_function("dense mmap tree writes", |b| {
        b.iter_batched_ref(
            || {
                let file = tempfile::tempfile().unwrap();
                let storage = unsafe { MmapVec::create(file).unwrap() };
                CascadingMerkleTree::<PoseidonHash, _>::new_with_leaves(
                    storage,
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

fn create_values_for_tree(depth: usize) -> TreeValues<PoseidonHash> {
    let empty_value = Field::from(0);

    let initial_values: Vec<ruint::Uint<256, 4>> = (0..(1 << depth)).map(Field::from).collect();

    TreeValues {
        depth,
        empty_value,
        initial_values,
    }
}
