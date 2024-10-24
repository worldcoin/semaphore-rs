use color_eyre::Result;
use hasher::Hasher;
use itertools::Itertools;
use poseidon::Poseidon;
use rand::Rng;
use ruint::aliases::U256;
use std::{env, process::Stdio};
use storage::MmapVec;
use trees::cascading::CascadingMerkleTree;
use trees::lazy::LazyMerkleTree;

static FILE_PATH: &str = "target/debug/examples/abort.mmap";
static BIN_PATH: &str = "target/debug/examples/abort";
static ITERATIONS: usize = 20;
static INITIAL_LEAVES: usize = 10;

/// A test that interupts writes to the mmap merkle trees
/// to simulate a crash, and to check if restoring the tree
/// is successful
///
/// Run this binary with no arguments to run the tests
/// `RUSTFLAGS="-C panic=abort" cargo run --example abort`
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // initialize
    if args.len() == 1 {
        run()?;
    } else if args.len() == 2 && args[1] == "cascade_restore" {
        cascade_restore()?;
    } else if args.len() == 2 && args[1] == "cascade_init" {
        cascade_init()?;
    } else if args.len() == 2 && args[1] == "lazy_restore" {
        lazy_restore()?;
    } else if args.len() == 2 && args[1] == "lazy_init" {
        lazy_init()?;
    } else {
        panic!("invalid arguments");
    }

    Ok(())
}

fn run() -> Result<()> {
    let cascade_failures = run_test("cascade")?;
    let lazy_failures = run_test("lazy")?;

    println!("\nAll Tests Complete!");
    println!("Cascade failure rate: {cascade_failures}/{ITERATIONS}");
    println!("Lazy failure rate: {lazy_failures}/{ITERATIONS}");

    Ok(())
}

fn run_test(prefix: &str) -> Result<u32> {
    let mut failures = 0u32;
    println!("Running {prefix} test");
    for i in 0..ITERATIONS {
        println!("\n{prefix} run #{i}");
        let output = std::process::Command::new(BIN_PATH)
            .arg(format!("{prefix}_init"))
            .stdout(Stdio::piped())
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        print!("{}", stdout);
        let stderr = String::from_utf8(output.stderr)?;
        print!("{}", stderr);

        let output = std::process::Command::new(BIN_PATH)
            .arg(format!("{prefix}_restore"))
            .stdout(Stdio::piped())
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        print!("{}", stdout);
        let stderr = String::from_utf8(output.stderr)?;
        if !stderr.is_empty() {
            print!("{}", stderr);
            failures += 1;
        }
    }

    println!("\n{prefix} test complete");
    Ok(failures)
}

fn cascade_init() -> Result<()> {
    let mmap_vec: MmapVec<<Poseidon as Hasher>::Hash> =
        unsafe { MmapVec::create_from_path(FILE_PATH)? };

    let leaves = vec![Default::default(); INITIAL_LEAVES];

    let mut tree = CascadingMerkleTree::<Poseidon, _>::new_with_leaves(
        mmap_vec,
        30,
        &Default::default(),
        &leaves,
    );

    let _handle = tokio::spawn(async move {
        for _ in 0..15 {
            tree.push(U256::from(2)).unwrap();
        }
    });

    let mut rng = rand::thread_rng();
    let millis: u64 = rng.gen_range(0..50);
    std::thread::sleep(std::time::Duration::from_millis(millis));

    panic!("");
}

fn cascade_restore() -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(FILE_PATH)?;

    let mmap_vec: MmapVec<<Poseidon as Hasher>::Hash> = unsafe { MmapVec::restore(file)? };
    let tree = CascadingMerkleTree::<Poseidon, _>::restore(mmap_vec, 30, &Default::default())?;
    println!("tree length: {}", tree.num_leaves());
    tree.validate()?;

    Ok(())
}

fn lazy_init() -> Result<()> {
    let leaves = vec![Default::default(); INITIAL_LEAVES];

    let mut tree = LazyMerkleTree::<Poseidon>::new_mmapped_with_dense_prefix_with_init_values(
        30,
        13,
        &Default::default(),
        &leaves,
        FILE_PATH,
    )?;

    let _handle = std::thread::spawn(move || {
        for i in INITIAL_LEAVES..(INITIAL_LEAVES + 15) {
            tree = tree.update_with_mutation(i, &U256::from(2));
        }
    });

    let mut rng = rand::thread_rng();
    let millis: u64 = rng.gen_range(0..50);
    std::thread::sleep(std::time::Duration::from_millis(millis));

    panic!("");
}

fn lazy_restore() -> Result<()> {
    let tree = LazyMerkleTree::<Poseidon>::attempt_dense_mmap_restore(
        30,
        13,
        &Default::default(),
        FILE_PATH,
    )?;

    let leaves = tree.leaves().take(20).collect_vec();
    println!("tree length: {leaves:?}");
    Ok(())
}
