use std::{env, process::Stdio};

use color_eyre::Result;

use hasher::Hasher;
use storage::MmapVec;
use trees::cascading::CascadingMerkleTree;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestHasher;
impl Hasher for TestHasher {
    type Hash = usize;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        left + right
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let tempfile = tempfile::tempfile()?;
    let mmap_vec: MmapVec<<TestHasher as Hasher>::Hash> =
        unsafe { MmapVec::restore(tempfile.try_clone()?)? };

    // initialize
    if args.len() == 1 {
        println!("initializing\n");
        let leaves = vec![1; 1_000_000];
        let _ = CascadingMerkleTree::<TestHasher, _>::new_with_leaves(mmap_vec, 30, &1, &leaves);
        for i in 0..100 {
            println!("running interation {}", i);
            let output = std::process::Command::new("target/debug/examples/abort_test")
                .arg("child")
                .stdout(Stdio::piped())
                .output()?;
            let stdout = String::from_utf8(output.stdout)?;
            println!("stdout:\n{}", stdout);
            let stderr = String::from_utf8(output.stderr)?;
            println!("stderr:\n{}", stderr);
        }
        return Ok(());
    }

    drop(mmap_vec);

    let mmap_vec: MmapVec<<TestHasher as Hasher>::Hash> = unsafe { MmapVec::restore(tempfile)? };

    println!("restoring");
    let mut tree = CascadingMerkleTree::<TestHasher, _>::restore(mmap_vec, 30, &1)?;
    tree.push(2).unwrap();

    println!("tree length: {}", tree.num_leaves());

    println!("validating");
    tree.validate()?;

    println!("spawning");
    std::thread::spawn(move || loop {
        tree.push(2).unwrap();
    });
    std::thread::sleep(std::time::Duration::from_millis(1));

    println!("aborting");
    panic!();
    // abort();
}
