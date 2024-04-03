use std::{
    env,
    process::{abort, Stdio},
};

use color_eyre::Result;
use semaphore::{
    cascading_merkle_tree::{CascadingMerkleTree, MmapTreeStorageConfig, MmapVec},
    merkle_tree::Hasher,
};

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

    let config = unsafe { MmapTreeStorageConfig::new("target/tmp/abort.mmap".into()) };

    // initialize
    if args.len() == 1 {
        println!("initializing\n");
        let leaves = vec![1; 1_000_000];
        let _ = CascadingMerkleTree::<TestHasher, MmapVec<TestHasher>>::new_with_leaves(
            config, 30, &1, &leaves,
        );
        for i in 0..2 {
            println!("running interation {}", i);
            let output = std::process::Command::new("target/debug/examples/abort_test")
                .arg("child")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()?;
            let string = String::from_utf8(output.stdout)?;
            println!("{}", string);
        }
        return Ok(());
    }

    println!("restoring");
    let mut tree = CascadingMerkleTree::<TestHasher, MmapVec<TestHasher>>::restore(config, 30, &1)?;

    println!("validating");
    match tree.validate() {
        Ok(()) => println!("tree is valid"),
        Err(e) => {
            println!("tree is invalid: {:?}", e);
            return Ok(());
        }
    }

    println!("spawning");
    std::thread::spawn(move || loop {
        println!("pushing");
        tree.push(2).unwrap();
    });
    std::thread::sleep(std::time::Duration::from_millis(100));

    println!("aboring");
    abort();
}
