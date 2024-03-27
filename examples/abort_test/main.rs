use std::{
    env,
    io::Read,
    process::{abort, Stdio},
};

use semaphore::dynamic_merkle_tree::{MmapTreeStorageConfig, MmapVec};

use semaphore::{dynamic_merkle_tree::DynamicMerkleTree, merkle_tree::Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestHasher;
impl Hasher for TestHasher {
    type Hash = usize;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        left + right
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = MmapTreeStorageConfig {
        file_path: "target/tmp/abort.mmap".into(),
    };

    // initialize
    if args.len() == 1 {
        println!("initializing");
        let leaves = vec![1; 1_000_000];
        let _ = DynamicMerkleTree::<TestHasher, MmapVec<TestHasher>>::new_with_leaves(
            config, 30, &1, &leaves,
        );
        for i in 0..1 {
            println!("running interation {}", i);
            let output = std::process::Command::new("target/debug/examples/abort_test")
                .arg("child")
                .stdout(Stdio::piped())
                .output()
                .unwrap();
            let string = String::from_utf8(output.stdout).unwrap();
            println!("{}", string);
        }
        return;
    }

    println!("restoring");
    let mut tree =
        DynamicMerkleTree::<TestHasher, MmapVec<TestHasher>>::restore(config, 30, &1).unwrap();

    std::thread::spawn(move || loop {
        println!("here");
        tree.push(1).unwrap();
    });
    std::thread::sleep(std::time::Duration::from_millis(10000));
    abort();
}
