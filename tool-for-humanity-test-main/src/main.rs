use sha3::{Digest, Sha3_256};

// For a perfect binary tree, the following utility functions address Exercise 2 requirements for the binary tree
// mentioned in the excerise doc.

/// Given a node index, calculate and return its depth and offset.
/// so as we go down the tree we know the num of nodes get doubled
/// basically 2 to the power n, so if we want ot calculate the depth
/// we can basically take log2 of the index to get depth of the tree
/// and for the offset as we go down the tree number of node will be doubled
/// so we gonna calculate the 2 to the power of depth and since its 0 based index tree
/// we gonna subtract 1 and then we gonna subtract this value from index to get our offset.
fn index_to_depth_offset(index: i32) -> (i32, i32) {
    let depth = (index as f64).log2().floor() as i32;
    let base: i32 = 2;
    let offset = index - (base.pow(depth as u32) - 1) as i32;
    (depth, offset)
}

/// Given a depth and offset, calculate and return the corresponding index.
/// to get the index with the values depth and offset we 1st take 2 to the power of depth
/// subtract 1 (cuz of the 0 based indexing) and then add offset to it.
fn depth_offset_to_index(depth: i32, offset: i32) -> i32 {
    let base: i32 = 2;
    (base.pow(depth as u32) - 1) as i32 + offset
}

/// Given an index, calculate and return the index of its parent.
/// to get parent index we gonna subtract 1 (cuz of the 0 based indexing) and then devide by 2.
fn parent_index(index: i32) -> Option<i32> {
    if index == 0 {
        None
    } else {
        Some((index - 1) / 2)
    }
}

/// Given an index, calculate and return the index of its left-most child.
/// since we know tree's node get doubled as we go down as we just multiply 2 to the index and add 1
/// to get the left index of the child.
fn left_child_index(index: i32) -> i32 {
    2 * index + 1
}

// ----------------- Merkle Tree -----------------

// MerkleTree Struct
#[derive(Debug)]
struct MerkleTree {
    root: Option<Box<Node>>,
    depth: usize,
}

// Node struct, added index of convenience
#[derive(Debug)]
struct Node {
    hash: String,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
    index: i32,
}

// Specifically using in proof
#[derive(Debug)]
enum Direction {
    Left,
    Right,
}

impl MerkleTree {
    // Create new MerkleTree
    fn new(depth: usize, initial_leaf: &str) -> Self {
        let mut tree = MerkleTree { root: None, depth };

        tree.root = Some(Box::new(Node::new_leaf(initial_leaf, depth, 0)));
        tree
    }

    // Get the hash_value of the root node
    fn root(&self) -> Option<String> {
        if let Some(tree_root) = &self.root {
            Some(tree_root.hash.clone())
        } else {
            None
        }
    }

    // Set the new hash_value of a leaf at a specific index and recalculate hashes up the tree
    pub fn set(&mut self, index: i32, new_value: &str) {
        if let Some(ref mut root) = self.root {
            // Update leaf and recalculate hashes up to the root
            root.set(index, &new_value);
        }
    }

    // Generates the proof for a given leaf index.
    pub fn proof(&self, index: i32) -> Vec<(String, Direction)> {
        let mut proof: Vec<(String, Direction)> = Vec::new();
        if let Some(ref root) = self.root {
            root.generate_proof(index, &mut proof);
        }

        proof
    }
}

impl Node {
    // Create new leaf/intermidiate/child node
    fn new_leaf(initial_hash: &str, depth: usize, index: i32) -> Self {
        if depth == 0 {
            return Node {
                hash: initial_hash.to_string(),
                left: None,
                right: None,
                index,
            };
        }

        let left_child = Box::new(Node::new_leaf(initial_hash, depth - 1, index * 2 + 1));
        let right_child = Box::new(Node::new_leaf(initial_hash, depth - 1, index * 2 + 2));

        let curr_node_hash = combine_str_hashs(&left_child.hash, &right_child.hash);

        Node {
            hash: curr_node_hash,
            left: Some(left_child),
            right: Some(right_child),
            index,
        }
    }

    // if the node is root_node or tree is empty then update its hash, else
    // Set a new value for a node at a specific index, recursively recalculate hash update its parent
    fn set(&mut self, index: i32, new_hash: &str) -> bool {
        if let Some(ref mut left) = self.left {
            // Determine if the target leaf/node is in the left or right subtree
            if index == left.index {
                left.hash = new_hash.to_string();

                // Recalculate this node's hash based on its updated children
                self.hash = combine_str_hashs(&left.hash, &self.right.as_ref().unwrap().hash);
                return true;
            } else {
                let found = left.set(index, new_hash);
                if found {
                    // Recalculate this node's hash based on its updated children
                    self.hash = combine_str_hashs(&left.hash, &self.right.as_ref().unwrap().hash);
                    return true;
                }
            }
        }

        if let Some(ref mut right) = self.right {
            // Determine if the target leaf/node is in the left or right subtree
            if index == right.index {
                right.hash = new_hash.to_string();

                // Recalculate this node's hash based on its updated children
                self.hash = combine_str_hashs(&self.left.as_ref().unwrap().hash, &right.hash);
                return true;
            } else {
                let found = right.set(index, new_hash);

                if found {
                    // Recalculate this node's hash based on its updated children
                    self.hash = combine_str_hashs(&self.left.as_ref().unwrap().hash, &right.hash);
                    return true;
                }
            }
        }

        return false;
    }

    // Generate a proof for a specific leaf index.
    fn generate_proof(&self, index: i32, proof: &mut Vec<(String, Direction)>) -> bool {
        if let Some(ref left) = self.left {
            // Determine if the target leaf/node is in the left or right subtree
            if index == left.index {
                if let Some(ref right) = self.right {
                    proof.push((right.hash.clone(), Direction::Right)); // true indicates the sibling is on the right
                }
                return true;
            } else {
                let found = left.generate_proof(index, proof);

                if found {
                    if let Some(ref right) = self.right {
                        proof.push((right.hash.clone(), Direction::Right)); // true indicates the sibling is on the right
                    }
                    return true;
                }
            }
        }

        if let Some(ref right) = self.right {
            // Determine if the target leaf/node is in the left or right subtree
            if index == right.index {
                if let Some(ref left) = self.left {
                    proof.push((left.hash.clone(), Direction::Left)); // true indicates the sibling is on the right
                }
                return true;
            } else {
                let found = right.generate_proof(index, proof);

                if found {
                    if let Some(ref left) = self.left {
                        proof.push((left.hash.clone(), Direction::Left)); // true indicates the sibling is on the right
                    }
                    return true;
                }
            }
        }

        return false;
    }
}

// Verify the proof for a given leaf and its hash.
fn verify_proof(leaf_hash: &str, proof_hex: Vec<(String, Direction)>) -> String {
    let mut current_hash = leaf_hash.to_string();

    for (sibling_hash, direction) in proof_hex {
        current_hash = match direction {
            Direction::Left => combine_str_hashs(&sibling_hash, &current_hash),
            Direction::Right => combine_str_hashs(&current_hash, &sibling_hash),
        };
    }

    current_hash
}

fn sha256_to_str(hash: Vec<u8>) -> String {
    let mut str_hash_prefix_0x = "0x".to_string();
    str_hash_prefix_0x.push_str(&hex::encode(hash));
    str_hash_prefix_0x
}

fn str_to_sha256(hash: &str) -> Vec<u8> {
    let hash_sha256 = hex::decode(&hash[2..]).expect("Decoding failed");
    hash_sha256
}

fn combine_sha256_hashs(left_hash: Vec<u8>, right_hash: Vec<u8>) -> Vec<u8> {
    Sha3_256::digest(&[left_hash, right_hash].concat()).to_vec()
}

fn combine_str_hashs(left_hash: &str, right_hash: &str) -> String {
    let left_hash_sha256 = str_to_sha256(left_hash);
    let right_hash_sha256 = str_to_sha256(right_hash);

    let combined = combine_sha256_hashs(left_hash_sha256, right_hash_sha256);

    sha256_to_str(combined)
}

fn main() {
    // Usage of the utility functions
    let (depth, offset) = index_to_depth_offset(6); // taking index 6 as example
    println!("Depth: {}, Offset: {}", depth, offset);

    let index = depth_offset_to_index(depth, offset); // value of depth, offset will be used from the above variable.
    println!("Index: {}", index);

    if let Some(parent) = parent_index(index) {
        println!("Parent index: {}", parent);
    }

    let left_child = left_child_index(index);
    println!("Left child index: {}", left_child);

    // ----------------- Merkle Tree -----------------

    let initial_leaf = "0xabababababababababababababababababababababababababababababababab";
    let mut tree = MerkleTree::new(2, initial_leaf);

    if let Some(root_hash) = tree.root() {
        println!("Root hash: {:?}", root_hash);
    }

    let new_hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
    tree.set(3, new_hash);

    if let Some(new_root_hash) = tree.root() {
        println!("Recalculated Root hash: {:?}", new_root_hash);
    }

    let proof = tree.proof(6);

    println!("printing entire tree: {:?}", tree);

    println!("printing proof {:?}", proof);
    println!(
        "printing result of verify {:?}",
        verify_proof(initial_leaf, proof)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_to_depth_offset() {
        let (depth, offset) = index_to_depth_offset(6);
        assert_eq!(depth, 2);
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_depth_offset_to_index() {
        let index = depth_offset_to_index(2, 3);
        assert_eq!(index, 6);
    }

    #[test]
    fn test_parent_index() {
        assert_eq!(parent_index(3), Some(1));
        assert_eq!(parent_index(0), None);
    }

    #[test]
    fn test_left_child_index() {
        assert_eq!(left_child_index(1), 3);
    }

    #[test]
    fn test_merkle_tree_creation_and_root() {
        let initial_leaf = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let tree = MerkleTree::new(2, initial_leaf);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_update_and_root_change() {
        let initial_leaf = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let mut tree = MerkleTree::new(2, initial_leaf);
        let initial_root = tree.root().unwrap();

        let new_hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
        tree.set(1, new_hash);
        let new_root = tree.root().unwrap();

        assert_ne!(initial_root, new_root);
    }

    #[test]
    fn test_proof_verification() {
        let initial_leaf = "0xabababababababababababababababababababababababababababababababab";
        let mut tree = MerkleTree::new(3, initial_leaf);

        tree.set(
            7,
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        );

        let root_hash = tree.root().unwrap();

        let proof = tree.proof(8);
        // let leaf_hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let proof_root = verify_proof(initial_leaf, proof);

        assert!(root_hash == proof_root);
    }
}
