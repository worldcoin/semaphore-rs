// NOTE: Append the lines below to ios/Classes/GreeterPlugin.h

typedef struct Identity Identity;

/**
 * Merkle tree with all leaf and intermediate hashes stored
 */
typedef struct MerkleTree_PoseidonHash MerkleTree_PoseidonHash;

/**
 * Merkle proof path, bottom to top.
 */
typedef struct Proof_Bn_Parameters Proof_Bn_Parameters;

/**
 * Merkle proof path, bottom to top.
 */
typedef struct Proof_PoseidonHash Proof_PoseidonHash;

typedef struct MerkleTree_PoseidonHash PoseidonTree;

/**
 * Creates a new idenity and returns the object
 */
struct Identity *new_identity(const char *seed);

/**
 * Generates the identity commitment based on seed for identity
 */
char *generate_identity_commitment(struct Identity *identity);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
char *generate_nullifier_hash(struct Identity *identity, const char *external_nullifier);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
PoseidonTree *create_poseidon_tree(int depth);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
void insert_leaf(PoseidonTree *tree, struct Identity *identity);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
char *get_root(PoseidonTree *tree);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
struct Proof_PoseidonHash *get_merkle_proof(PoseidonTree *tree, int leaf_idx);

/**
 * Generates nullifier hash based on identity and external nullifier
 */
struct Proof_Bn_Parameters *generate_proof(struct Identity *identity,
                                           const char *external_nullifier,
                                           const char *signal,
                                           struct Proof_PoseidonHash *merkle_proof,
                                           const char *zkey_path,
                                           const char *wasm_path);

int verify_proof(const char *root,
                 const char *external_nullifier,
                 const char *signal,
                 const char *nullifier,
                 struct Proof_Bn_Parameters *proof,
                 const char *zkey_path,
                 const char *wasm_path);
