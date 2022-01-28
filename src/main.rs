mod proof;
mod identity;

fn main() {
    // proof::Proof_signal().unwrap();
    let id = identity::Identity::new(b"hello");
    dbg!(&id);
    dbg!(id.identity_commitment());
}
