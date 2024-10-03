use std::fmt::Debug;

use hasher::Hasher;
use serde::{Deserialize, Serialize};

/// Merkle proof path, bottom to top.
pub struct Proof<H>(pub Vec<Branch<H::Hash>>)
where
    H: Hasher;

impl<H> PartialEq for Proof<H>
where
    H: Hasher,
    H::Hash: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<H> Clone for Proof<H>
where
    H: Hasher,
    <H as Hasher>::Hash: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<H> Eq for Proof<H>
where
    H: Hasher,
    H::Hash: Eq,
{
}

/// Element of a Merkle proof
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Branch<T> {
    /// Left branch taken, value is the right sibling hash.
    Left(T),

    /// Right branch taken, value is the left sibling hash.
    Right(T),
}

impl<H> Serialize for Proof<H>
where
    H: Hasher,
    H::Hash: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, H> Deserialize<'de> for Proof<H>
where
    H: Hasher,
    H::Hash: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let branches = Vec::deserialize(deserializer)?;
        Ok(Proof(branches))
    }
}

impl<T> Branch<T> {
    /// Get the inner value
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Self::Left(sibling) => sibling,
            Self::Right(sibling) => sibling,
        }
    }
}

impl<T: Debug> Debug for Branch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Left(arg0) => f.debug_tuple("Left").field(arg0).finish(),
            Self::Right(arg0) => f.debug_tuple("Right").field(arg0).finish(),
        }
    }
}

impl<H> Debug for Proof<H>
where
    H: Hasher,
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}
