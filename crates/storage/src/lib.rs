use std::ops::{Deref, DerefMut};

pub trait GenericStorage<T>:
    Deref<Target = [T]> + DerefMut<Target = [T]> + Extend<T> + Send + Sync
{
    fn push(&mut self, value: T);

    fn extend_from_slice(&mut self, slice: &[T]);

    fn clear(&mut self);

    /// Shortens the storage to `len`, dropping the trailing elements.
    ///
    /// Has no effect if `len` is greater than or equal to the current length.
    /// Like [`Vec::truncate`], this does not change the allocated capacity.
    fn truncate(&mut self, len: usize);
}

impl<T: Send + Sync + Copy> GenericStorage<T> for Vec<T> {
    fn push(&mut self, value: T) {
        self.push(value);
    }

    fn extend_from_slice(&mut self, slice: &[T]) {
        Vec::extend_from_slice(self, slice);
    }

    fn clear(&mut self) {
        self.clear();
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
pub use native::MmapVec;
