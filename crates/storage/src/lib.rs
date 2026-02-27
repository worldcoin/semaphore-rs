use std::ops::{Deref, DerefMut};

#[cfg(not(target_arch = "wasm32"))]
mod mmap_vec;

#[cfg(not(target_arch = "wasm32"))]
use bytemuck::Pod;
#[cfg(not(target_arch = "wasm32"))]
pub use mmap_vec::MmapVec;

pub trait GenericStorage<T>:
    Deref<Target = [T]> + DerefMut<Target = [T]> + Extend<T> + Send + Sync
{
    fn push(&mut self, value: T);

    fn extend_from_slice(&mut self, slice: &[T]);

    fn clear(&mut self);
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
}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + Pod> GenericStorage<T> for MmapVec<T> {
    fn push(&mut self, value: T) {
        self.push(value);
    }

    fn extend_from_slice(&mut self, slice: &[T]) {
        self.extend_from_slice(slice);
    }

    fn clear(&mut self) {
        self.clear();
    }
}
