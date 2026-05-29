mod mmap_vec;

use bytemuck::Pod;

pub use mmap_vec::MmapVec;

impl<T: Send + Sync + Pod> super::GenericStorage<T> for MmapVec<T> {
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
