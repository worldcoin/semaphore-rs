use std::ops::{Deref, DerefMut};

mod mmap_vec;

use bytemuck::Pod;
pub use mmap_vec::MmapVec;

pub trait GenericStorage<T>: Deref<Target = [T]> + DerefMut<Target = [T]> + Send + Sync {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_storage() {
        // Box to ensure we're using the trait methods
        let mut storage: Box<dyn GenericStorage<u32>> = Box::<Vec<u32>>::default();

        storage.push(1);
        storage.push(2);
        storage.push(3);

        assert_eq!(storage.len(), 3);

        assert_eq!(storage[0], 1);
        assert_eq!(storage[1], 2);
        assert_eq!(storage[2], 3);
    }
}
