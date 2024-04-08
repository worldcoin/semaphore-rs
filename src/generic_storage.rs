use std::ops::{Deref, DerefMut};

mod mmap_vec;

pub use mmap_vec::MmapVec;

pub trait GenericStorage<T>: Deref<Target = [T]> + DerefMut<Target = [T]> + Send + Sync {
    fn push(&mut self, value: T);
}

impl<T: Send + Sync> GenericStorage<T> for Vec<T> {
    fn push(&mut self, value: T) {
        self.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_storage() {
        // Box to ensure we're using the trait methods
        let mut storage: Box<dyn GenericStorage<u32>> = Box::new(Vec::<u32>::new());

        storage.push(1);
        storage.push(2);
        storage.push(3);

        assert_eq!(storage.len(), 3);

        assert_eq!(storage[0], 1);
        assert_eq!(storage[1], 2);
        assert_eq!(storage[2], 3);
    }
}
