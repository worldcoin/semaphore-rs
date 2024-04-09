use std::{
    fs::{File, OpenOptions},
    ops::{Deref, DerefMut},
    path::Path,
};

use bytemuck::Pod;
use color_eyre::eyre::bail;
use mmap_rs::{MmapMut, MmapOptions};

const META_SIZE: usize = std::mem::size_of::<usize>();

pub struct MmapVec<T> {
    mmap:     MmapMut,
    file:     File,
    capacity: usize,
    phantom:  std::marker::PhantomData<T>,
}

// Public API
impl<T> MmapVec<T> {
    pub unsafe fn open_create(
        file_path: impl AsRef<Path>,
        initial_capacity: usize,
    ) -> color_eyre::Result<Self> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
        {
            Ok(file) => file,
            Err(_e) => bail!("File creation failed"),
        };

        Self::create(file, initial_capacity)
    }

    pub unsafe fn create(file: File, initial_capacity: usize) -> color_eyre::Result<Self> {
        let initial_byte_len = META_SIZE + initial_capacity * std::mem::size_of::<T>();

        file.set_len(initial_byte_len as u64)
            .expect("Failed to resize underlying file");

        let mut s = Self::new(file)?;

        s.set_storage_len(0);

        Ok(s)
    }

    pub unsafe fn restore(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
        let file = match OpenOptions::new().read(true).write(true).open(file_path) {
            Ok(file) => file,
            Err(_e) => bail!("File doesn't exist"),
        };

        Self::new(file)
    }

    pub unsafe fn new(file: File) -> color_eyre::Result<Self> {
        if std::mem::size_of::<T>() == 0 {
            bail!("Zero-sized types are not supported");
        }

        let mut byte_len = file.metadata().expect("cannot get file metadata").len() as usize;

        if byte_len < META_SIZE {
            file.set_len(META_SIZE as u64)
                .expect("Failed to resize underlying file");

            byte_len = META_SIZE;
        }

        let capacity = byte_len.saturating_sub(META_SIZE) / std::mem::size_of::<T>();

        let mmap = unsafe {
            MmapOptions::new(byte_len)
                .expect("cannot create memory map")
                .with_file(file.try_clone().expect("Failed to clone file handle"), 0)
                .map_mut()
                .expect("cannot build memory map")
        };

        let s = Self {
            mmap,
            file,
            capacity,
            phantom: std::marker::PhantomData,
        };

        Ok(s)
    }

    pub fn push(&mut self, v: T) {
        let len = self.storage_len();
        let capacity = self.capacity;

        if len == capacity {
            if capacity == 0 {
                self.resize(1);
            } else {
                self.resize(capacity * 2);
            }
        }

        let offset = META_SIZE + len * std::mem::size_of::<T>();

        // TODO: Ensure that we're not breaking alignment safety requirements
        unsafe {
            let typed_ptr = self.mmap.as_mut_ptr().add(offset) as *mut T;
            std::ptr::write(typed_ptr, v);
        }

        self.set_storage_len(len + 1);
    }

    pub fn resize(&mut self, new_capacity: usize) {
        let new_file_len = META_SIZE + new_capacity * std::mem::size_of::<T>();

        self.file
            .set_len(new_file_len as u64)
            .expect("Failed to resize underlying file");

        // # Safety
        // Provided that this struct has been initialized while
        // upholding the safety guarantees during creation.
        //
        // then at this point there are no other mappings to this file.
        // Therefore, it is safe to remap it.
        self.mmap = unsafe {
            MmapOptions::new(new_file_len as usize)
                .expect("cannot create memory map")
                .with_file(
                    self.file.try_clone().expect("Failed to clone file handle"),
                    0,
                )
                .map_mut()
                .expect("cannot build memory map")
        };

        self.capacity = new_capacity;
    }

    fn set_storage_len(&mut self, new_len: usize) {
        unsafe {
            std::ptr::write(self.mmap.as_mut_ptr() as *mut usize, new_len);
        }
    }

    fn storage_len(&self) -> usize {
        unsafe { *(self.mmap.as_ptr() as *const usize) }
    }
}

impl<T> Deref for MmapVec<T>
where
    T: Pod,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        let byte_slice_len = self.storage_len() * std::mem::size_of::<T>();
        bytemuck::cast_slice(&self.mmap.as_slice()[META_SIZE..META_SIZE + byte_slice_len])
    }
}

impl<T> DerefMut for MmapVec<T>
where
    T: Pod,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let byte_slice_len = self.storage_len() * std::mem::size_of::<T>();
        bytemuck::cast_slice_mut(
            &mut self.mmap.as_mut_slice()[META_SIZE..META_SIZE + byte_slice_len],
        )
    }
}

impl<T> PartialEq for MmapVec<T> {
    fn eq(&self, other: &Self) -> bool {
        // self.mmap.as_ref() == other.mmap.as_ref()
        //     && self.file == other.file
        //     && self.phantom == other.phantom
        unimplemented!()
    }
}

impl<T> std::fmt::Debug for MmapVec<T>
where
    T: Pod + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slice: &[T] = bytemuck::cast_slice(self.mmap.as_slice());

        f.debug_struct("MmapVec").field("mmap", &slice).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmap_vec() {
        let f = tempfile::tempfile().unwrap();
        let mut storage: MmapVec<u32> =
            unsafe { MmapVec::create(f.try_clone().unwrap(), 2).unwrap() };

        storage.push(u32::MAX);
        storage.push(2);
        storage.push(42);
        storage.push(4);

        assert_eq!(storage.len(), 4);

        assert_eq!(storage[0], u32::MAX);
        assert_eq!(storage[1], 2);
        assert_eq!(storage[2], 42);
        assert_eq!(storage[3], 4);

        drop(storage);
        let restored: MmapVec<u32> = unsafe { MmapVec::new(f).unwrap() };

        assert_eq!(restored.len(), 4);

        assert_eq!(restored[0], u32::MAX);
        assert_eq!(restored[1], 2);
        assert_eq!(restored[2], 42);
        assert_eq!(restored[3], 4);
    }

    #[test]
    #[should_panic]
    fn test_mmap_vec_zst() {
        let f = tempfile::tempfile().unwrap();
        let _storage: MmapVec<()> = unsafe { MmapVec::create(f.try_clone().unwrap(), 2).unwrap() };
    }
}
