use std::{
    fs::{File, OpenOptions},
    ops::{Deref, DerefMut},
    path::Path,
};

use bytemuck::Pod;
use color_eyre::eyre::{ensure, Context};
use mmap_rs::{MmapFlags, MmapMut, MmapOptions};

const META_SIZE: usize = std::mem::size_of::<usize>();

pub struct MmapVec<T> {
    // This must be Option to properly uphold aliasing access safety guarantees
    // Look at the `resize` method for more details
    mmap:     Option<MmapMut>,
    file:     File,
    capacity: usize,
    phantom:  std::marker::PhantomData<T>,
}

// Public API
impl<T: Pod> MmapVec<T> {
    /// Creates a new MmapVec from a file path.
    /// Any existing data in the file will be truncated.
    ///
    /// # Safety
    /// Same requirements as `create`
    pub unsafe fn create_from_path(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)?;

        Self::create(file)
    }

    /// Creates a new MmapVec from a file.
    /// Any existing data in the file will be truncated.
    ///
    /// # Safety
    /// This method requires that the safety requirements of [`mmap_rs::MmapOptions::with_file`](https://docs.rs/mmap-rs/0.6.1/mmap_rs/struct.MmapOptions.html#method.with_file) are upheld.
    ///
    /// Notably this means that there can exist no other mutable mappings to the
    /// same file in this process or any other
    pub unsafe fn create(file: File) -> color_eyre::Result<Self> {
        file.set_len(0)?;
        file.set_len(META_SIZE as u64)
            .context("Failed to resize underlying file")?;

        let mut s = Self::restore(file)?;

        s.set_storage_len(0);

        Ok(s)
    }

    /// Restores an MmapVec from a file path.
    ///
    /// # Safety
    /// Same requirements as `restore`
    pub unsafe fn restore_from_path(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(file_path)?;

        Self::restore(file)
    }

    /// Restores an MmapVec from a file. This should not panic.
    ///
    /// # Safety
    /// This method requires that the safety requirements of [`mmap_rs::MmapOptions::with_file`](https://docs.rs/mmap-rs/0.6.1/mmap_rs/struct.MmapOptions.html#method.with_file) are upheld.
    ///
    /// Additioanally the caller must ensure that the file contains valid data.
    ///
    /// Notably this means that there can exist no other mutable mappings to the
    /// same file in this process or any other
    pub unsafe fn restore(file: File) -> color_eyre::Result<Self> {
        assert!(std::mem::size_of::<T>() != 0);

        let mut byte_len = file.metadata()?.len() as usize;

        if byte_len < META_SIZE {
            file.set_len(0)?;

            file.set_len(META_SIZE as u64)?;

            byte_len = META_SIZE;
        }

        let data_len = byte_len.saturating_sub(META_SIZE);
        ensure!(data_len % std::mem::size_of::<T>() == 0);

        let capacity = data_len / std::mem::size_of::<T>();

        let mmap = MmapOptions::new(byte_len)?
            .with_file(&file, 0)
            .with_flags(MmapFlags::SHARED)
            .map_mut()?;

        let s = Self {
            mmap: Some(mmap),
            file,
            capacity,
            phantom: std::marker::PhantomData,
        };

        let len = s.storage_len();
        ensure!(len <= capacity);

        Ok(s)
    }

    pub fn clear(&mut self) {
        self.set_storage_len(0);
    }

    pub fn push(&mut self, v: T) {
        let len = self.storage_len();
        let capacity = self.capacity;
        let new_len = len + 1;

        if new_len > capacity {
            self.resize(new_len.next_power_of_two());
        }

        self.capacity_slice_mut()[len] = v;
        self.set_storage_len(new_len);
    }

    pub fn extend_from_slice(&mut self, slice: &[T]) {
        let len = self.storage_len();
        let capacity = self.capacity;
        let new_len = len + slice.len();

        if new_len >= capacity {
            self.resize(new_len.next_power_of_two());
        }

        self.capacity_slice_mut()[len..(new_len)].copy_from_slice(slice);
        self.set_storage_len(new_len);
    }

    pub fn resize(&mut self, new_capacity: usize) {
        let new_file_len = META_SIZE + new_capacity * std::mem::size_of::<T>();

        self.file
            .set_len(new_file_len as u64)
            .expect("Failed to resize underlying file");

        // # Safety
        // MmapMut requires that no other instance of MmapMut exists that has access
        // to the same file.
        //
        // In order to uphold that we must first drop the current MmapMut instance.
        //
        // MmapMut also requires that the caller must ensure that no other process
        // has access to the same file at the same time.
        // This requirement is upheld at the instantiation of MmapVec and must hold true
        // for its entire lifetime. Therefore it must be upheld here as well.
        unsafe {
            self.mmap = None;
            self.mmap = Some(
                MmapOptions::new(new_file_len)
                    .expect("cannot create memory map")
                    .with_file(&self.file, 0)
                    .with_flags(MmapFlags::SHARED)
                    .map_mut()
                    .expect("cannot build memory map"),
            );
        }

        self.capacity = new_capacity;
    }

    fn set_storage_len(&mut self, new_len: usize) {
        let slice: &mut [usize] =
            bytemuck::cast_slice_mut(&mut self.mmap.as_mut().unwrap()[..META_SIZE]);
        slice[0] = new_len;
    }

    fn storage_len(&self) -> usize {
        bytemuck::cast_slice(&self.mmap.as_ref().unwrap()[..META_SIZE])[0]
    }

    fn capacity_slice(&self) -> &[T] {
        bytemuck::cast_slice(&self.mmap.as_ref().unwrap().as_slice()[META_SIZE..])
    }

    fn capacity_slice_mut(&mut self) -> &mut [T] {
        bytemuck::cast_slice_mut(&mut self.mmap.as_mut().unwrap().as_mut_slice()[META_SIZE..])
    }
}

impl<T> Extend<T> for MmapVec<T>
where
    T: Pod,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for item in iter {
            self.push(item);
        }
    }
}

impl<T> Deref for MmapVec<T>
where
    T: Pod,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.capacity_slice()[..self.storage_len()]
    }
}

impl<T> DerefMut for MmapVec<T>
where
    T: Pod,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let len = self.storage_len();
        &mut self.capacity_slice_mut()[..len]
    }
}

impl<T> std::fmt::Debug for MmapVec<T>
where
    T: Pod + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let contents: &[T] = self.deref();

        f.debug_struct("MmapVec")
            .field("contents", &contents)
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[allow(clippy::manual_bits)]
    fn test_capacity_push() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let file_path = f.path().to_owned();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len(),
            META_SIZE as u64
        );

        storage.push(0);
        assert_eq!(storage.capacity, 1);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() + META_SIZE
        );

        storage.push(0);
        assert_eq!(storage.capacity, 2);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 2 + META_SIZE
        );

        storage.push(0);
        assert_eq!(storage.capacity, 4);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 4 + META_SIZE
        );

        storage.push(0);
        assert_eq!(storage.capacity, 4);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 4 + META_SIZE
        );

        storage.push(0);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );
    }

    #[test]
    #[allow(clippy::manual_bits)]
    fn test_capacity_extend() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let file_path = f.path().to_owned();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len(),
            META_SIZE as u64
        );

        storage.extend_from_slice(&[0, 0]);
        assert_eq!(storage.capacity, 2);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 2 + META_SIZE
        );

        storage.extend_from_slice(&[0, 0, 0]);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );

        storage.extend_from_slice(&[0]);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );
    }

    #[test]
    #[allow(clippy::manual_bits)]
    fn test_capacity_create() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let file_path = f.path().to_owned();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            META_SIZE
        );

        storage.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );

        let storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            META_SIZE
        );
    }

    #[test]
    #[allow(clippy::manual_bits)]
    fn test_capacity_create_from_path() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let file_path = f.path().to_owned();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            META_SIZE
        );

        storage.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );

        let storage: MmapVec<u32> = unsafe { MmapVec::create_from_path(&file_path).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            META_SIZE
        );
    }

    #[test]
    #[allow(clippy::manual_bits)]
    fn test_capacity_restore() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let file_path = f.path().to_owned();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            META_SIZE
        );

        storage.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );

        let storage: MmapVec<u32> = unsafe { MmapVec::restore(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );
    }

    #[test]
    #[allow(clippy::manual_bits)]
    fn test_capacity_restore_from_path() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let file_path = f.path().to_owned();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.reopen().unwrap()).unwrap() };
        assert_eq!(storage.capacity, 0);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            META_SIZE
        );

        storage.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );

        let storage: MmapVec<u32> = unsafe { MmapVec::restore_from_path(&file_path).unwrap() };
        assert_eq!(storage.capacity, 8);
        assert_eq!(
            std::fs::metadata(&file_path).unwrap().len() as usize,
            size_of::<u32>() * 8 + META_SIZE
        );
    }

    #[test]
    fn test_mmap_vec() {
        let f = tempfile::tempfile().unwrap();

        let mut storage: MmapVec<u32> = unsafe { MmapVec::create(f.try_clone().unwrap()).unwrap() };

        println!("{storage:?}");
        storage.resize(2);
        println!("{storage:?}");

        storage.push(u32::MAX);
        println!("{storage:?}");
        storage.push(2);
        println!("{storage:?}");

        storage.resize(4);
        println!("{storage:?}");

        storage.push(42);
        println!("{storage:?}");
        storage.push(4);
        println!("{storage:?}");

        assert_eq!(storage.len(), 4);

        println!("{storage:?}");
        assert_eq!(storage[0], u32::MAX);
        assert_eq!(storage[1], 2);
        assert_eq!(storage[2], 42);
        assert_eq!(storage[3], 4);

        drop(storage);
        let restored: MmapVec<u32> = unsafe { MmapVec::restore(f).unwrap() };

        assert_eq!(restored.len(), 4);

        assert_eq!(restored[0], u32::MAX);
        assert_eq!(restored[1], 2);
        assert_eq!(restored[2], 42);
        assert_eq!(restored[3], 4);
    }
}
