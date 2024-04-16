use std::{
    fs::{File, OpenOptions},
    ops::{Deref, DerefMut},
    path::Path,
};

use bytemuck::Pod;
use color_eyre::eyre::bail;
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
    /// # Safety
    /// Same requirements as `new` method
    pub unsafe fn open_create(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
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

        Self::create(file)
    }

    /// # Safety
    /// Same requirements as `new` method
    pub unsafe fn create(file: File) -> color_eyre::Result<Self> {
        let initial_byte_len = META_SIZE;

        file.set_len(initial_byte_len as u64)
            .expect("Failed to resize underlying file");

        let mut s = Self::new(file)?;

        s.set_storage_len(0);

        Ok(s)
    }

    /// # Safety
    /// Same requirements as `new` method
    pub unsafe fn restore(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
        let file = match OpenOptions::new().read(true).write(true).open(file_path) {
            Ok(file) => file,
            Err(_e) => bail!("File doesn't exist"),
        };

        Self::new(file)
    }

    /// # Safety
    /// This method requires that the safety requirements of [`mmap_rs::MmapOptions::with_file`](https://docs.rs/mmap-rs/0.6.1/mmap_rs/struct.MmapOptions.html#method.with_file) are upheld
    ///
    /// Notably this means that there can exist no other mutable mappings to the
    /// same file in this process or any other
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

        let mmap = MmapOptions::new(byte_len)
            .expect("cannot create memory map")
            .with_file(&file, 0)
            .with_flags(MmapFlags::SHARED)
            .map_mut()
            .expect("cannot build memory map");

        let s = Self {
            mmap: Some(mmap),
            file,
            capacity,
            phantom: std::marker::PhantomData,
        };

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
        let _storage: MmapVec<()> = unsafe { MmapVec::create(f.try_clone().unwrap()).unwrap() };
    }
}
