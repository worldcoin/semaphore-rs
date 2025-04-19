use std::fs::{File, OpenOptions};
use std::ops::{Deref, DerefMut};
use std::path::Path;

use bytemuck::Pod;
use color_eyre::eyre::{ensure, Context};

const META_SIZE: usize = std::mem::size_of::<usize>();

pub struct MmapVec<T>(Vec<T>);

// Public API
impl<T: Pod + Default> MmapVec<T> {
    pub unsafe fn create_from_path(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
        unimplemented!()
    }

    pub unsafe fn create(file: File) -> color_eyre::Result<Self> {
        unimplemented!()
    }

    pub unsafe fn restore_from_path(file_path: impl AsRef<Path>) -> color_eyre::Result<Self> {
        unimplemented!()
    }

    pub unsafe fn restore(file: File) -> color_eyre::Result<Self> {
        unimplemented!()
    }

    pub fn clear(&mut self) {
        unimplemented!()
    }

    pub fn push(&mut self, v: T) {
        unimplemented!()
    }

    pub fn extend_from_slice(&mut self, slice: &[T]) {
        unimplemented!()
    }

    pub fn resize(&mut self, new_capacity: usize) {
        unimplemented!()
    }

    fn set_storage_len(&mut self, new_len: usize) {
        unimplemented!()
    }

    fn storage_len(&self) -> usize {
        unimplemented!()
    }

    fn capacity_slice(&self) -> &[T] {
        unimplemented!()
    }

    fn capacity_slice_mut(&mut self) -> &mut [T] {
        unimplemented!()
    }
}

impl<T> Extend<T> for MmapVec<T>
where
    T: Pod + Default,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        unimplemented!()
    }
}

impl<T> Deref for MmapVec<T>
where
    T: Pod + Default,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unimplemented!()
    }
}

impl<T> DerefMut for MmapVec<T>
where
    T: Pod + Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unimplemented!()
    }
}

impl<T> std::fmt::Debug for MmapVec<T>
where
    T: Pod + Default + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}
