use std::ops::{Deref, DerefMut};


#[derive(Debug, Clone)]
pub struct InlineArray<T, const S : usize> {
	pub used : usize,
	pub data : [T; S],
}

impl<T, const S : usize> Default for InlineArray<T, S> {
	fn default() -> Self {
		Self { used: 0, data: unsafe{ std::mem::MaybeUninit::uninit().assume_init() } }
	}
}

impl<T, const S : usize> InlineArray<T, S> {
	pub fn new() -> Self { Self::default() }

	pub fn push(&mut self, element : T) {
		self.data[self.used] = element;
		self.used += 1;
	}

	pub fn swap_remove(&mut self, index : usize) {
		if self.used > 1 && index != self.used - 1 {
			let ptr = self.as_mut_ptr();
			unsafe { std::ptr::copy(ptr.add(self.used - 1), ptr.add(index), 1) }
		}
		self.used -= 1;
	}
}

impl<T, const S : usize> Deref for InlineArray<T, S> {
	type Target = [T];
	fn deref(&self) -> &Self::Target { &self.data[..self.used] }
}

impl<T, const S : usize> DerefMut for InlineArray<T, S> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data[..self.used] }
}