pub mod internal;
pub mod data;

use std::mem::size_of;
use crate::util::ceil_to_u32_boundary;

pub trait Packet {
	fn calculate_crc(&self) -> Checksum {
		let _self = std::ptr::from_ref(self);
		let length = unsafe { _self.cast::<Header>().as_ref().unwrap_unchecked() }.length_in_u32s as usize - 1;
		calculate_crc_from_raw_packet(_self.cast(), length)
	}
}

pub trait SizedPacket : Packet + Sized { }



#[repr(C, align(2))]
pub struct GenericPacket<T> {
	pub header : Header,
	pub data : T,
	pub crc : Checksum,
}
impl<T> Packet for GenericPacket<T> {}
impl<T> SizedPacket for GenericPacket<T> {}

impl<T> std::ops::Deref for GenericPacket<T> {
	type Target = T;
	fn deref(&self) -> &Self::Target { &self.data }
}
impl<T> std::ops::DerefMut for GenericPacket<T> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data }
}

pub const MIN_SIZE : usize = ceil_to_u32_boundary(size_of::<Header>()) + ceil_to_u32_boundary(size_of::<Checksum>());



pub fn calculate_crc_from_raw_packet(packet_as_u32s : *const u32, length_in_u32s : usize) -> Checksum {
	let mut start = packet_as_u32s;
	let end = unsafe { start.add(length_in_u32s - 1) }; // skip the last entry
	let mut accumulator : u32 = 0;
	while start < end {
		accumulator = accumulator.wrapping_add(unsafe { start.read() });
		start = unsafe { start.add(1) };
	}
	Checksum(accumulator)
}


#[repr(C, packed)]
#[derive(Debug)]
pub struct Header {
	pub target_addon : crate::AddonSignature,
	pub length_in_u32s : u8,
	pub flags : Flags,
}


bitflags::bitflags!{
#[repr(transparent)]
	#[derive(Debug, Clone, Copy)]
	pub struct Flags : u8 {
		const None = 0;
		/// This flag indicates that this packet contains a source UserId int the first 32bit aligned 16 bytes of the data.  
		/// The id will be set by the server, just make sure to have enough space in the packet.
		/// This also increases the minimum valid packet size by those 16 bytes.
		const ContainsSource = 1 << 0;
		/// This flag indicates that this is not a broadcast packet, and the last 16 bytes in the data contain a destination UserId.  
		/// This is placed at the end of the packet, because in almost all cases a handler doesn't care about it being a broadcast or unicast packet,
		/// and so the handler implementation can be teh same for both versions if the handler doesn't care.
		/// This also increases the minimum valid packet size by 16 bytes.
		const ContainsTarget = 1 << 1;
	}
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksum(pub u32);
