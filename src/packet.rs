pub trait Packet {
	fn calculate_crc(&self) -> PacketChecksum {
		let _self = std::ptr::from_ref(self);
		let as_u32s : &[u32] = unsafe { std::slice::from_raw_parts(_self.cast(), _self.cast::<Header>().as_ref().unwrap_unchecked().u32_length as usize - 1) };  // skip the last entry
		
		let mut start = as_u32s.as_ptr();
		let end = unsafe { start.add(as_u32s.len()) };
		let mut accumulator : u32 = 0;
		while start < end {
			accumulator = accumulator.wrapping_add(unsafe { start.read() });
			start = unsafe { start.add(1) };
		}
		PacketChecksum(accumulator)
	}
}

pub trait SizedPacket {
	const SIZE : usize;
}



#[repr(C, align(2))]
pub struct GenericPacket<T> {
	pub header : Header,
	pub data : T,
	pub crc : PacketChecksum,
}
impl<T> Packet for GenericPacket<T> {}

impl<T> std::ops::Deref for GenericPacket<T> {
	type Target = T;
	fn deref(&self) -> &Self::Target { &self.data }
}
impl<T> std::ops::DerefMut for GenericPacket<T> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data }
}

pub const MIN_PACKET_SIZE : usize = (std::mem::size_of::<Header>() + 3) / 4 + std::mem::size_of::<PacketChecksum>();

pub fn calculate_crc_from_raw_packet(packet_as_u32s : *const u32, length_in_u32s : usize) -> PacketChecksum {
	let mut start = packet_as_u32s;
	let end = unsafe { start.add(length_in_u32s - 1) }; // skip the last entry
	let mut accumulator : u32 = 0;
	while start < end {
		accumulator = accumulator.wrapping_add(unsafe { start.read() });
		start = unsafe { start.add(1) };
	}
	PacketChecksum(accumulator)
}


#[repr(C, packed)]
#[derive(Debug)]
pub struct Header {
	pub target_addon : AddonSignature,
	pub u32_length : u16,
}


#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddonSignature(i32);
impl AddonSignature {
	pub const INTERNAL_PACKET : AddonSignature = AddonSignature(0);
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketChecksum(pub u32);


// the addon id for internal packets is 0, these cannot be sent by normal addons.
pub mod internal {
	use std::mem::size_of;

	use super::{Header, PacketChecksum};
	use crate::{packet_data::{internal::{Data as InternalData, DynamicData, SizedData}, Data}, SessionId, UserId};

	pub const MIN_PACKET_SIZE : usize = size_of::<ExtendedHeader>() + size_of::<PacketChecksum>();

	#[repr(C, align(4))]
	pub struct Packet<T : Data> {
		pub header : ExtendedHeader,
		pub data : T,
		pub crc : PacketChecksum,
	}
	impl<T : Data> super::Packet for Packet<T> {}

	impl<T : Data> std::ops::Deref for Packet<T> {
		type Target = T;
		fn deref(&self) -> &Self::Target { &self.data }
	}
	impl<T : Data> std::ops::DerefMut for Packet<T> {
		fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data }
	}

	pub const fn is_plausible_size_for_packet<T : DynamicData + ?Sized>(size : usize) -> bool {
		let min = size_of::<ExtendedHeader>() + T::MIN_SIZE + size_of::<PacketChecksum>();
		let max = size_of::<ExtendedHeader>() + T::MAX_SIZE + size_of::<PacketChecksum>();
		min <= size && size <= max
	}

	#[repr(C, align(4))]
	#[derive(Debug)]
	pub struct ExtendedHeader {
		pub basic : Header,
		pub type_ : PacketType,
	}

	#[repr(u16)]
	#[derive(Debug, Clone, Copy)]
	pub enum PacketType {
		_UNKNOWN       = 0,
		JoinSession    = 1,
		SessionCreated = 2,
		LeaveSession   = 4,
	}

	pub type JoinSession = Packet<JoinSessionData>;
	#[repr(C)]
	pub struct JoinSessionData {
		pub my_user_id : UserId,
		pub session_id : SessionId,
	}
	impl Data for JoinSessionData {}
	impl InternalData for JoinSessionData { const TYPE : PacketType = PacketType::JoinSession; }
	impl SizedData for JoinSessionData { }

	pub type LeaveSession = Packet<LeaveSessionData>;
	#[repr(C)]
	pub struct LeaveSessionData {
		pub my_user_id : UserId,
	}
	impl Data for LeaveSessionData {}
	impl InternalData for LeaveSessionData { const TYPE : PacketType = PacketType::LeaveSession; }
	impl SizedData for LeaveSessionData { }

	#[repr(C)]
	pub struct SessionCreatedData {
		pub session_id : SessionId,
	}
	impl Data for SessionCreatedData {}
	impl InternalData for SessionCreatedData { const TYPE : PacketType = PacketType::SessionCreated; }
	impl SizedData for SessionCreatedData {}

}

