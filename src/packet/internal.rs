use std::mem::size_of;
use super::{Header, Checksum};
use crate::{packet::data::{internal::{Data as InternalData, DynamicData, SizedData}, Data}, util::ceil_to_u32_boundary, SessionId, UserId};

pub const MIN_SIZE : usize = ceil_to_u32_boundary(size_of::<ExtendedHeader>()) + ceil_to_u32_boundary(size_of::<Checksum>());

#[repr(C, align(4))]
pub struct Packet<T : Data> {
	pub header : ExtendedHeader,
	pub data : T,
	pub crc : Checksum,
}
impl<T : Data> super::Packet for Packet<T> {}
impl<T : Data> super::SizedPacket for Packet<T> {}

impl<T : Data> std::ops::Deref for Packet<T> {
	type Target = T;
	fn deref(&self) -> &Self::Target { &self.data }
}
impl<T : Data> std::ops::DerefMut for Packet<T> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data }
}

pub const fn is_plausible_size_for_packet<T : DynamicData + ?Sized>(size : usize) -> bool {
	let min = size_of::<ExtendedHeader>() + T::MIN_SIZE + size_of::<Checksum>();
	let max = size_of::<ExtendedHeader>() + T::MAX_SIZE + size_of::<Checksum>();
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