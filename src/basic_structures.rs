use crate::util::InlineArray;
use std::{fmt::Display, net::SocketAddr};


#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddonSignature(i32);
impl AddonSignature {
	pub const INTERNAL_PACKET : AddonSignature = AddonSignature(0);
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId([u32; 4]);
impl Display for UserId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{:08x}{:08x}{:08x}{:08x}", self.0[0], self.0[1], self.0[2], self.0[3]))
	}
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u32; 4]);
impl Display for SessionId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{:08x}{:08x}{:08x}{:08x}", self.0[0], self.0[1], self.0[2], self.0[3]))
	}
}


#[derive(Debug, Default)]
pub struct Session {
	pub members : InlineArray<SessionMemberData, 50>,
}

#[derive(Debug)]
pub struct SessionMemberData {
	pub user_id : UserId,
	pub address : SocketAddr,
}
