use crate::util::InlineArray;
use std::{fmt::Display, net::SocketAddr};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId([u32; 4]);
impl Display for UserId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Debug::fmt(&self.0, f) }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u32; 4]);
impl Display for SessionId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Debug::fmt(&self.0, f) }
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
