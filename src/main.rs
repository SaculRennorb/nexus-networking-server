use std::{cell::UnsafeCell, collections::{hash_map::Entry::{Occupied, Vacant}, HashMap}, fmt::Display, mem::{size_of, MaybeUninit}, net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket}, ops::{Deref, DerefMut}, sync::RwLock};
mod packet;
mod packet_data;
use packet::{AddonSignature, PacketFlags};
mod util;
use util::InlineArray;


fn main() {
	_ = color_eyre::install();
	let socket = &UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1337)).expect("could not bind comm socket :: :1337");

	let mut buffer : [u8; 1024] = unsafe { #[allow(invalid_value)] std::mem::MaybeUninit::uninit().assume_init() };
	let buffer_u32 : &[u32; 1024 / 4] = unsafe{ std::mem::transmute(&buffer) }; // tricking the borrow checker

	loop {
		let (data_len, packet_source_address) = match socket.recv_from(&mut buffer) {
			Ok(l) => l,
			Err(e) => {
				eprintln!("{e:?}");
				continue;
			}
		};

		let header = unsafe { buffer.as_ptr().cast::<packet::Header>().as_ref().unwrap_unchecked() };
		let mut min_size = packet::MIN_PACKET_SIZE;
		if data_len >= min_size {
			if header.flags.contains(PacketFlags::ContainsTarget) { min_size += size_of::<UserId>(); }
			if header.flags.contains(PacketFlags::ContainsSource) { min_size += size_of::<UserId>(); }
		}

		if data_len % 4 != 0 || data_len < min_size || header.length_in_u32s as usize != data_len / 4  {
			eprintln!("Invalid length for packet"); //TODO
			continue;
		}

		let expected_crc = packet::calculate_crc_from_raw_packet(buffer_u32.as_ptr(), header.length_in_u32s as usize);
		let packet_crc = unsafe { buffer.as_mut_ptr().add(header.length_in_u32s as usize * 4 - size_of::<packet::Checksum>()).cast::<packet::Checksum>().as_mut().unwrap_unchecked() };
		if expected_crc != *packet_crc {
			eprintln!("Invalid crc for packet"); //TODO
			continue;
		}

		let addon = header.target_addon; // misaligned pointer read
		if addon == AddonSignature::INTERNAL_PACKET {
			process_internal_packet(socket, packet_source_address, &buffer[..data_len]);
		}
		else {
			// not internal, route the packet
			let Some((source_user_id, session_id)) = unsafe { ADDR_TO_SESSION.read().unwrap().get().as_ref().unwrap_unchecked() }.get(&packet_source_address) else {
				eprintln!("No session for packet with {packet_source_address:?}");
				continue
			};
			let Some(session) = unsafe { SESSIONS.read().unwrap().get().as_ref().unwrap_unchecked() }.get(session_id) else {
				eprintln!("{session_id:?} does not exist.");
				continue
			};


			#[repr(C, packed(4))]
			struct ExtendedHeader {
				header : packet::Header,
				// any required alignment padding after the header will be produced by packed(4)
				source_user : MaybeUninit<UserId>,
			}

			if header.flags.contains(PacketFlags::ContainsTarget) {
				// target id goes on the end of the data section
				let target_user = unsafe{ buffer.as_ptr().add(data_len - size_of::<packet::Checksum>() - size_of::<UserId>()).cast::<UserId>().as_ref().unwrap_unchecked() };
				match session.members.iter().find(|m| m.user_id == *target_user) {
					Some(target) => {
						// only if we find the user do we take the time to set the id
						if header.flags.contains(PacketFlags::ContainsSource) {
							let ext_header = unsafe { buffer.as_mut_ptr().cast::<ExtendedHeader>().as_mut().unwrap_unchecked() };
							ext_header.source_user.write(*source_user_id);
							// need to redo the crc when we write into the packet
							let new_crc = packet::calculate_crc_from_raw_packet(buffer_u32.as_ptr(), header.length_in_u32s as usize);
							*packet_crc = new_crc;
						}

						println!("Routing to {target_user:?} in {session_id:?} for targeted packet from {addon:?}.");
						let packet_data = &buffer[..data_len];
						socket.send_to(packet_data, target.address).unwrap();
					},
					None => {
						let addon = header.target_addon; // unaligned read
						eprintln!("Could not find {target_user:?} in {session_id:?} for targeted packet from {addon:?}.");
					}
				}
			}
			else {
				if header.flags.contains(PacketFlags::ContainsSource) {
					let ext_header = unsafe { buffer.as_mut_ptr().cast::<ExtendedHeader>().as_mut().unwrap_unchecked() };
					ext_header.source_user.write(*source_user_id);
					// need to redo the crc when we write into the packet
					let new_crc = packet::calculate_crc_from_raw_packet(buffer_u32.as_ptr(), header.length_in_u32s as usize);
					*packet_crc = new_crc;
				}

				println!("Broadcasting in {session_id:?} for packet from {addon:?}.");
				let packet_data = &buffer[..data_len];
				// broadcast packet
				for other in session.members.iter() {
					if other.address == packet_source_address { continue };

					socket.send_to(packet_data, other.address).unwrap();
				}
			}
		}
	}
}

fn process_internal_packet(socket: &UdpSocket, packet_source_address: SocketAddr, buffer: &[u8]) {
	use packet::internal::*;
	use packet_data::internal::SizedData as _;

	if buffer.len() < MIN_PACKET_SIZE {
		eprintln!("Internal packet less then min size");
		return;
	}
	let header = unsafe { buffer.as_ptr().cast::<ExtendedHeader>().as_ref().unwrap_unchecked() };
		
	match header.type_ {
		PacketType::JoinSession if buffer.len() == size_of::<JoinSession>() => {
			let packet = unsafe { buffer.as_ptr().cast::<JoinSession>().as_ref().unwrap_unchecked() };
			
			println!("{:?} wants to join {:?}", packet.my_user_id, packet.session_id);

			let mut a2s_map_wlock = ADDR_TO_SESSION.write().unwrap();
			let a2s_entry = a2s_map_wlock.get_mut().entry(packet_source_address);

			let mut u2s_map_wlock = USER_TO_SESSION.write().unwrap();
			let u2s_entry = u2s_map_wlock.get_mut().entry(packet.my_user_id);

			let mut sessions_wlock = SESSIONS.write().unwrap();
			let sessions = sessions_wlock.get_mut();

			let session_id = 'early_bail: { 
				if let Occupied(ref old_session) = a2s_entry { 
					// found old session, disconnect from that one and then join the new one
					let (_, old_id) = old_session.get();
					// test that we are not joining the same session again
					if packet.session_id == *old_id { break 'early_bail packet.session_id }

					if let Occupied(mut old_session_) = sessions.entry(*old_id) {
						let old_session = old_session_.get_mut();
						if let Some(old_idx) = old_session.members.iter().position(|s| s.user_id == packet.my_user_id) {
							old_session.members.swap_remove(old_idx);
							// if the session is now completely empty; remove it
							if old_session.members.used == 0 {
								old_session_.remove();

								println!("removed empty {:?}", old_id);
							}
						}
					}
				}

				if let Some(session) = sessions.get_mut(&packet.session_id) {
					// found a session to join
					let member = SessionMemberData { user_id: packet.my_user_id, address: packet_source_address };
					session.members.push(member);

					match u2s_entry {
						Occupied(mut e) => { e.insert((packet_source_address, packet.session_id)); },
						Vacant(e) => { e.insert((packet_source_address, packet.session_id)); },
					}

					match a2s_entry {
						Occupied(mut e) => { e.insert((packet.my_user_id, packet.session_id)); },
						Vacant(e) => { e.insert((packet.my_user_id, packet.session_id)); },
					}
					drop(u2s_map_wlock);
					drop(a2s_map_wlock);
					drop(sessions_wlock);

					println!("joined existing {:?}", packet.session_id);

					packet.session_id
				}
				else {
					// no session found, create a new one
					match u2s_entry {
						Vacant(slot) => {
							let mut new_session = Session::default();
							new_session.members.push(SessionMemberData { user_id: packet.my_user_id, address: packet_source_address });
							sessions.insert(packet.session_id, new_session);

							slot.insert((packet_source_address, packet.session_id));

							match a2s_entry {
								Occupied(mut e) => { e.insert((packet.my_user_id, packet.session_id)); },
								Vacant(e) => { e.insert((packet.my_user_id, packet.session_id)); },
							}

							drop(u2s_map_wlock);
							drop(a2s_map_wlock);
							drop(sessions_wlock);
							
							println!("created new session {}", packet.session_id);
							packet.session_id
						},
						Occupied(slot) => {
							let id = slot.get().1;

							drop(u2s_map_wlock);
							drop(a2s_map_wlock);
							drop(sessions_wlock);

							println!("rejoined old session {id}");
							id
						},
					}
				}
			};

			let response = SessionCreatedData { session_id }.to_packet();
			send_packet(socket, packet_source_address, response).unwrap();
		},
		PacketType::LeaveSession if buffer.len() == size_of::<LeaveSession>() => {
			let packet = unsafe { buffer.as_ptr().cast::<LeaveSession>().as_ref().unwrap_unchecked() };
			println!("{:?} wants to leave their session", packet.my_user_id);

			if let Some((_, session_id)) = USER_TO_SESSION.write().unwrap().get_mut().remove(&packet.my_user_id) {
				remove_from_session(packet.my_user_id, session_id, &mut SESSIONS.write().unwrap().get_mut());
			}
		}
		_ => eprintln!("Unknown internal packet type: {}, len: {} Bytes", header.type_ as u16, buffer.len()),
	}
}
 
fn remove_from_session(user_id : UserId, session_id : SessionId, sessions : &mut HashMap<SessionId, Session>) {
	if let Some(old_session) = sessions.get_mut(&session_id) {
		if let Some(old_idx) = old_session.members.iter().position(|s| s.user_id == user_id) {
			old_session.members.swap_remove(old_idx);
			// if the session is now completely empty; remove it
			//TODO(Rennorb) @perf: can optimize out second check
			if old_session.members.used == 0 {
				sessions.remove(&session_id);

				println!("removed empty session {session_id}");
			}
		}
	}
}

fn send_packet<T : packet::Packet, A : ToSocketAddrs>(socket : &UdpSocket, destination : A, packet : T) -> Result<usize, std::io::Error> {
	let raw_data = unsafe { std::slice::from_raw_parts(std::ptr::from_ref(&packet).cast(), size_of::<T>()) };
	socket.send_to(raw_data, destination)
}



lazy_static::lazy_static! {
	static ref SESSIONS : RwLock<SessionStore> = Default::default();
	static ref USER_TO_SESSION : RwLock<User2SessionStore> = Default::default();
	static ref ADDR_TO_SESSION : RwLock<Address2UserStore> = Default::default();
}

#[derive(Default)]
struct SessionStore(UnsafeCell<HashMap<SessionId, Session>>);
unsafe impl Sync for SessionStore {}
impl Deref for SessionStore {
	type Target = UnsafeCell<HashMap<SessionId, Session>>;
	fn deref(&self) -> &Self::Target { &self.0 }
}
impl DerefMut for SessionStore {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[derive(Default)]
struct User2SessionStore(UnsafeCell<HashMap<UserId, (SocketAddr, SessionId)>>);
unsafe impl Sync for User2SessionStore {}
impl Deref for User2SessionStore {
	type Target = UnsafeCell<HashMap<UserId, (SocketAddr, SessionId)>>;
	fn deref(&self) -> &Self::Target { &self.0 }
}
impl DerefMut for User2SessionStore {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[derive(Default)]
struct Address2UserStore(UnsafeCell<HashMap<SocketAddr, (UserId, SessionId)>>);
unsafe impl Sync for Address2UserStore {}
impl Deref for Address2UserStore {
	type Target = UnsafeCell<HashMap<SocketAddr, (UserId, SessionId)>>;
	fn deref(&self) -> &Self::Target { &self.0 }
}
impl DerefMut for Address2UserStore {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionId([u32; 4]);
impl Display for SessionId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Debug::fmt(&self.0, f) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UserId([u32; 4]);
impl Display for UserId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Debug::fmt(&self.0, f) }
}

#[derive(Debug, Default)]
struct Session {
	pub members : InlineArray<SessionMemberData, 50>,
}

#[derive(Debug)]
struct SessionMemberData {
	pub user_id : UserId,
	pub address : SocketAddr,
}
