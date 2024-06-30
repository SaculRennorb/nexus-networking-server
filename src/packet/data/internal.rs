use std::mem::size_of;
use crate::packet::{internal::{ExtendedHeader, Packet, PacketType}, AddonSignature, Header, Packet as _, Flags};

pub trait Data : super::Data {
	const TYPE : PacketType;
}
pub trait SizedData : Data + Sized {
	fn to_packet(self) -> Packet<Self> {
		let mut packet = Packet {
			header: ExtendedHeader { 
				basic: Header {
					target_addon: AddonSignature::INTERNAL_PACKET,
					length_in_u32s: (size_of::<Packet<Self>>() / 4) as u8,
					flags: Flags::None,
				},
				type_: Self::TYPE,
			},
			data: self,
			crc:  unsafe { #[allow(invalid_value)] std::mem::MaybeUninit::uninit().assume_init() },
		};
		packet.crc = packet.calculate_crc();
		packet
	}
}
pub trait DynamicData : Data {
	const MIN_SIZE : usize;
	const MAX_SIZE : usize;
}