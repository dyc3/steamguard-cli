use serde::{Serialize, Deserialize};
use serde_repr::{Serialize_repr, Deserialize_repr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Quality {
	Normal = 0,
	Genuine = 1,
	Vintage = 3,
	Unusual = 5,
	Unique = 6,
	Community = 7,
	Valve = 8,
	SelfMade = 9,
	Strange = 11,
	Haunted = 13,
	Collectors = 14,
	Decorated = 15,
	Unknown = 255,
}

impl std::fmt::Display for Quality {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{:?}", self))
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemSlot {
	Primary,
	Secondary,
	Melee,
	Head,
	/// Misc slot items such as medals
	Misc,
	/// The Engineer's Build PDA, the Spy's Disguise Kit, and "Slot Token - PDA"
	Pda,
	/// The Engineer's Destroy PDA, the Spy's Invisibility Watch, the Cloak and Dagger, the Dead Ringer, and "Slot Token - PDA2"
	Pda2,
	Building,
	Grenade,
	Action,
	Taunt,
	Utility,
}

impl std::fmt::Display for ItemSlot {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("{:?}", self))
	}
}
