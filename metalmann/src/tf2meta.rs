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
}
