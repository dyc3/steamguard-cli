use std::fmt::Formatter;
use std::marker::PhantomData;

use protobuf::EnumFull;
use protobuf::EnumOrUnknown;
use protobuf::Message;
use protobuf::MessageField;
use protobuf::MessageFull;
use serde::{Deserialize, Serialize};

include!(concat!(env!("OUT_DIR"), "/protobufs/mod.rs"));

fn serialize_enum_or_unknown<E: EnumFull, S: serde::Serializer>(
	e: &Option<EnumOrUnknown<E>>,
	s: S,
) -> Result<S::Ok, S::Error> {
	if let Some(e) = e {
		match e.enum_value() {
			Ok(v) => s.serialize_str(v.descriptor().name()),
			Err(v) => s.serialize_i32(v),
		}
	} else {
		s.serialize_unit()
	}
}

fn deserialize_enum_or_unknown<'de, E: EnumFull, D: serde::Deserializer<'de>>(
	d: D,
) -> Result<Option<EnumOrUnknown<E>>, D::Error> {
	struct DeserializeEnumVisitor<E: EnumFull>(PhantomData<E>);

	impl<'de, E: EnumFull> serde::de::Visitor<'de> for DeserializeEnumVisitor<E> {
		type Value = Option<EnumOrUnknown<E>>;

		fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
			write!(formatter, "a string, an integer or none")
		}

		fn visit_str<R>(self, v: &str) -> Result<Self::Value, R>
		where
			R: serde::de::Error,
		{
			match E::enum_descriptor().value_by_name(v) {
				Some(v) => Ok(Some(EnumOrUnknown::from_i32(v.value()))),
				None => Err(serde::de::Error::custom(format!(
					"unknown enum value: {}",
					v
				))),
			}
		}

		fn visit_i32<R>(self, v: i32) -> Result<Self::Value, R>
		where
			R: serde::de::Error,
		{
			Ok(Some(EnumOrUnknown::from_i32(v)))
		}

		fn visit_unit<R>(self) -> Result<Self::Value, R>
		where
			R: serde::de::Error,
		{
			Ok(None)
		}
	}

	d.deserialize_any(DeserializeEnumVisitor(PhantomData))
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "MessageField")]
pub(crate) struct MessageFieldDef<T>(pub Option<Box<T>>);
