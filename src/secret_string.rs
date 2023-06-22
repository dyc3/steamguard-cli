use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serializer};

/// Helper to allow serializing a [secrecy::SecretString] as a [String]
pub(crate) fn serialize<S>(secret_string: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(secret_string.expose_secret())
}

/// Helper to allow deserializing a [String] as a [secrecy::SecretString]
pub(crate) fn deserialize<'de, D>(d: D) -> Result<secrecy::SecretString, D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(d)?;
	Ok(SecretString::new(s))
}

#[cfg(test)]
mod test {
	use serde::Serialize;

	use super::*;

	#[test]
	fn test_secret_string_round_trip() {
		#[derive(Serialize, Deserialize)]
		struct Foo {
			#[serde(with = "super")]
			secret: SecretString,
		}

		let foo = Foo {
			secret: String::from("hello").into(),
		};

		let s = serde_json::to_string(&foo).unwrap();
		let foo2: Foo = serde_json::from_str(&s).unwrap();
		assert_eq!(foo.secret.expose_secret(), foo2.secret.expose_secret());
	}

	#[test]
	fn test_secret_string_deserialize() {
		#[derive(Serialize, Deserialize)]
		struct Foo {
			#[serde(with = "super")]
			secret: SecretString,
		}

		let foo: Foo = serde_json::from_str("{\"secret\": \"hello\"}").unwrap();
		assert_eq!(foo.secret.expose_secret(), "hello");
	}
}
