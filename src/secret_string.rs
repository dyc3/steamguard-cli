use secrecy::SecretString;
use serde::{Deserialize, Deserializer};

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
	use secrecy::ExposeSecret;

	use super::*;

	#[derive(Deserialize)]
	struct Foo {
		#[serde(with = "super")]
		secret: SecretString,
	}

	#[test]
	fn test_secret_string_deserialize() {
		let foo: Foo = serde_json::from_str("{\"secret\": \"hello\"}").unwrap();
		assert_eq!(foo.secret.expose_secret(), "hello");
	}
}
