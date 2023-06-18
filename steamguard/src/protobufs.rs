use std::fmt::Formatter;
use std::marker::PhantomData;

use protobuf::EnumFull;
use protobuf::EnumOrUnknown;
use protobuf::MessageField;
use serde::{Deserialize, Serialize};

include!(concat!(env!("OUT_DIR"), "/protobufs/mod.rs"));

#[cfg(test)]
mod parse_tests {
	use protobuf::Message;

	use super::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;

	#[test]
	fn test_build_protobuf() {
		let mut req = CAuthentication_GetPasswordRSAPublicKey_Request::new();
		req.set_account_name("hydrastar2".to_owned());

		let bytes = req.write_to_bytes().unwrap();
		let s = base64::encode_config(bytes, base64::URL_SAFE);
		assert_eq!(s, "CgpoeWRyYXN0YXIy");
	}
}
