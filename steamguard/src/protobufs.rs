use zeroize::Zeroize;

use self::steammessages_base::{cmsg_ipaddress::Ip, cmsg_proto_buf_header::Ip_addr};

include!("gen/mod.rs");

impl Zeroize for Ip {
	fn zeroize(&mut self) {
		match self {
			Ip::V4(ip) => ip.zeroize(),
			Ip::V6(ip) => ip.zeroize(),
		}
	}
}

impl Zeroize for Ip_addr {
	fn zeroize(&mut self) {
		match self {
			Ip_addr::Ip(ip) => ip.zeroize(),
			Ip_addr::IpV6(ip) => ip.zeroize(),
		}
	}
}

#[cfg(test)]
mod parse_tests {
	use base64::Engine;
	use protobuf::Message;

	use super::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;

	#[test]
	fn test_build_protobuf() {
		let mut req = CAuthentication_GetPasswordRSAPublicKey_Request::new();
		req.set_account_name("hydrastar2".to_owned());

		let bytes = req.write_to_bytes().unwrap();
		let s = base64::engine::general_purpose::URL_SAFE.encode(bytes);
		assert_eq!(s, "CgpoeWRyYXN0YXIy");
	}
}
