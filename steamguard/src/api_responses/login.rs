use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthData {
	pub oauth_token: String,
	pub steamid: String,
	pub wgtoken: String,
	pub wgtoken_secure: String,
	#[serde(default)]
	pub webcookie: String,
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_oauth_data_parse() {
		// This example is from a login response that did not contain any transfer URLs.
		let oauth: OAuthData = serde_json::from_str("{\"steamid\":\"78562647129469312\",\"account_name\":\"feuarus\",\"oauth_token\":\"fd2fdb3d0717bcd2220d98c7ec61c7bd\",\"wgtoken\":\"72E7013D598A4F68C7E268F6FA3767D89D763732\",\"wgtoken_secure\":\"21061EA13C36D7C29812CAED900A215171AD13A2\",\"webcookie\":\"6298070A226E5DAD49938D78BCF36F7A7118FDD5\"}").unwrap();

		assert_eq!(oauth.steamid, "78562647129469312");
		assert_eq!(oauth.oauth_token, "fd2fdb3d0717bcd2220d98c7ec61c7bd");
		assert_eq!(oauth.wgtoken, "72E7013D598A4F68C7E268F6FA3767D89D763732");
		assert_eq!(
			oauth.wgtoken_secure,
			"21061EA13C36D7C29812CAED900A215171AD13A2"
		);
		assert_eq!(oauth.webcookie, "6298070A226E5DAD49938D78BCF36F7A7118FDD5");
	}
}
