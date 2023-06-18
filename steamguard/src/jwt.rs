use serde::Deserialize;

pub(crate) fn decode_jwt(jwt: &String) -> anyhow::Result<SteamJwtData> {
	let parts = jwt.split(".").collect::<Vec<&str>>();
	ensure!(parts.len() == 3, "Invalid JWT");

	let data = parts[1].replace("-", "+").replace("_", "/");
	let bytes = base64::decode(data)?;
	let json = String::from_utf8(bytes)?;
	let jwt_data: SteamJwtData = serde_json::from_str(&json)?;
	Ok(jwt_data)
}

#[derive(Deserialize, Debug)]
pub(crate) struct SteamJwtData {
	exp: u64,
	iat: u64,
	iss: String,
	// Audience
	aud: Vec<String>,
	// Subject (steam id)
	sub: String,
	jti: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_decode_jwt() {
		let sample = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTE1NTcwNjg5MiIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTcwNTAxMTk1NSwgIm5iZiI6IDE2Nzg0NjQ4MzcsICJpYXQiOiAxNjg3MTA0ODM3LCAianRpIjogIjE4QzVfMjJCM0Y0MzFfQ0RGNkEiLCAib2F0IjogMTY4NzEwNDgzNywgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjY5LjEyMC4xMzYuMTI0IiwgImlwX2NvbmZpcm1lciI6ICI2OS4xMjAuMTM2LjEyNCIgfQ.7p5TPj9pGQbxIzWDDNCSP9OkKYSeDnWBE8E-M8hUrxOEPCW0XwrbDUrh199RzjPDw";
	}
}
