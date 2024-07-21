use log::{debug, trace};
use protobuf::MessageFull;
use reqwest::blocking::multipart::Form;

use super::{Transport, TransportError};
use crate::steamapi::{ApiRequest, ApiResponse, BuildableRequest, EResult};

#[derive(Debug, Clone)]
pub struct WebApiTransport {
	client: reqwest::blocking::Client,
}

impl WebApiTransport {
	pub fn new(client: reqwest::blocking::Client) -> Self {
		Self { client }
	}
}

impl Transport for WebApiTransport {
	fn send_request<Req: BuildableRequest + MessageFull, Res: MessageFull>(
		&self,
		apireq: ApiRequest<Req>,
	) -> Result<ApiResponse<Res>, TransportError> {
		// All the API endpoints accept 2 data formats: json and protobuf.
		// Depending on the http method for the request, the data can go in 2 places:
		// - GET: query string, with the key `input_protobuf_encoded` or `input_json`
		// - POST: multipart form body, with the key `input_protobuf_encoded` or `input_json`, however url encoded form data seems to also be accepted

		// input protobuf data is always encoded in base64

		if Req::requires_access_token() && apireq.access_token().is_none() {
			return Err(TransportError::Unauthorized);
		}

		let url = apireq.build_url();
		debug!("HTTP Request: {} {}", Req::method(), url);
		trace!("Request body: {:#?}", apireq.request_data());
		let mut req = self.client.request(Req::method(), &url);

		req = if Req::method() == reqwest::Method::GET {
			let encoded = encode_msg(
				apireq.request_data(),
				base64::engine::general_purpose::URL_SAFE,
			)?;
			let mut params = vec![("input_protobuf_encoded", encoded.as_str())];
			if let Some(access_token) = apireq.access_token() {
				params.push(("access_token", access_token.expose_secret()));
			}
			req.query(&params)
		} else {
			if let Some(access_token) = apireq.access_token() {
				req = req.query(&[("access_token", access_token)]);
			}
			let encoded = encode_msg(
				apireq.request_data(),
				base64::engine::general_purpose::STANDARD,
			)?;
			let form = Form::new().text("input_protobuf_encoded", encoded);
			req.multipart(form)
		};

		let resp = req.send()?;
		let status = resp.status();
		debug!("Response HTTP status: {}", status);

		let eresult = if let Some(eresult) = resp.headers().get("x-eresult") {
			let s = eresult
				.to_str()
				.map_err(|err| TransportError::HeaderParseFailure {
					header: "x-eresult".to_owned(),
					source: err.into(),
				})?;
			debug!("HTTP Header x-eresult: {}", s);
			s.parse::<i32>()
				.map_err(|err| TransportError::HeaderParseFailure {
					header: "x-eresult".to_owned(),
					source: err.into(),
				})?
				.into()
		} else {
			EResult::Invalid
		};
		let error_msg = if let Some(error_message) = resp.headers().get("x-error_message") {
			let s = error_message
				.to_str()
				.map_err(|err| TransportError::HeaderParseFailure {
					header: "x-error_message".to_owned(),
					source: err.into(),
				})?;
			debug!("HTTP Header x-error_message: {}", s);
			Some(s.to_owned())
		} else {
			None
		};

		let bytes = resp.bytes()?;
		if !status.is_success() {
			trace!("Response body (raw): {:?}", bytes);

			if status == reqwest::StatusCode::UNAUTHORIZED {
				return Err(TransportError::Unauthorized);
			}
		}

		let res = decode_msg::<Res>(bytes.as_ref())?;
		trace!("Response body (decoded): {:#?}", res);
		let api_resp = ApiResponse {
			result: eresult,
			error_message: error_msg,
			response_data: res,
		};

		Ok(api_resp)
	}

	fn close(&mut self) {}

	fn innner_http_client(&self) -> anyhow::Result<reqwest::blocking::Client> {
		Ok(self.client.clone())
	}
}

fn encode_msg<T: MessageFull>(msg: &T, engine: impl base64::Engine) -> anyhow::Result<String> {
	let bytes = msg.write_to_bytes()?;
	let b64 = engine.encode(bytes);
	Ok(b64)
}

fn decode_msg<T: MessageFull>(bytes: &[u8]) -> Result<T, protobuf::Error> {
	T::parse_from_bytes(bytes)
}

#[cfg(test)]
mod tests {
	use crate::protobufs::steammessages_auth_steamclient::{
		CAuthentication_BeginAuthSessionViaCredentials_Request,
		CAuthentication_GetPasswordRSAPublicKey_Response,
		CAuthentication_PollAuthSessionStatus_Response,
	};

	use super::*;
	use base64::{engine::general_purpose::STANDARD, Engine};

	#[test]
	fn test_parse_poll_response() {
		let sample = b"GuUDZXlBaWRIbHdJam9nSWtwWFZDSXNJQ0poYkdjaU9pQWlSV1JFVTBFaUlIMC5leUFpYVhOeklqb2dJbk4wWldGdElpd2dJbk4xWWlJNklDSTNOalUyTVRFNU9URTFOVGN3TmpnNU1pSXNJQ0poZFdRaU9pQmJJQ0ozWldJaUxDQWljbVZ1WlhjaUxDQWlaR1Z5YVhabElpQmRMQ0FpWlhod0lqb2dNVGN3TlRBeE1UazFOU3dnSW01aVppSTZJREUyTnpnME5qUTRNemNzSUNKcFlYUWlPaUF4TmpnM01UQTBPRE0zTENBaWFuUnBJam9nSWpFNFF6VmZNakpDTTBZME16RmZRMFJHTmtFaUxDQWliMkYwSWpvZ01UWTROekV3TkRnek55d2dJbkJsY2lJNklERXNJQ0pwY0Y5emRXSnFaV04wSWpvZ0lqWTVMakV5TUM0eE16WXVNVEkwSWl3Z0ltbHdYMk52Ym1acGNtMWxjaUk2SUNJMk9TNHhNakF1TVRNMkxqRXlOQ0lnZlEuR3A1VFBqOXBHUWJ4SXpXREROQ1NQOU9rS1lTZXduV0JFOEUtY1ZxalFxcVQ1M0FzRTRya213OER5TThoVXJ4T0VQQ1dDWHdyYkRVcmgxOTlSempQRHci/gNleUFpZEhsd0lqb2dJa3BYVkNJc0lDSmhiR2NpT2lBaVJXUkVVMEVpSUgwLmV5QWlhWE56SWpvZ0luSTZNVGhETlY4eU1rSXpSalF6TVY5RFJFWTJRU0lzSUNKemRXSWlPaUFpTnpZMU5qRXhPVGt4TlRVM01EWTRPVElpTENBaVlYVmtJam9nV3lBaWQyVmlJaUJkTENBaVpYaHdJam9nTVRZNE56RTVNamM0T0N3Z0ltNWlaaUk2SURFMk56ZzBOalE0TXpjc0lDSnBZWFFpT2lBeE5qZzNNVEEwT0RNM0xDQWlhblJwSWpvZ0lqRXlSREZmTWpKQ00wVTROekZmT1RaRk5EQWlMQ0FpYjJGMElqb2dNVFk0TnpFd05EZ3pOeXdnSW5KMFgyVjRjQ0k2SURFM01EVXdNVEU1TlRVc0lDSndaWElpT2lBd0xDQWlhWEJmYzNWaWFtVmpkQ0k2SUNJMk9TNHhNakF1TVRNMkxqRXlOQ0lzSUNKcGNGOWpiMjVtYVhKdFpYSWlPaUFpTmprdU1USXdMakV6Tmk0eE1qUWlJSDAuMVNnUEotSVZuWEp6Nk9nSW1udUdOQ0hMbEJTcGdvc0Z0UkxoOV9iVVBHQ1RaMmFtRWY2ZTZVYkJzVWZ3bnlYbEdFdG5LSHhPemhibTdLNzBwVFhEQ0EoADIKaHlkcmFzdGFyMg==";

		let bytes = STANDARD.decode(sample).unwrap();

		let resp: CAuthentication_PollAuthSessionStatus_Response = decode_msg(&bytes).unwrap();

		println!("{:#?}", resp);
	}

	#[test]
	fn parse_get_public_rsa_response() {
		let sample = b"CoAEYjYyMGI1ZWNhMWIxMjgyYjkxYzZkZmZkYWFhOWI0ODI0YjlhNmRiYmEyZDVmYjc0ODcxNDczZDc1MDYxNGEzNWM4ODQ3NDYzZTEyNjAwNTJmNzZlNTYxMDM5ODdlN2U3NGJkMWZjZGRjYWJhMDVmZGM5OTBjMWIyNmQ2ZDg5MGM2MTEzZmRkNTZmMmQ1YmZjNzU4ODhlMzZhNTM2NjM3N2IzZTE3ZTJiZWM5MjhlNGY4MmE1YzY0NGYxZTZlMTk3NzZkNjIzMDIxYjhmYTA0MGRjNWE5YjY0M2I0N2I5YmVhMjM2YmEyZjM4ODVjM2ZlNWVhNjMzZThlNjJjNGE1YTY4NjNmMzNiMzdlMTQ4M2MwZTUzZTg4ODIzMGFkNTVjNzg5ZmU4Y2NkMjVjNzdiMTkxOTg0ZThjN2JmNWYzNzY2MjI0OGI1NWVmOWM1OGY3NDM5YjA4ZjNhNWJiNzljNTc5ZDE5M2I3NzhmMzFiY2IwYTA3MmVhZWYxOGEyYjljZDY2M2VmYmY2YmRiZDU3MGEyMTNiOTIxNTc4ODk0MjJkMDY3ODFiNTVkY2VjYjQ4NjA4MjUyMmUzZWQyOWM4MjExYzQ5N2Q1YjNhYTk2OGM2MDY1YWFhZTNhNGVmYzZiMGJjNDYyMzMxNmVmYTUxN2JjNzRiZDYzODcxMWU4ZWYSBjAxMDAwMRiQn6Ly3wk=";

		let bytes = STANDARD.decode(sample).unwrap();

		let resp: CAuthentication_GetPasswordRSAPublicKey_Response = decode_msg(&bytes).unwrap();

		println!("{:#?}", resp);
	}

	#[test]
	fn test_decode_encode_roundtrip() {
		let sample = b"EgpoeWRyYXN0YXIyGtgCRUxaNTBXdHM2Z0kxWlZaVjl6bzRJNFBEcEhTMGRZR3RSNzJPbytqZkR5QmRBUitrbnBUcUVGcGF4NDd1UVdqdUQ1R2hpRC9JanA2cEtGQzlrdUZDdzBFT0RMSFpINERZUG5hci9IMktOZGoxSFNjWEhyemZjNmk1OWpsRE5OTTI0RVllNUEyUjVSdzBoa2lodU14Z1A4NDJESFUxMkgwNWFyYmdRUWp3NFJmVHh6cDBQQlRjdTk4VUViUjJnak1RajlVK3RsYStPdTN6WTQ5K1BKc0szTkpMTVdxWm4vaFZ1dTR3NFprZGhXNVBqNWphb2Flb3J6MG8zbWIvUXo2M0NlNFdwWmUra1lFYUlSa29oUXBaZkliaW4rTWdQcVpNelg4cW4vNDcyNFp5N05mblpETlVBV3RoTkowTkUxSDVESXZ4N0IwRFJHZVBwdk5FbVdqWEJ3PT0g4MCW2tYBOAFCBk1vYmlsZUocCgpHYWxheHkgUzIyEAMYjPz/////////ASCQBA==";

		let bytes = STANDARD.decode(sample).unwrap();
		let decoded: CAuthentication_BeginAuthSessionViaCredentials_Request =
			decode_msg(&bytes).expect("Failed to decode");

		let encoded = encode_msg(&decoded, STANDARD).expect("Failed to encode");

		assert_eq!(encoded, String::from_utf8(sample.to_vec()).unwrap());
	}
}
