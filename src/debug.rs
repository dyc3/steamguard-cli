use log::*;

/// Parses a JSON string and prints it in a readable format, with all values stripped and replaced with their types.
pub fn parse_json_stripped(json: &str) -> anyhow::Result<serde_json::Value> {
	let v: serde_json::Value = serde_json::from_str(json)?;
	let v = strip_json_value(v);
	Ok(v)
}

pub fn strip_json_value(v: serde_json::Value) -> serde_json::Value {
	match v {
		serde_json::Value::Object(mut map) => {
			for (_, v) in map.iter_mut() {
				*v = strip_json_value(v.clone());
			}
			serde_json::Value::Object(map)
		}
		serde_json::Value::Array(mut arr) => {
			for v in arr.iter_mut() {
				*v = strip_json_value(v.clone());
			}
			serde_json::Value::Array(arr)
		}
		serde_json::Value::String(_) => serde_json::Value::String("string".into()),
		serde_json::Value::Number(_) => serde_json::Value::Number(0.into()),
		serde_json::Value::Bool(_) => serde_json::Value::Bool(false),
		serde_json::Value::Null => serde_json::Value::Null,
	}
}

pub fn log_json_error_better(err: serde_json::Error, json: &str) -> serde_json::Error {
	match err.classify() {
		serde_json::error::Category::Data => {
			let v = parse_json_stripped(json).unwrap();
			error!(
				"This is the json that we failed to parse: {}",
				serde_json::to_string_pretty(&v).unwrap()
			);
		}
		_ => {}
	}
	err
}
