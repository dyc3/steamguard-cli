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
