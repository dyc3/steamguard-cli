use std::path::Path;
use std::path::PathBuf;

use protobuf_codegen::Codegen;

fn main() {
	// let current_dir = std::env::current_dir().unwrap();
	let mut codegen = Codegen::new();
	codegen.pure();
	codegen.include("protobufs");

	// get all the .proto files in the protobufs directory using std
	let proto_files = get_all_proto_paths("protobufs").expect("failed to read protobufs directory");
	for proto_file in proto_files {
		codegen.input(proto_file);
	}
	codegen.cargo_out_dir("protobufs");

	codegen.run().expect("protobuf codegen failed");
	println!("cargo:rerun-if-changed=protobufs");
	println!("cargo:rerun-if-changed=build.rs");
}

fn get_all_proto_paths<P: AsRef<Path>>(dir: P) -> anyhow::Result<Vec<PathBuf>> {
	let mut paths = Vec::new();
	let proto_files = std::fs::read_dir(dir).expect("failed to read protobufs directory");
	for proto_file in proto_files {
		let proto_file = proto_file?;
		if proto_file.file_type().unwrap().is_dir() {
			let sub_paths = get_all_proto_paths(proto_file.path())?;
			paths.extend(sub_paths);
		} else {
			paths.push(proto_file.path());
		}
	}
	Ok(paths)
}
