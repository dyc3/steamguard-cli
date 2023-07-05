use std::path::Path;
use std::path::PathBuf;

use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::reflect::FieldDescriptor;
use protobuf::reflect::MessageDescriptor;
use protobuf_codegen::Codegen;
use protobuf_codegen::Customize;
use protobuf_codegen::CustomizeCallback;

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

	codegen.customize_callback(GenSerde);
	codegen.run_from_script();
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

struct GenSerde;

impl CustomizeCallback for GenSerde {
	fn message(&self, _message: &MessageDescriptor) -> Customize {
		Customize::default().before("#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]")
		// Customize::default()
	}

	fn enumeration(&self, _enum_type: &protobuf::reflect::EnumDescriptor) -> Customize {
		Customize::default()
			.before("#[derive(::serde::Serialize, ::serde::Deserialize, ::zeroize::Zeroize)]")
	}

	fn field(&self, field: &FieldDescriptor) -> Customize {
		// if field.name() == "public_ip" {
		// 	eprintln!("type_name: {:?}", field.proto().type_name());
		// 	eprintln!("type_: {:?}", field.proto().type_());
		// 	eprintln!("{:?}", field.proto());
		// }
		if field.proto().type_() == Type::TYPE_ENUM || field.proto().type_() == Type::TYPE_MESSAGE {
			Customize::default().before("#[zeroize(skip)]")
		} else {
			Customize::default()
		}
	}

	fn special_field(&self, _message: &MessageDescriptor, _field: &str) -> Customize {
		Customize::default().before("#[zeroize(skip)]")
	}
}
