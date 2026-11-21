//! Keeps maFiles accessible only to the current user, since they contain account secrets.
//!
//! Permission checks are only performed on Unix. On other platforms these functions fall back to
//! the platform's default behavior.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::{collections::BTreeSet, os::unix::fs::PermissionsExt, path::PathBuf};

/// Owner read/write.
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
/// Owner read/write/execute.
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
/// Any permission bits for group or other users.
#[cfg(unix)]
const GROUP_OTHER_MASK: u32 = 0o077;

/// Creates or truncates a file that only the current user can read or write.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
	let mut options = OpenOptions::new();
	// Truncate only after permissions are set, so existing contents survive if that fails.
	options.write(true).create(true).truncate(false);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_FILE_MODE);
	let file = options.open(path)?;
	// `mode` only applies when the file is newly created, so tighten files that already existed.
	#[cfg(unix)]
	file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
	file.set_len(0)?;
	Ok(file)
}

/// Recursively creates a directory that only the current user can access.
pub(crate) fn create_private_dir_all(path: &Path) -> io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	std::os::unix::fs::DirBuilderExt::mode(&mut builder, PRIVATE_DIR_MODE);
	builder.create(path)
}

/// Makes sure the maFiles directory, the files in it, and the account files referenced by the
/// manifest are only accessible by the current user.
///
/// If anything is accessible by other users, the user is asked whether to fix it. If they decline,
/// or can't be asked because stdin is not a terminal, this returns an error. Files outside the
/// maFiles directory are never changed automatically, because the manifest that references them
/// may itself have been modified by someone else.
pub(crate) fn ensure_private_mafiles_dir(dir: &Path) -> anyhow::Result<()> {
	#[cfg(unix)]
	{
		use log::*;
		use std::io::IsTerminal;

		let dir = std::fs::canonicalize(dir)?;
		let insecure = find_insecure_paths(&dir)?;
		if insecure.is_empty() {
			return Ok(());
		}

		warn!("Permissions for these files are too open:");
		for path in &insecure {
			warn!("  {}", path.display());
		}
		warn!("They can be read by other users on the same system. It is recommended that your maFiles are NOT accessible by others.");

		let refusal = format!(
			"Refusing to continue while maFiles are accessible by other users. To fix this yourself, run: chmod go-rwx {}",
			insecure
				.iter()
				.map(|path| shell_quote(path))
				.collect::<Vec<_>>()
				.join(" ")
		);
		if insecure.iter().any(|path| !path.starts_with(&dir)) {
			warn!("Some of these files are outside {}, so their permissions won't be changed automatically.", dir.display());
			bail!(refusal);
		}
		if !std::io::stdin().is_terminal() {
			bail!(refusal);
		}
		if crate::tui::prompt_char(
			"Restrict permissions so only you can access these files?",
			"Yn",
		) == 'n'
		{
			bail!(refusal);
		}

		for path in &insecure {
			restrict_to_owner(path)?;
		}
		info!("Restricted permissions on {} path(s)", insecure.len());
	}
	#[cfg(not(unix))]
	let _ = dir;
	Ok(())
}

/// Quotes a path for a POSIX shell, so that it is passed to a command literally.
#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
	format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// Returns the directory itself, and any files from [`files_to_check`], that group or other users can access.
///
/// `dir` must be canonicalized.
#[cfg(unix)]
fn find_insecure_paths(dir: &Path) -> io::Result<Vec<PathBuf>> {
	let mut insecure = vec![];
	if is_accessible_by_others(&std::fs::metadata(dir)?) {
		insecure.push(dir.to_path_buf());
	}
	for path in files_to_check(dir)? {
		let metadata = std::fs::metadata(&path)?;
		if metadata.is_file() && is_accessible_by_others(&metadata) {
			insecure.push(path);
		}
	}
	Ok(insecure)
}

/// Returns the regular files directly inside `dir`, plus the manifest and every account file it
/// references, wherever they are.
///
/// Symlinks directly inside `dir` are skipped unless the manifest uses them, because they may
/// point to files that have nothing to do with steamguard-cli. Referenced files are resolved to
/// the real file the CLI reads, so that is what gets checked, shown to the user, and fixed.
#[cfg(unix)]
fn files_to_check(dir: &Path) -> io::Result<BTreeSet<PathBuf>> {
	let mut paths = BTreeSet::new();
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		if entry.file_type()?.is_file() {
			paths.insert(entry.path());
		}
	}

	let manifest_path = dir.join("manifest.json");
	let referenced = std::iter::once(manifest_path.clone()).chain(
		manifest_filenames(&manifest_path)
			.into_iter()
			.map(|filename| dir.join(filename)),
	);
	for path in referenced {
		// missing files are reported when the accounts are loaded
		if let Ok(path) = std::fs::canonicalize(path) {
			paths.insert(path);
		}
	}
	Ok(paths)
}

/// Reads the account filenames from the manifest. Both the current and the legacy SDA manifest
/// formats store them in `entries[].filename`.
///
/// Like the manifest loaders, this ignores anything after the first JSON value, so that it sees
/// the same entries they do. Returns nothing if the manifest can't be read, because loading it
/// will fail later with a better error.
#[cfg(unix)]
fn manifest_filenames(manifest_path: &Path) -> Vec<String> {
	#[derive(serde::Deserialize)]
	struct Manifest {
		#[serde(default)]
		entries: Vec<Entry>,
	}
	#[derive(serde::Deserialize)]
	struct Entry {
		filename: String,
	}

	let Ok(file) = File::open(manifest_path) else {
		return vec![];
	};
	let mut deser = serde_json::Deserializer::from_reader(io::BufReader::new(file));
	<Manifest as serde::Deserialize>::deserialize(&mut deser)
		.map(|manifest| manifest.entries.into_iter().map(|e| e.filename).collect())
		.unwrap_or_default()
}

#[cfg(unix)]
fn is_accessible_by_others(metadata: &std::fs::Metadata) -> bool {
	metadata.permissions().mode() & GROUP_OTHER_MASK != 0
}

/// Removes all group and other permission bits, keeping the owner's permissions as they are.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> io::Result<()> {
	let mode = std::fs::metadata(path)?.permissions().mode();
	std::fs::set_permissions(
		path,
		std::fs::Permissions::from_mode(mode & !GROUP_OTHER_MASK),
	)
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;
	use std::fs::Permissions;
	use tempfile::TempDir;

	fn mode_of(path: &Path) -> u32 {
		std::fs::metadata(path).unwrap().permissions().mode() & 0o777
	}

	#[test]
	fn test_create_private_file_new() {
		let tmp_dir = TempDir::new().unwrap();
		let path = tmp_dir.path().join("test.maFile");
		create_private_file(&path).unwrap();
		assert_eq!(mode_of(&path), 0o600);
	}

	#[test]
	fn test_create_private_file_tightens_existing() {
		let tmp_dir = TempDir::new().unwrap();
		let path = tmp_dir.path().join("test.maFile");
		std::fs::write(&path, "{}").unwrap();
		std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
		create_private_file(&path).unwrap();
		assert_eq!(mode_of(&path), 0o600);
	}

	#[test]
	fn test_create_private_file_truncates_existing() {
		let tmp_dir = TempDir::new().unwrap();
		let path = tmp_dir.path().join("test.maFile");
		std::fs::write(&path, "old contents that are longer").unwrap();
		let mut file = create_private_file(&path).unwrap();
		std::io::Write::write_all(&mut file, b"new").unwrap();
		drop(file);
		assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
	}

	#[test]
	fn test_create_private_dir_all() {
		let tmp_dir = TempDir::new().unwrap();
		let path = tmp_dir.path().join("a/maFiles");
		create_private_dir_all(&path).unwrap();
		assert_eq!(mode_of(&path), 0o700);
	}

	#[test]
	fn test_find_insecure_paths() {
		let tmp_dir = TempDir::new().unwrap();
		let dir = &std::fs::canonicalize(tmp_dir.path()).unwrap();
		std::fs::set_permissions(dir, Permissions::from_mode(0o700)).unwrap();
		let secure = dir.join("secure.maFile");
		let insecure = dir.join("insecure.maFile");
		let read_only = dir.join("readonly.maFile");
		std::fs::write(&secure, "{}").unwrap();
		std::fs::write(&insecure, "{}").unwrap();
		std::fs::write(&read_only, "{}").unwrap();
		std::fs::set_permissions(&secure, Permissions::from_mode(0o600)).unwrap();
		std::fs::set_permissions(&insecure, Permissions::from_mode(0o640)).unwrap();
		std::fs::set_permissions(&read_only, Permissions::from_mode(0o400)).unwrap();

		assert_eq!(find_insecure_paths(dir).unwrap(), vec![insecure]);

		std::fs::set_permissions(dir, Permissions::from_mode(0o755)).unwrap();
		assert!(find_insecure_paths(dir)
			.unwrap()
			.contains(&dir.to_path_buf()));
	}

	#[test]
	fn test_find_insecure_paths_manifest_references() {
		let tmp_dir = TempDir::new().unwrap();
		let root = std::fs::canonicalize(tmp_dir.path()).unwrap();
		let dir = root.join("maFiles");
		let elsewhere = root.join("elsewhere");
		create_private_dir_all(&dir).unwrap();
		create_private_dir_all(&dir.join("nested")).unwrap();
		create_private_dir_all(&elsewhere).unwrap();

		let nested = dir.join("nested/nested.maFile");
		let absolute = elsewhere.join("absolute.maFile");
		let link_target = elsewhere.join("link_target.maFile");
		let unrelated = elsewhere.join("unrelated.txt");
		for path in [&nested, &absolute, &link_target, &unrelated] {
			std::fs::write(path, "{}").unwrap();
			std::fs::set_permissions(path, Permissions::from_mode(0o644)).unwrap();
		}
		std::os::unix::fs::symlink(&link_target, dir.join("link.maFile")).unwrap();
		std::os::unix::fs::symlink(&unrelated, dir.join("unrelated.txt")).unwrap();

		let manifest = serde_json::json!({
			"entries": [
				{ "filename": "nested/nested.maFile" },
				{ "filename": absolute },
				{ "filename": "link.maFile" },
			]
		});
		let manifest_path = dir.join("manifest.json");
		std::fs::write(&manifest_path, manifest.to_string()).unwrap();
		std::fs::set_permissions(&manifest_path, Permissions::from_mode(0o600)).unwrap();

		let mut insecure = find_insecure_paths(&dir).unwrap();
		insecure.sort();
		let mut expected = vec![nested, absolute, link_target];
		expected.sort();
		assert_eq!(insecure, expected);
	}

	#[test]
	fn test_manifest_filenames_ignores_trailing_content() {
		let tmp_dir = TempDir::new().unwrap();
		let path = tmp_dir.path().join("manifest.json");
		std::fs::write(&path, r#"{"entries":[{"filename":"a.maFile"}]} trailing"#).unwrap();
		assert_eq!(manifest_filenames(&path), vec!["a.maFile"]);
	}

	#[test]
	fn test_shell_quote() {
		for name in [
			"plain",
			"it's",
			"$(echo pwned)",
			"`echo pwned`",
			"a\\b \"c\"",
		] {
			let path = PathBuf::from(format!("/tmp/{}.maFile", name));
			let output = std::process::Command::new("sh")
				.arg("-c")
				.arg(format!("printf %s {}", shell_quote(&path)))
				.output()
				.unwrap();
			assert_eq!(
				String::from_utf8(output.stdout).unwrap(),
				path.to_str().unwrap()
			);
		}
	}

	#[test]
	fn test_restrict_to_owner() {
		let tmp_dir = TempDir::new().unwrap();
		let path = tmp_dir.path().join("test.maFile");
		std::fs::write(&path, "{}").unwrap();
		std::fs::set_permissions(&path, Permissions::from_mode(0o664)).unwrap();
		restrict_to_owner(&path).unwrap();
		assert_eq!(mode_of(&path), 0o600);

		std::fs::set_permissions(&path, Permissions::from_mode(0o444)).unwrap();
		restrict_to_owner(&path).unwrap();
		assert_eq!(mode_of(&path), 0o400);
	}
}
