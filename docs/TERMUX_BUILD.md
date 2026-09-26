# Building steamguard-cli on-device in Termux

This builds `steamguard` directly on your Android phone, inside Termux,
using Termux's own native Rust toolchain. No NDK, no cross-compilation, no
desktop machine required. (If you want to cross-compile from a desktop
instead, that's a different, more involved route, not the one this guide 
covers.)

## Why this is possible without extra work

- Networking (`reqwest`) uses `rustls-tls`, not OpenSSL — no OpenSSL build
  headaches.
- The TLS crypto backend (`ring`) is plain C, no C++ runtime needed.
- Account crypto (`aes`, `cbc`, `argon2`, `pbkdf2`, `rsa`, `sha1`) and gzip
  support (`flate2`/`miniz_oxide`) are all pure Rust.
- The only feature that doesn't work headless — `keyring`, which normally
  caches your encryption passphrase via the OS — is already feature-gated
  in `Cargo.toml` and can just be left out at build time. No source changes
  needed.

## STEPS :

## 1. Install Termux

Get it from **Play Store** or **GitHub** — not the F-Droid releases, which may 
install the wrong version for your device.

(Optional but useful later: also install the separate **Termux:API** app
from the same source, for phone-integration commands.)

## Termux basics

- Termux's home directory is `/data/data/com.termux/files/home/` (`~`).
- Termux's own binaries/packages live under
  `/data/data/com.termux/files/usr/` (`$PREFIX`).
- Files inside Termux's own filesystem are executable. Files in Android
  shared storage (`/sdcard`, including Downloads) are mounted `noexec` and
  cannot be run directly, regardless of `chmod +x` — see the notes section
  at the end.

## 2. Install Rust and git

```bash
pkg update
pkg install rust git
```

This installs a native `aarch64` Rust toolchain built for Termux.

## 3. Get the source onto the phone

One-time, so Termux can see your phone's shared storage (Downloads, etc.):

```bash
termux-setup-storage
```

Android will show a permission prompt — allow it.

Then, if you have the project as a zip in your Downloads folder:

```bash
cd ~
cp -v storage/downloads/steamguard-cli-android.zip .
unzip steamguard-cli-android.zip
```

(`~/storage/downloads` is a symlink into shared storage that
`termux-setup-storage` creates for you. If the filename differs, check with
`ls storage/downloads/` first.)

*Note: The name can differ based on the Termux version and where it was 
installed from. In which case, you can check the directory name by running 
`ls -a` after running `termux-setup-storage`. Adjust the file path accordingly.*

Alternatively, cloning the GitHub repo is the **Recommended** method. Make
sure you trust the repo because it will be handling your Steam credentials.

```bash
git clone https://www.github.com/alphaxleonidas/steamguard-cli-android.git
```

## 4. Build

```bash
cargo build --profile termux --no-default-features --features qr,updater
```

What this does:

- `--profile termux` — uses the `[profile.termux]` block added to
  `Cargo.toml` (`opt-level = 2`, `lto = false`). Skips full LTO, which is
  slow and can get OOM-killed on phone-level RAM. This only affects build
  speed/memory, not functionality.
- `--no-default-features --features qr,updater` — builds with QR login and
  the update checker, but without the `keyring` feature (not usable from a
  headless Termux process — Android's Credential Manager/Autofill require
  a foreground `Activity`, which a CLI binary doesn't have).

First build: expect roughly 10–20 minutes depending on the device, mostly
spent compiling dependencies. Rebuilds after code changes are much faster.

## Download PreCompiled File: 

Alternatively, you can download the **precompiled binary** from [Releases](https://github.com/alphaxleonidas/steamguard-cli-android/releases)
and move it to the Termux directory using the following commands (in which case skip step 5): 
```bash
termux-setup-storage
cd ~
cp -v storage/downloads/steamguard $PREFIX/bin/
chmod +x $PREFIX/bin/steamguard
steamguard --help
```


## 5. Verify and install onto PATH

```bash
./target/termux/steamguard --help
```

If that prints the command list, the build worked. To make it runnable as
just `steamguard` from anywhere in Termux:

```bash
cp target/termux/steamguard $PREFIX/bin/steamguard
chmod +x $PREFIX/bin/steamguard
steamguard --help
```

## 6. Load an account (if you already have a file)

**If you have an existing `maFile`/manifest folder** (e.g. from Steam
Desktop Authenticator or a previous `steamguard-cli` install):

```bash
mkdir -p ~/.config/steamguard-cli/maFiles
mv ~/your-mafile-folder/* ~/.config/steamguard-cli/maFiles/
steamguard list
```

`steamguard` auto-detects the manifest and migrates older (SDA) formats in
place — no `import` command needed if a `manifest.json` is already present.

**If you only have loose, individual `.maFile` files with no manifest:**

```bash
steamguard import --files ~/gaben.maFile
```

(`import` requires the file be unencrypted; replace the filename with your
actual one.)

## 7. Setup an account (If you dont have a maFile)
```bash
steamguard setup
```
It creates two files in `~/.config/steamguard-cli/maFiles`. Be sure to 
**create a backup** of those files.

For commands, use: 
```bash
steamguard --help
```

## IMPORTANT NOTE
  `steamguard setup` (command to setup steamguard-cli as a 2FA) **has not 
  been tested fully** and if you do, make sure you do it on your **OWN 
  RISK**. The steps are the same as the original repo: [Usage](https://github.com/dyc3/steamguard-cli#usage)
  Make sure to read it fully. So far there have been no issues with the 
  Android version.
  
## Notes specific to phone storage

- `/sdcard` (shared storage, including Downloads) is readable by any app
  with storage permission — it is **not** private the way Termux's own
  home directory is. Move `maFile`s out of shared storage into `~/` (or
  straight into the `maFiles` directory above) as soon as you've copied
  them in; don't leave credentials sitting in Downloads.
- Android mounts shared storage `noexec` — binaries placed in `/sdcard`
  cannot be executed from there regardless of `chmod +x`. Always run
  `steamguard` from inside Termux's own filesystem (`$PREFIX/bin` or `~/`).
  Copying the binary *to* Downloads for backup/transfer is fine; running it
  from there is not.
- The compiled `steamguard` binary itself contains no account secrets and
  is safe to share/back up freely. It's `aarch64`-specific (won't run on
  32-bit devices, desktop OSes, or emulators without a separate build for
  that target) and has no external `.so` dependencies beyond Android's
  system `libc`, so it runs on any Termux install on a compatible device
  without missing-library issues.


  
## Day-to-day use

```bash
steamguard              # print current 2FA code
steamguard confirm      # list and approve/deny trade & market confirmations
steamguard list         # list configured accounts
```
