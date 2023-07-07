# steamguard-cli

[![Lint, Build, Test](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml)
[![AUR Tester](https://github.com/dyc3/steamguard-cli/actions/workflows/aur-checker.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/aur-checker.yml)

A command line utility for setting up and using Steam Mobile Authenticator (AKA Steam 2FA). It can also be used to respond to trade and market confirmations.

**The only legitimate place to download steamguard-cli binaries is through this repo's releases, or by any package manager that is linked in this document.**

# Disclaimer
**This utility is effectively in beta. Use this software at your own risk. Make sure to back up your maFiles regularly, and make sure to actually write down your revocation code. If you lose both of these, we can't help you, your only recourse is to beg Steam support.**

# Quickstart

If you have no idea what the rest of this document is talking about, go read the [quickstart](docs/quickstart.md).

# Features

- Generate 2FA codes
- Respond to trade, market or any other confirmations
- Encrypted storage of your 2FA secrets
  - With the option to store your encryption passkey in the system keyring
- Special memory-clearing data structures to prevent leaking secrets
- QR code generation for importing 2FA secrets into other applications, like KeeWeb
- QR code logins for quickly logging into Steam on a new device, like the Steam Deck
- Able to read Steam Desktop Authenticator's `maFiles` format
- Uses as many official Steam APIs as possible, unlikely to break

# Install

If you have the Rust toolchain installed:
```
cargo install steamguard-cli
```

Arch-based systems can install from the AUR:

- [steamguard-cli](https://aur.archlinux.org/packages/steamguard-cli/) tracks the latest release
- [steamguard-cli-git](https://aur.archlinux.org/packages/steamguard-cli-git/) tracks the latest git commit

Otherwise, you can download binaries from the releases.

## Building From Source

```
cargo build --release
```

# Usage
`steamguard-cli` looks for your `maFiles/manifest.json` in at these paths, in this order:

Linux:
- `~/.config/steamguard-cli/maFiles/`
- `~/maFiles/`

Windows:
- `%APPDATA%\Roaming\steamguard-cli\maFiles\`
- `%USERPROFILE%\maFiles\`

Your `maFiles` can be created with or imported from [Steam Desktop Authenticator][SDA]. You can create `maFiles` with steamguard-cli using the `setup` action (`steamguard setup`).

**REMEMBER TO MAKE BACKUPS OF YOUR `maFiles`, AND TO WRITE DOWN YOUR RECOVERY CODE!**

[SDA]: https://github.com/Jessecar96/SteamDesktopAuthenticator

Full helptext can be displayed with:
```
steamguard --help
```

## One Liners

Generate and copy a new code to clipboard:
```bash
steamguard | xclip -selection clipboard
```

## Importing 2FA Secret Into Other Applications

It's possible to import your 2FA secret into other applications. This is useful if you want to use a password manager to generate your 2FA codes, like KeeWeb.

To make this easy, steamguard-cli can generate a QR code for your 2FA secret. You can then scan this QR code with your password manager.

```bash
steamguard qr # print QR code for the first account in your maFiles
steamguard -u <account name> qr # print QR code for a specific account
```

There are some applications that do not generate correct 2fa codes from the secret, so **do not use them**:
- Google Authenticator
- Authy

# Contributing

By contributing code to this project, you give me and any future maintainers a non-exclusive transferable license to use that code for this project, including permission to modify, redistribute, and relicense it.

# License

`steamguard-cli`, the command line program is licensed under GPLv3.

`steamguard`, the library that is used by `steamguard-cli` is dual licensed under MIT or Apache 2.0, at your option.

# Used By

* [Unreal Engine to Steam publishing CI/CD pipeline](https://github.com/kasp1/dozer-pipelines), a sample pipeline built for [Dozer](https://github.com/kasp1/Dozer), a simple CI/CD runner
