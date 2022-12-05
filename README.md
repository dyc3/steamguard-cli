# steamguard-cli

[![Lint, Build, Test](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml)
[![AUR Tester](https://github.com/dyc3/steamguard-cli/actions/workflows/aur-checker.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/aur-checker.yml)

A command line utility for setting up and using Steam Mobile Authenticator (AKA Steam 2FA). It can also be used to respond to trade and market confirmations.

**The only legitimate place to download steamguard-cli binaries is through this repo's releases, or by any package manager that is linked in this document.**

# Disclaimer
**This utility is effectively in beta. Use this software at your own risk. Make sure to back up your maFiles regularly, and make sure to actually write down your revocation code. If you lose both of these, we can't help you, your only recourse is to beg Steam support.**

# Install

If you have the Rust toolchain installed:
```
cargo install steamguard-cli
```

Arch-based systems can install from the AUR:

- For [steamguard-cli-git](https://aur.archlinux.org/packages/steamguard-cli-git/)
- *Non-git release is not officially provided. Please open an issue if you would like to help set that up.*

Otherwise, you can download binaries from the releases.

## Building From Source

```
cargo build --release
```

# Usage
`steamguard-cli` looks for your `maFiles/manifest.json` in at these paths, in this order:
- `~/.config/steamguard-cli/maFiles/`
- `~/maFiles/`

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
steamguard-cli | xclip -selection clipboard
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
