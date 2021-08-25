# steamguard-cli

[![Rust](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml/badge.svg)](https://github.com/dyc3/steamguard-cli/actions/workflows/rust.yml)

A command line utility for setting up and using Steam Mobile Authenticator (AKA Steam 2FA). It can also be used to respond to trade and market confirmations.

**The only legitamate place to download steamguard-cli binaries is through this repo's releases, or by any package manager that is linked in this document.**

# Disclaimer
**This utility is effectively in beta. Use this software at your own risk. Make sure to back up your maFiles regularly, and make sure to actually write down your revocation code. If you lose both of these, we can't help you, your only recourse is to beg Steam support.**

# Install

If you have the Rust toolchain installed:
```
cargo install steamguard-cli
```

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

## Importing 2FA Secret Into Other Applications

It's possible to import your 2FA secret into other applications, like Google Authenticator or KeeWeb. The `uri` field contains a URI in that starts with `otpauth://...`, which you can create a QR code for.

# Contributing

By contributing code to this project, you give me and any future maintainers a non-exclusive transferable license to use that code for this project, including permission to modify, redistribute, and relicense it.

# License

`steamguard-cli`, the command line program is licensed under GPLv3.

`steamguard`, the library that is used by `steamguard-cli` is dual licensed under MIT or Apache 2.0, at your option.
