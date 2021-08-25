# steamguard-cli
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
`steamguard-cli` looks for your `maFiles` folder in the current user's home directory (eg. `~/maFiles/`).
Your `maFiles` can be created with [Steam Desktop Authenticator][SDA]. You can create `maFiles` with
steamguard-cli using the `setup` action (`steamguard setup`).

**REMEMBER TO MAKE BACKUPS OF YOUR `maFiles`, AND TO WRITE DOWN YOUR RECOVERY CODE!**

[SDA]: https://github.com/Jessecar96/SteamDesktopAuthenticator

Full helptext can be displayed with:
```
steamguard --help
```
