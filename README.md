# steamguard-cli
A linux utility for setting up and using Steam Mobile Authenticator (AKA Steam 2FA) on the command line.
**This utility is in beta.**

# Disclaimer
**Use this software at your own risk.**

# Prerequisites
These packages are required to build and run steamguard-cli.
* mono-complete
* nuget
* make

# Building
Downloading as .zip will not work because submodules are used. You must clone the repository.

## Linux
Building on Linux is very simple. Make sure you have all the prerequisites listed above.

    git clone --recursive https://github.com/dyc3/steamguard-cli.git
    cd steamguard-cli
    make

To run the current build:

    build/steamguard

To run the current build quickly:

    make run

## Windows
Coming soon...

# Installation
To install the latest version on Debian-based systems, download the package from the releases section and type

    sudo dpkg --install steamguard-cli_x.x.x.x-x.deb

To install after building from source, run:

    sudo make install

# Usage
`steamguard-cli` looks for your `maFiles` folder in the current user's home directory (eg. `~/maFiles/`).
Your `maFiles` can be created with [Steam Desktop Authenticator][SDA]. You can create `maFiles` with
steamguard-cli using the `setup` action (`steamguard setup`).

**REMEMBER TO MAKE BACKUPS OF YOUR `maFiles`, AND TO WRITE DOWN YOUR RECOVERY CODE!**

[SDA]: https://github.com/Jessecar96/SteamDesktopAuthenticator

## Arguments
    usage: steamguard (action) (steam username) -v -h

      -h, --help                Display this help message.
      -v, --verbose             Display some extra information when the program is running.
      -m, --mafiles-path        Specify which folder your maFiles are in. Ex: ~/maFiles
      -p, --passkey             Specify your encryption passkey.

    Actions:
      generate-code             Generate a Steam Guard code for the specified user (if any) and exit. (default)
      encrypt                   Encrypt your maFiles or change your encryption passkey.
      decrypt                   Remove encryption from your maFiles.
      code                      Same as generate-code
      2fa                       Same as generate-code
      add                       Set up Steam Guard for 2 factor authentication.
      setup                     Same as add
      trade                     Opens an interactive prompt to handle trade confirmations.
      accept-all                Accepts all trade confirmations.
