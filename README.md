# steamguard-cli
A linux utility for setting up and using Steam Guard on the command line.
**This utility is in beta. Not all features are implemented yet.**

# Disclaimer
Use this software at your own risk. 

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

    make run

## Windows
Coming soon...

# Installation
Coming soon...

# Usage
`steamguard-cli` looks for your `maFiles` folder in the current user's home directory (eg. `~/maFiles/`). 
Your `maFiles` can be created with [Steam Desktop Authenticator][SDA]. Creating `maFiles` with
steamguard-cli is not supported at this time. 

**REMEMBER TO MAKE BACKUPS OF YOUR `maFiles`, AND TO WRITE DOWN YOUR RECOVERY CODE!**

[SDA]: https://github.com/Jessecar96/SteamDesktopAuthenticator

## Arguments
    --help, -h         Display this help message.
    --verbose, -v      Display some extra information when the program is running.
    --user, -u         Specify an account for which to generate a Steam Gaurd code.
                       Otherwise, the first account will be selected.
    --generate-code              Generate a Steam Guard code and exit. (default)
    --encrypt                    Encrypt your maFiles or change your encryption passkey.
    --decrypt                    Remove encryption from your maFiles.
