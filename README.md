# steamguard-cli (Enhanced Fork)

An improved fork of steamguard-cli with enhanced HTTP API capabilities and decline functionality.

A command line utility for setting up and using Steam Mobile Authenticator (AKA Steam 2FA). It can also be used to respond to trade, market, and any other steam mobile confirmations that you would normally get in the app. This fork adds comprehensive HTTP API support for remote confirmation management and enhanced decline capabilities.

# Disclaimer
**This utility is effectively in beta. Use this software at your own risk. Make sure to back up your maFiles regularly, and make sure to actually write down your revocation code. If you lose both of these, we can't help you, your only recourse is to beg Steam support.**

# Quickstart

If you have no idea what the rest of this document is talking about, go read the [quickstart](docs/quickstart.md).

# Features

## Enhanced Features (This Fork)
- **Complete HTTP API server** for remote confirmation management
- **Decline confirmations** via CLI or HTTP API with robust retry logic
- **RESTful endpoints** for listing, accepting, and declining confirmations
- **CORS support** for browser extensions and web applications
- **Comprehensive error handling** with automatic retries

## Core Features
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

## Building From Source

```bash
git clone https://github.com/meduk0/steamguard-cli
cd steamguard-cli
cargo build --release
```

The binary will be available at `target/release/steamguard`.

# Usage
`steamguard-cli` looks for your `maFiles/manifest.json` in at these paths, in this order:

Linux:
- `~/.config/steamguard-cli/maFiles/`
- `~/maFiles/`

Windows:
- `%APPDATA%\steamguard-cli\maFiles\`
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

# HTTP API Server

This fork includes a comprehensive HTTP API server for remote confirmation management. Perfect for automation, browser extensions, CI/CD pipelines, or any application that needs to interact with Steam confirmations programmatically.

## Starting the Server

```bash
# Start server on default port 3030
steamguard server

# Start server on custom port
steamguard server --port 8080

# Start server for specific account
steamguard -u <username> server --port 3030

# Start server for all accounts
steamguard --all server --port 3030
```

## API Endpoints

### Health Check
- **GET** `/health`
- Returns server status
- **Response**: `{"success": true, "message": "Server is running", "data": null}`

### List Confirmations
- **GET** `/confirmations`
- Lists all pending confirmations across all accounts
- **Response**: 
```json
{
  "success": true,
  "message": "Found 2 confirmations",
  "data": [
    {
      "id": "12345678901234567",
      "creator_id": "987654321",
      "headline": "Confirm Trade",
      "summary": "Trade with SomeUser",
      "conf_type": "Trade"
    }
  ]
}
```

### Accept Confirmations
- **POST** `/confirm`
- Accepts confirmations based on action type
- **Request Body**:
```json
{
  "action": "latest|trade|all",
  "trade_offer_id": "optional_trade_id"
}
```

### Decline Confirmations
- **POST** `/decline`
- Declines confirmations based on action type
- **Request Body**:
```json
{
  "action": "latest|trade|all", 
  "trade_offer_id": "optional_trade_id"
}
```

## API Usage Examples

### Health Check
```bash
curl http://localhost:3030/health
```

### List All Confirmations
```bash
curl http://localhost:3030/confirmations
```

### Accept Confirmations

#### Accept Latest Confirmation
```bash
curl -X POST http://localhost:3030/confirm \
  -H "Content-Type: application/json" \
  -d '{"action": "latest"}'
```

#### Accept Specific Trade Offer
```bash
curl -X POST http://localhost:3030/confirm \
  -H "Content-Type: application/json" \
  -d '{"action": "trade", "trade_offer_id": "123456789"}'
```

#### Accept All Confirmations
```bash
curl -X POST http://localhost:3030/confirm \
  -H "Content-Type: application/json" \
  -d '{"action": "all"}'
```

### Decline Confirmations

#### Decline Latest Confirmation
```bash
curl -X POST http://localhost:3030/decline \
  -H "Content-Type: application/json" \
  -d '{"action": "latest"}'
```

#### Decline Specific Trade Offer
```bash
curl -X POST http://localhost:3030/decline \
  -H "Content-Type: application/json" \
  -d '{"action": "trade", "trade_offer_id": "123456789"}'
```

#### Decline All Confirmations
```bash
curl -X POST http://localhost:3030/decline \
  -H "Content-Type: application/json" \
  -d '{"action": "all"}'
```

## API Response Format

All API endpoints return responses in the following format:

```json
{
  "success": boolean,
  "message": "string description",
  "data": null | object | array
}
```

### Success Response Example
```json
{
  "success": true,
  "message": "Successfully executed latest action",
  "data": null
}
```

### Error Response Example
```json
{
  "success": false,
  "message": "Failed to execute command: Invalid tokens - re-login required",
  "data": null
}
```

## CORS Support

The API server includes CORS headers for browser-based applications:
- Allows any origin
- Supports `GET`, `POST`, `OPTIONS` methods
- Accepts `content-type` header

## CLI Decline Command

Enhanced decline functionality is also available via CLI:

```bash
# Decline latest confirmation
steamguard decline --latest

# Decline specific trade offer  
steamguard decline --trade-offer-id 123456789

# Decline all confirmations
steamguard decline --decline-all

# Decline with fail-fast (exit on first error)
steamguard decline --latest --fail-fast

# Decline for specific account
steamguard -u <username> decline --latest

# Decline for all accounts
steamguard --all decline --latest
```

## Error Handling & Retry Logic

Both the HTTP API and CLI decline functionality include robust error handling:

- **Automatic retries** for network failures (up to 3 attempts)
- **Exponential backoff** between retry attempts
- **Token refresh** handling for expired sessions
- **Detailed error logging** for debugging
- **Graceful degradation** for partial failures

# Contributing

Contributions are welcome! This fork focuses on enhancing the HTTP API capabilities and improving confirmation management features.

## Areas for Contribution
- Additional API endpoints
- Enhanced error handling
- Performance improvements
- Documentation improvements
- Testing coverage

# License

`steamguard-cli`, the command line program is licensed under GPLv3.

`steamguard`, the library that is used by `steamguard-cli` is dual licensed under MIT or Apache 2.0, at your option.

# Fork Information

This is an enhanced fork of the original steamguard-cli with focus on:
- Comprehensive HTTP API server
- Enhanced decline functionality with robust retry logic
- Better error handling and logging
- CORS support for web applications
