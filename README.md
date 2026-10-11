# kpn-filetransfer-mcp

An unofficial [MCP](https://modelcontextprotocol.io) server for [KPN Secure File Transfer](https://filetransfer.kpn.com). It lets an MCP client inspect, download and create end-to-end encrypted transfers.

**Not affiliated with or endorsed by KPN.** KPN publishes no API for this service. The client is built from KPN's public [technical whitepaper](https://filetransfer.kpn.com/assets/pdfs/whitepaper.pdf) and from the requests the web app itself makes. The whitepaper is partly out of date (see below), so the web app's behaviour is the reference. The API can change without notice. Check KPN's terms of use before relying on this.

## Tools

| Tool | What it does |
|---|---|
| `inspect_transfer` | Lists files, sizes, expiry and remaining downloads. Consumes no download. |
| `download_transfer` | Downloads and decrypts every file into a directory. **Consumes one download** from the sender's limit, only after every file is written and authenticated. |
| `create_transfer` | Encrypts local files client-side, uploads them, returns the share link. Optional password. |

## Run

```
bun install
bun run src/server.ts          # stdio transport
claude mcp add kpn-filetransfer -- bun run /path/to/src/server.ts
```

## Safety

- File reads (uploads) and writes (downloads) are confined to `KPN_FT_ALLOWED_ROOTS` (colon-separated; default `~/Downloads/kpn-filetransfer`). Symlinks and `..` are resolved before the check.
- The share link contains the decryption key in its `#fragment`, and passwords are passed as tool arguments. Both are visible to the model and to any transcript. Treat them as secrets and send passwords over a different channel than the link.
- Do not retry a successful `download_transfer`: a retry spends another download.

## Protocol notes

Verified against the live service, in both directions with the official web app (port upload to browser download, and browser upload to port download, including a password containing non-ASCII characters):

- Files are split into 16 MB chunks. Each chunk's key material is `SHA-256(SHA-256(plaintext) || SHA-256(random))`.
- Key and IV come from HKDF-SHA-256 with an 8-byte zero salt and info `"fileEncryptionKey"` and `"iv"` (12 bytes). The whitepaper's salt and info strings are wrong.
- AES-256-GCM with a 128-bit tag and a one-byte zero additional-data value.
- Keys are URL-safe Base64 with `=` replaced by `.`.
- The password header is `SHA-256(be32(256) || manifestKey || be32(288) || transferId || be32(8 * password.length) || password)`. The length counts UTF-16 code units, not UTF-8 bytes. The upload value is a second SHA-256 of that hash.

## Not tested

Files over 16 MB (multi-chunk upload), deleting a transfer (no endpoint found), and the wrong-password path.

## Development

```
bun test
```
