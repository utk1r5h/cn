# ProofDrop

ProofDrop is a small client-server file-submission system for a Computer Networks lab. It demonstrates how a file can be sent over TCP in numbered chunks, resumed after a broken connection, checked for corruption, encrypted in transit, and accompanied by a verifiable signed receipt.

The project is intentionally a command-line prototype. Its code is split into small modules so each networking and security idea can be explained independently during a demo or viva.

## What the project does

1. The client computes the file's SHA-256 hash and divides the file into chunks (256 KiB by default).
2. The client and server perform an ephemeral X25519 Diffie-Hellman exchange. The server signs the exchange with its RSA identity key. The client checks that signature using a trusted copy of the server's public key.
3. Both sides derive separate client-to-server and server-to-client keys. Each application message is encrypted and authenticated with AES-GCM.
4. The client asks the server to start an upload. The server stores the upload metadata and replies with the indexes of chunks it has not stored yet.
5. The client sends only missing chunks. The server checks each chunk's length and SHA-256 hash, writes it to disk, and records it in SQLite.
6. When every chunk is present, the server joins the chunks in index order and compares the completed file's SHA-256 hash with the client's original hash.
7. If the hashes match, the server saves the submission and returns a receipt containing the upload ID, filename, size, hash, timestamp, and accepted status. The server signs the receipt with RSA. The client verifies that signature and saves the receipt as JSON.

To resume, run the same upload command again with the same local state database. The client reuses the upload ID, reconnects, and asks which chunks are missing. The server's SQLite database and chunk files survive server restarts.

## Requirements

- Python 3.10 or newer
- The `cryptography` Python package (listed in `requirements.txt`)
- Two terminals for the local demonstration

## Setup

From the project directory, create a virtual environment and install the one dependency:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1` instead.

Generate the server's long-term identity keys:

```sh
python -m proofdrop keygen
```

This creates `keys/server_private.pem` and `keys/server_public.pem`. The private key stays on the server. The public key is the client's trust anchor: copy it to each client machine through a trusted channel. For the local demo, both commands use the same `keys` directory.

## Run locally

In terminal 1, start the server:

```sh
python -m proofdrop server --host 127.0.0.1 --port 5050
```

In terminal 2, make a sample file and upload it:

```sh
python -c "from pathlib import Path; Path('sample.bin').write_bytes(bytes(range(256)) * 5000)"
python -m proofdrop upload sample.bin --host 127.0.0.1 --port 5050
```

The client prints progress and the verified receipt. It saves a copy in `.proofdrop/receipts/<upload-id>.json`. The server stores the received file under `server_data/submissions/` and its metadata under `server_data/proofdrop_server.sqlite3`.

Verify the saved receipt later:

```sh
python -m proofdrop verify .proofdrop/receipts/<upload-id>.json --server-key keys/server_public.pem
```

For a test over a LAN, set the server's `--host` to its LAN interface (or `0.0.0.0`) and use that machine's reachable IP in the client command. Make sure the selected TCP port is reachable through the lab network firewall. Use a trusted copy of the public key on the client. The default bind is localhost-only.

## Demonstrate resume behavior

1. Start the server and begin uploading a moderately large file.
2. Stop the client with Ctrl+C or disconnect the network while it is sending chunks.
3. Restart the server if desired; its received chunks remain in `server_data/chunks/` and SQLite.
4. Run the exact same upload command again, using the same file and `--state` path.
5. The client prints the count of chunks still to send. Chunks already acknowledged by the server are skipped.

For a more controlled interruption, use a larger file or a smaller `--chunk-size`, such as `--chunk-size 32768`. If a brief socket error occurs, the client also retries up to three connections automatically. Restarting the command is the reliable way to demonstrate persistence after a deliberate interruption.

## Commands and options

- `python -m proofdrop keygen [--dir keys]` creates an RSA-3072 private/public key pair.
- `python -m proofdrop server [--host 127.0.0.1] [--port 5050] [--data server_data] [--private-key keys/server_private.pem]` starts the threaded TCP server.
- `python -m proofdrop upload FILE [--host HOST] [--port PORT] [--chunk-size BYTES] [--server-key PATH] [--state PATH]` uploads or resumes a file. Chunk sizes from 1 byte through 2 MiB are accepted.
- `python -m proofdrop verify RECEIPT.json [--server-key PATH]` verifies a saved receipt signature.

The upload ID is kept in the client's local SQLite state, keyed by server address, source file path, and file hash. Changing the file contents creates a new upload ID. The client recalculates the full hash on each run so it can detect local file changes.

## Project files

### `proofdrop/__init__.py`

Marks `proofdrop` as a Python package and defines its version. It contains no networking behavior.

### `proofdrop/__main__.py`

Implements the top-level `python -m proofdrop` command. It parses the four subcommands (`keygen`, `server`, `upload`, and `verify`) and passes the options to the relevant module. Keeping a single entry point gives the demo consistent command names.

### `proofdrop/protocol.py`

Contains the wire-level building blocks. TCP is a byte stream, so `send_frame`, `recv_frame`, and `recv_exact` add and read a four-byte network-order message length; they do not assume one `recv()` call equals one message. The handshake creates fresh X25519 keys per connection and signs the two ephemeral public keys with the server's RSA key. After the client verifies the signature against its pinned RSA public key, both sides derive 64 bytes with HKDF-SHA-256. The first half encrypts client-to-server messages and the second half encrypts server-to-client messages. `SecureChannel` encrypts JSON messages with AES-GCM and uses a distinct increasing nonce counter for each direction.

This file also loads and creates PEM-encoded RSA keys. The private key is written with owner-only permissions where the operating system supports them.

### `proofdrop/client.py`

Implements file hashing, persistent client upload IDs, and the upload loop. It opens a TCP connection, authenticates the server, asks for the missing chunk indexes, seeks to each missing chunk in the local file, and waits for an acknowledgement before advancing. On common network errors it reconnects up to three times; every new connection requests the missing list again. After finalization it verifies the receipt and stores both its signed fields and signature as JSON.

The local state database is only a resume convenience. The server database is the authoritative record of which chunks it has accepted.

### `proofdrop/server.py`

Runs a `ThreadingTCPServer`, allowing multiple client connections to be handled by separate threads. Each connection performs the handshake, receives upload metadata, returns the missing indexes, accepts chunk messages, and finalizes the file. Errors after the handshake are returned inside the encrypted channel. The server's default network binding is `127.0.0.1` so it is local-only unless explicitly configured otherwise.

### `proofdrop/storage.py`

Owns persistent server state. SQLite stores one upload row and one row per accepted chunk. The binary chunk contents are stored separately in `server_data/chunks/<upload-id>/`. Chunk writes use a temporary file followed by an atomic rename, then record the verified chunk in SQLite. When a client resumes, the server rechecks that recorded chunk files still exist and match their stored hashes; missing or damaged chunks are requested again. Finalization reads chunks by index, computes the full-file SHA-256 while assembling them, and only moves the completed file into `server_data/submissions/` if both size and hash match. A lock serializes storage operations in this single-process prototype.

### `proofdrop/receipts.py`

Defines deterministic JSON serialization for the receipt fields, signs them with RSA-PSS/SHA-256 on the server side, and verifies a saved receipt with the public key. Deterministic serialization matters: the verifier must hash exactly the same bytes that the signer hashed.

### `requirements.txt`

Lists the single external library. Python's built-in modules provide TCP sockets, SQLite, JSON, file operations, and SHA-256; `cryptography` supplies maintained X25519, HKDF, AES-GCM, RSA-PSS, and PEM key handling.

### `.gitignore`

Keeps virtual environments, Python bytecode, runtime databases, server submissions, local resume state, and generated private keys out of version control. The private key should never be committed or sent to clients.

## Protocol summary

Each TCP message is encoded as a 4-byte big-endian length followed by that many bytes. The two handshake messages are JSON in this framing; after the key exchange, all messages use the same framing but their contents are AES-GCM ciphertext. Encrypted JSON messages have these application actions:

| Direction | Message | Purpose |
| --- | --- | --- |
| Client to server | `start` | Provide upload ID, filename, size, chunk size, total chunks, and full SHA-256 |
| Server to client | `ready` | Return indexes missing from persistent server storage |
| Client to server | `chunk` | Send one indexed chunk, its SHA-256, and base64-encoded bytes |
| Server to client | `chunk_ack` | Confirm that chunk bytes were checked and stored |
| Client to server | `finalize` | Ask the server to assemble and verify the file |
| Server to client | `receipt` | Return accepted receipt fields and RSA signature |

## Cryptography and integrity in plain language

- **X25519 Diffie-Hellman:** each connection creates temporary public/private key pairs. The shared secret is never sent over the network.
- **RSA signature on the handshake:** the server proves that it owns the private key corresponding to the public key the client trusts. Signing both ephemeral keys prevents an attacker from silently replacing the exchange.
- **HKDF-SHA-256:** turns the shared secret into independent keys for each direction of communication.
- **AES-GCM:** encrypts each application message and detects if ciphertext or authenticated data was changed.
- **Chunk SHA-256:** checks each chunk before the server records it.
- **Whole-file SHA-256:** confirms the reconstructed file is byte-for-byte consistent with the file hash sent at the start.
- **Signed receipt:** provides evidence that the holder of the server's private key issued those receipt fields. Anyone with the trusted public key can check that signature.

## Viva talking points

**Why use TCP?** TCP provides an ordered reliable byte stream while a connection exists. The application still needs its own framing because TCP does not preserve message boundaries. The upload protocol adds chunk indexes and acknowledgements so the application can resume across separate TCP connections.

**How does resumption work?** Every chunk has a stable index. After reconnecting, the client asks for the server's missing indexes and transmits only those. The server's database records acknowledgements durably, so a server restart does not erase progress.

**Why hash chunks and then hash the whole file?** A chunk hash detects a damaged or mismatched chunk when it arrives. The whole-file hash checks that all accepted chunks, in the right order, reconstruct the original file.

**What is the role of AES-GCM?** It gives confidentiality and message integrity for application messages. Its authentication tag causes modified ciphertext to fail decryption.

**Why sign the handshake and receipt?** The signature authenticates the server's ephemeral key exchange and lets a recipient verify that the receipt fields came from the server key holder. Encryption alone would not establish the server's identity.

**Does the receipt prove which student uploaded the file?** No. This prototype authenticates the server and protects the session, but it does not log in or cryptographically authenticate individual students. A real deployment would need user accounts or client certificates and access control. The receipt proves server acceptance of a file hash and metadata, not a real-world person's identity.

**Can this replace HTTPS or a production submission service?** No. It is a lab prototype for explaining sockets and protocol components. It has no account system, rate limiting, quotas, formal protocol audit, key rotation, or production-grade operational controls. The server private key is unencrypted on disk, and the server must be configured to bind to a network interface for LAN use.

## Wireshark demonstration

Capture traffic on the loopback or lab interface while uploading. You can identify the TCP connection and observe message lengths and timing. After the key exchange, application payloads are encrypted ciphertext, so filenames and file contents should not appear as readable protocol data. The unencrypted handshake includes ephemeral public keys and a signature; it does not contain the file content or the shared secret. Use loopback capture support or a LAN interface appropriate to your operating system.

## Notes and limitations

- This is an educational prototype, not a production secure file-transfer protocol.
- The public key must be delivered to clients through a trusted channel. Accepting an arbitrary key from the network would defeat server authentication.
- Client identity is not authenticated. The lab can extend the protocol with student login or client certificates as a future improvement.
- The server trusts the configured storage directory and does not implement quotas or automatic cleanup of incomplete uploads.
- Files are buffered as base64 inside each encrypted JSON message, so the 2 MiB maximum chunk size favors code clarity over throughput.
- A changed source file receives a new upload ID because its SHA-256 hash changes. Old partial server uploads are retained for inspection and can be manually removed from the data directory when the server is stopped.
