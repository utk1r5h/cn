# ProofDrop: Resumable File Transfer over TCP

ProofDrop is a small Computer Networks lab project. It demonstrates how an application can send a file over a TCP connection, divide the file into numbered chunks, acknowledge stored chunks, resume after a disconnect, and measure how acknowledgement delay affects transfer throughput.

The main lab topics are **TCP sockets, byte-stream framing, application acknowledgements, stop-and-wait, a bounded sliding window, retransmission after reconnect, throughput, and client-server communication**. Cryptography is included to protect the submitted file and authenticate the server. The signed receipt is a normal server response; this project has no blockchain, blocks, consensus, mining, or distributed ledger.

## What you can demonstrate

1. Start a TCP server and submit a file from a client.
2. Change the chunk size and observe the application-level chunk acknowledgements.
3. Compare stop-and-wait (`--window-size 1`) with a bounded window (`--window-size 8`). An optional teaching delay makes the effect of waiting for acknowledgements easy to see on localhost.
4. Interrupt an upload and resume it. The client asks the server for missing chunk indexes and skips chunks that the server already stored.
5. Inspect the server's chunk counts with the `status` command.
6. View the TCP connection, TCP sequence numbers, TCP acknowledgements, and traffic timing in Wireshark.
7. Check that the server reassembles chunks in order, verifies SHA-256, and issues a signed receipt.

## How the transfer works

```text
Client                                      Server
  |---- TCP connect -------------------------->|
  |<--- signed key exchange ------------------|
  |---- start(file info, chunk count) -------->|
  |<--- missing chunk indexes ----------------|
  |---- chunk 0, chunk 1 ... (bounded window)->|
  |<--- application ACKs for stored chunks ----|
  |---- finalize ----------------------------->|
  |<--- accepted receipt + signature ----------|
```

The application divides a file into chunks. Every chunk has an index, so the receiver can put it back in the right place. The server acknowledges a chunk after checking and storing it. The client can send one chunk and wait (`window-size 1`) or send a small group before waiting (`window-size 8`). This is a simple application-level stop-and-wait/sliding-window comparison.

TCP itself is still responsible for reliable, ordered delivery of bytes within each connection. The application chunk acknowledgements serve a different purpose: they record which pieces have been durably stored so the upload can continue on a new connection after the old one ends. TCP packets/segments and ProofDrop file chunks are different things; TCP may split or combine application data however it chooses.

## Computer Networks concepts in the code

| CN concept | How ProofDrop demonstrates it |
| --- | --- |
| Client-server model | A TCP client connects to a threaded server listening on a host and port. |
| TCP sockets | Python's `socket` and `socketserver` APIs carry the byte stream. |
| TCP is a byte stream | A 4-byte length prefix frames each application message. `recv_exact` handles partial reads. |
| Application protocol | `start`, `ready`, `chunk`, `chunk_ack`, `finalize`, and `receipt` messages define the exchange. |
| Sequence/order | Each file chunk has an index; the server reassembles by index. |
| Stop-and-wait | `--window-size 1` sends one chunk, then waits for its application ACK. |
| Bounded window | A larger `--window-size` sends a group of chunks before reading their ACKs. This shows how pipelining can use a delayed path better. |
| Acknowledgement and recovery | The server records acknowledged chunk indexes. After reconnect, the client sends only missing indexes. |
| Throughput and delay | The client reports file-data throughput and mean application ACK time. An optional teaching wait makes the window comparison visible locally. |
| Concurrent clients | The threaded server can handle separate client connections at the same time. |
| Integrity | Per-chunk and whole-file SHA-256 checks catch inconsistent data or incorrect reassembly. |
| Protocol security | X25519 key exchange, AES-GCM message protection, and a signed server receipt protect the session and provide server-origin evidence. |

**Layering note:** the application window is a teaching example, not TCP's congestion window. TCP's own flow control, congestion control, segmentation, retransmission, and packet acknowledgements remain inside the operating system. The `--demo-rtt-ms` option adds a deliberate application wait once per chunk batch; it is not a real network emulator and should not be presented as a measured physical RTT.

## Setup

Requirements: Python 3.10 or newer and the `cryptography` package.

```sh
cd /Users/utkarshshukla/Downloads/cn_lab_proj
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

Generate the server keys once:

```sh
python -m proofdrop keygen
```

The private key remains on the server in `keys/server_private.pem`. The client uses `keys/server_public.pem` to authenticate the server. Do not run `keygen` again for an existing server unless you intend to replace its identity key.

## Viva demo A: stop-and-wait versus a window

Use two terminal windows. In terminal 1, start the server and leave it running:

```sh
cd /Users/utkarshshukla/Downloads/cn_lab_proj
source .venv/bin/activate
python -m proofdrop server --host 127.0.0.1 --port 5051
```

In terminal 2, create a repeatable 1.25 MiB sample file (1,310,720 bytes):

```sh
cd /Users/utkarshshukla/Downloads/cn_lab_proj
source .venv/bin/activate
python -c "from pathlib import Path; Path('sample.bin').write_bytes(bytes(range(256)) * 5120)"
```

Run stop-and-wait with a small chunk and a 20 ms teaching wait per ACK batch:

```sh
python -m proofdrop upload sample.bin --port 5051 --chunk-size 4096 --window-size 1 --demo-rtt-ms 20 --state .proofdrop/stop_wait.sqlite3
```

Then run the same file with a window of eight. A separate state file gives this run a fresh upload ID, so the chunks are transferred again:

```sh
python -m proofdrop upload sample.bin --port 5051 --chunk-size 4096 --window-size 8 --demo-rtt-ms 20 --state .proofdrop/window8.sqlite3
```

Compare elapsed time, application ACK timing, and file-data throughput in the two summaries. With 320 chunks, the configured teaching wait alone is about 6.4 seconds for window 1 and about 0.8 seconds for window 8. Actual values include local processing and scheduling, so treat them as a demonstration, not a benchmark. Explain that a larger window lets more application data be in flight before the sender waits; TCP still manages the underlying network connection.

## Viva demo B: resume a partial upload

Create a larger sample file:

```sh
python -c "from pathlib import Path; Path('resume_demo.bin').write_bytes(bytes(range(256)) * 16384)"
```

Begin an upload with a small chunk and a short teaching wait:

```sh
python -m proofdrop upload resume_demo.bin --port 5051 --chunk-size 8192 --window-size 1 --demo-rtt-ms 10 --state .proofdrop/resume.sqlite3
```

After several `ACK for chunk` lines, press **Ctrl+C**. Run the exact same command again. The second run should report chunks already stored and send only what remains. You can also stop and restart the server between attempts; its SQLite database and chunk files preserve progress.

Inspect server state at any time from another terminal on the server machine:

```sh
python -m proofdrop status --data server_data
```

`status` displays each upload's state, ID, filename, stored/total chunks, and stored/total bytes. It reads the server's local data directory, so run it on the server machine (or where that directory is available).

## Other commands

```text
python -m proofdrop keygen [--dir keys]
python -m proofdrop server [--host 127.0.0.1] [--port 5050] [--data server_data]
python -m proofdrop upload FILE [--host HOST] [--port PORT] [--chunk-size BYTES]
    [--window-size 1..64] [--demo-rtt-ms 0..1000] [--state PATH]
python -m proofdrop status [--data server_data]
python -m proofdrop verify RECEIPT.json [--server-key keys/server_public.pem]
```

The default chunk size is 256 KiB. The maximum is 2 MiB. The default application window is 1, which is easiest to explain as stop-and-wait. `--demo-rtt-ms` defaults to zero.

## Wireshark demonstration

Capture on loopback while uploading and use the display filter:

```text
tcp.port == 5051
```

Point out the TCP connection, TCP sequence and acknowledgement numbers, segment timing, and changing payload lengths. TCP sequence/ACK numbers are transport-layer behavior. ProofDrop's chunk indexes and `chunk_ack` messages are application-layer behavior. The application payload after key exchange is encrypted, so the file name and chunk JSON are not readable in a packet capture. TCP segmentation does not line up one-to-one with ProofDrop chunks.

For a LAN demo, bind the server to a reachable interface (for example `--host 0.0.0.0`) and connect to that computer's IP address from the client. Keep the server's public key trusted on the client.

## File-by-file guide

### `proofdrop/__init__.py`

Marks the directory as a Python package and defines its version.

### `proofdrop/__main__.py`

Defines the `python -m proofdrop` command. It parses `keygen`, `server`, `upload`, `status`, and `verify`, then dispatches to the relevant module. Argument checks keep the chunk size, window, and teaching delay inside documented limits.

### `proofdrop/client.py`

Hashes the source file, creates or finds its persistent upload ID, opens the TCP connection, authenticates the server, and performs the upload. The chunk loop sends at most `window_size` chunks before it waits for application ACKs. Each ACK is matched to its chunk index. On a network interruption, a new connection asks the server for missing indexes and resumes. The client reports ACK timing and file-data throughput, verifies the server's signed receipt, and saves it under `.proofdrop/receipts/`.

The teaching delay is applied once after each batch is sent and before the client reads its ACKs. It exists to make the effect of waiting visible on a fast local machine; it does not delay real network packets.

### `proofdrop/protocol.py`

Implements TCP message framing and the encrypted channel. `recv_exact` handles TCP splitting a message across reads. Four-byte big-endian length prefixes let the receiver determine where each application message ends. The handshake uses ephemeral X25519 keys, a server RSA signature, and HKDF to derive separate keys for each direction. AES-GCM protects each later message.

### `proofdrop/server.py`

Creates a threaded TCP server. For each client it performs the key exchange, reads upload metadata, returns missing chunk indexes, receives chunk messages, sends application ACKs, and finalizes the upload. Separate client connections can be served by separate threads.

### `proofdrop/storage.py`

Stores upload metadata and acknowledged chunk records in SQLite. Chunk bytes live under `server_data/chunks/`; accepted completed files live under `server_data/submissions/`. It checks each chunk, rechecks saved chunks on resume, and reassembles them by index before comparing the full-file hash. `status_rows` supplies the `status` command with stored chunk and byte totals.

### `proofdrop/receipts.py`

Serializes receipt fields consistently, signs them with RSA-PSS/SHA-256, and verifies the signature using the server's public key. This is a signed server receipt, not a blockchain transaction or ledger entry.

### `requirements.txt`

Lists the only third-party dependency, `cryptography`. TCP, SQLite, JSON, file operations, threading, and SHA-256 use Python's standard library.

### `.gitignore`

Excludes the virtual environment, Python bytecode, local state, server data, and generated keys. The server private key should not be committed or distributed to clients.

## Viva questions and short answers

**Why use TCP?** It provides a reliable, ordered byte stream between the client and server. The application still adds framing because TCP does not preserve message boundaries.

**Why split a file into chunks if TCP is reliable?** TCP handles delivery during one connection. Chunks let the application save progress durably and resume the file across a new connection after a disconnect.

**Are ProofDrop chunks TCP packets?** No. They are application-level pieces. TCP can divide one chunk among several segments or carry data from multiple chunks in its stream.

**What does the window comparison show?** Window 1 waits for each application ACK before sending the next chunk. A larger bounded window sends several chunks before waiting. This makes an artificial ACK delay cost fewer wait rounds. It is not a replacement for TCP congestion control.

**What is measured as throughput?** File bytes sent by the client divided by elapsed transfer time. It is application payload throughput, not raw link bandwidth; it includes connection and server processing time.

**Is the displayed ACK time a pure RTT?** No. It is the time from sending an application chunk to receiving its application ACK, including network delay and server processing. When the demo wait is enabled, it includes that wait too.

**Why are both chunk and whole-file hashes checked?** A chunk hash checks each piece at receipt. The whole-file hash checks that ordered reassembly matches the original file.

**What does the receipt prove?** It shows that the server key holder signed the listed upload ID, hash, size, filename, and acceptance time. It does not identify a student; client login is outside this prototype.

**Where is the blockchain?** There is none. SQLite stores ordinary upload and chunk rows. A hash and signed receipt support integrity and server acknowledgement, but there are no blocks, chain links, consensus, or distributed ledger.

## Scope and limitations

- This is an educational prototype, not a production file-transfer service.
- The application window is intentionally simple and does not implement TCP congestion control; the operating system's TCP stack does that.
- The demo RTT wait is a repeatable teaching knob, not a packet-level network simulator or substitute for a real LAN/WAN measurement.
- The server authenticates itself to the client. The project does not authenticate individual student accounts.
- The server has no quotas, rate limits, or automatic cleanup for abandoned partial uploads.
- Chunks are base64 encoded inside JSON for readability, so this favors simple explanation over maximum speed.
