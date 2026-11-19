"""Command-line uploader that resumes from server-acknowledged chunks."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import socket
import time
import uuid
from contextlib import closing

from .protocol import client_handshake, load_public_key

DEFAULT_CHUNK_SIZE = 256 * 1024


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while part := stream.read(1024 * 1024):
            digest.update(part)
    return digest.hexdigest()


def state_upload_id(state_path: str, remote: str, path: str, digest: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
    with closing(sqlite3.connect(state_path)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS client_uploads (remote TEXT, source_path TEXT, sha256 TEXT, upload_id TEXT, PRIMARY KEY(remote,source_path,sha256))")
        row = db.execute(
            "SELECT upload_id FROM client_uploads WHERE remote=? AND source_path=? AND sha256=?",
            (remote, path, digest),
        ).fetchone()
        if row:
            return row[0]
        upload_id = str(uuid.uuid4())
        db.execute("INSERT INTO client_uploads VALUES(?,?,?,?)", (remote, path, digest, upload_id))
        return upload_id


def upload(
    path: str,
    host: str,
    port: int,
    chunk_size: int,
    public_key_path: str,
    state_path: str,
    window_size: int = 1,
    demo_rtt_ms: int = 0,
) -> dict:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Not a regular file: {path}")
    size = os.path.getsize(path)
    digest = sha256_file(path)
    total_chunks = (size + chunk_size - 1) // chunk_size
    remote = f"{host}:{port}"
    upload_id = state_upload_id(state_path, remote, path, digest)
    public_key = load_public_key(public_key_path)
    metadata = {
        "action": "start",
        "upload_id": upload_id,
        "filename": os.path.basename(path),
        "size": size,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "sha256": digest,
    }
    transfer_started = time.monotonic()
    wire_bytes_sent = 0
    acknowledged_bytes = 0
    acknowledged_chunks = 0
    ack_times = []
    already_stored_chunks = 0

    # If a connection drops, reconnect and ask the server which chunks remain.
    for attempt in range(1, 4):
        try:
            with socket.create_connection((host, port), timeout=15) as sock:
                sock.settimeout(60)
                channel = client_handshake(sock, public_key)
                channel.send(metadata)
                ready = channel.receive()
                if ready.get("type") == "error":
                    raise ValueError(ready.get("message", "Server rejected upload"))
                if ready.get("type") != "ready":
                    raise ValueError("Unexpected server response")
                missing = ready.get("missing", [])
                already_stored_chunks = total_chunks - len(missing)
                print(
                    f"Upload {upload_id}: {size} bytes, {total_chunks} chunks; "
                    f"{len(missing)} to send (application window {window_size})"
                )
                with open(path, "rb") as stream:
                    for batch_start in range(0, len(missing), window_size):
                        batch = missing[batch_start:batch_start + window_size]
                        outstanding = {}
                        for index in batch:
                            stream.seek(index * chunk_size)
                            data = stream.read(chunk_size)
                            send_started = time.monotonic()
                            channel.send({
                                "action": "chunk",
                                "upload_id": upload_id,
                                "index": index,
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "data": base64.b64encode(data).decode("ascii"),
                            })
                            wire_bytes_sent += len(data)
                            outstanding[index] = (len(data), send_started)

                        # This optional wait is a teaching aid: one delay per ACK
                        # batch makes the effect of RTT and window size visible.
                        if demo_rtt_ms:
                            time.sleep(demo_rtt_ms / 1000)

                        for _ in batch:
                            ack = channel.receive()
                            if ack.get("type") == "error":
                                raise ValueError(ack.get("message", "Server rejected a chunk"))
                            index = ack.get("index")
                            if ack.get("type") != "chunk_ack" or index not in outstanding:
                                raise ValueError("Server acknowledged an unexpected chunk")
                            data_size, send_started = outstanding.pop(index)
                            ack_times.append(time.monotonic() - send_started)
                            acknowledged_bytes += data_size
                            acknowledged_chunks += 1
                            print(f"  ACK for chunk {index + 1}/{total_chunks}")
                channel.send({"action": "finalize", "upload_id": upload_id})
                response = channel.receive()
                if response.get("type") == "error":
                    raise ValueError(response.get("message", "Server could not finalize upload"))
                if response.get("type") != "receipt":
                    raise ValueError("Server did not return a signed receipt")
                from .receipts import verify_receipt
                verify_receipt(response["receipt"], response["signature"], public_key_path)
                receipt_directory = os.path.join(os.path.dirname(os.path.abspath(state_path)), "receipts")
                os.makedirs(receipt_directory, exist_ok=True)
                receipt_path = os.path.join(receipt_directory, f"{upload_id}.json")
                with open(receipt_path, "w", encoding="utf-8") as receipt_file:
                    json.dump(response, receipt_file, indent=2, sort_keys=True)
                elapsed = max(time.monotonic() - transfer_started, 0.000001)
                throughput = wire_bytes_sent / elapsed
                average_ack = sum(ack_times) / len(ack_times) if ack_times else None
                print("\nTransfer summary")
                print(f"  Chunks acknowledged this run: {acknowledged_chunks}")
                print(f"  Chunks already stored:        {already_stored_chunks}")
                print(f"  File bytes acknowledged:      {acknowledged_bytes}")
                print(f"  File bytes sent this run:     {wire_bytes_sent}")
                print(f"  Elapsed transfer time:        {elapsed:.3f} s")
                print(f"  File-data throughput:         {throughput / (1024 * 1024):.3f} MiB/s")
                print(f"  Application ACK window:      {window_size} chunk(s)")
                if demo_rtt_ms:
                    print(f"  Teaching RTT wait per batch: {demo_rtt_ms} ms")
                if average_ack is not None:
                    print(f"  Mean chunk ACK time:          {average_ack * 1000:.2f} ms (network + server processing + teaching wait)")
                else:
                    print("  Mean chunk ACK time:          n/a (all chunks were already stored)")
                return {"receipt": response["receipt"], "signature": response["signature"]}
        except (ConnectionError, TimeoutError, socket.timeout, OSError):
            if attempt == 3:
                raise
            delay = attempt
            print(f"Connection interrupted; reconnecting in {delay}s and resuming from stored chunks...")
            time.sleep(delay)
    raise RuntimeError("Upload did not complete")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file", help="Path to the file to submit")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Bytes per chunk (max 2097152)")
    parser.add_argument("--window-size", type=int, default=1, help="Maximum chunks sent before waiting for ACKs (1=stop-and-wait, max 64)")
    parser.add_argument("--demo-rtt-ms", type=int, default=0, help="Optional teaching delay per ACK batch, in milliseconds")
    parser.add_argument("--server-key", default="keys/server_public.pem", help="Pinned server public key used for authentication and receipt verification")
    parser.add_argument("--state", default=".proofdrop/client_state.sqlite3", help="Local resume-state database")


def main() -> None:
    parser = argparse.ArgumentParser(description="Transfer or resume a file over TCP with ProofDrop")
    add_arguments(parser)
    args = parser.parse_args()
    if not 1 <= args.chunk_size <= 2 * 1024 * 1024:
        parser.error("--chunk-size must be between 1 and 2097152")
    if not 1 <= args.window_size <= 64:
        parser.error("--window-size must be between 1 and 64")
    if not 0 <= args.demo_rtt_ms <= 1000:
        parser.error("--demo-rtt-ms must be between 0 and 1000")
    result = upload(args.file, args.host, args.port, args.chunk_size, args.server_key, args.state, args.window_size, args.demo_rtt_ms)
    receipt = result["receipt"]
    print("\nSubmission accepted")
    print(f"  ID:      {receipt['upload_id']}")
    print(f"  File:    {receipt['filename']}")
    print(f"  Size:    {receipt['size']} bytes")
    print(f"  SHA-256: {receipt['sha256']}")
    print(f"  Time:    {receipt['received_at']}")
    print("  Signed receipt verified with the pinned server public key.")
    print(f"  Saved:   {os.path.join(os.path.dirname(os.path.abspath(args.state)), 'receipts', receipt['upload_id'] + '.json')}")


if __name__ == "__main__":
    main()
