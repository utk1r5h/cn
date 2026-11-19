"""Top-level command dispatcher for ProofDrop."""

from __future__ import annotations

import argparse
import json
import os

from .client import add_arguments as add_upload_arguments
from .client import upload
from .protocol import generate_server_keys
from .receipts import verify_receipt
from .server import serve
from .storage import UploadStore
from .web import serve_dashboard


def main() -> None:
    parser = argparse.ArgumentParser(prog="proofdrop", description="TCP chunked file transfer for a Computer Networks lab")
    commands = parser.add_subparsers(dest="command", required=True)

    keys = commands.add_parser("keygen", help="Create the server RSA private and public keys")
    keys.add_argument("--dir", default="keys")

    server = commands.add_parser("server", help="Start the TCP upload server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=5050)
    server.add_argument("--data", default="server_data")
    server.add_argument("--private-key", default="keys/server_private.pem")

    client = commands.add_parser("upload", help="Upload or resume over TCP and compare application ACK windows")
    add_upload_arguments(client)

    verify = commands.add_parser("verify", help="Verify a saved signed receipt")
    verify.add_argument("receipt", help="JSON receipt saved by the upload command")
    verify.add_argument("--server-key", default="keys/server_public.pem")

    status = commands.add_parser("status", help="Display saved and in-progress uploads on the server")
    status.add_argument("--data", default="server_data", help="Server data directory")

    web = commands.add_parser("web", help="Start the browser upload and TCP frame dashboard")
    web.add_argument("--web-host", default="127.0.0.1")
    web.add_argument("--web-port", type=int, default=8080)
    web.add_argument("--tcp-host", default="127.0.0.1", help="Host where the ProofDrop TCP server is listening")
    web.add_argument("--tcp-port", type=int, default=5050)
    web.add_argument("--server-key", default="keys/server_public.pem")
    web.add_argument("--state", default=".proofdrop/web_client_state.sqlite3")
    web.add_argument("--inbox", default=".proofdrop/web_inbox")

    args = parser.parse_args()
    if args.command == "keygen":
        private_path, public_path = generate_server_keys(args.dir)
        print(f"Created server private key: {private_path}")
        print(f"Created public key to copy to clients: {public_path}")
    elif args.command == "server":
        serve(args.host, args.port, args.data, args.private_key)
    elif args.command == "upload":
        if not 1 <= args.chunk_size <= 2 * 1024 * 1024:
            parser.error("--chunk-size must be between 1 and 2097152")
        if not 1 <= args.window_size <= 64:
            parser.error("--window-size must be between 1 and 64")
        if not 0 <= args.demo_rtt_ms <= 1000:
            parser.error("--demo-rtt-ms must be between 0 and 1000")
        result = upload(
            args.file, args.host, args.port, args.chunk_size, args.server_key,
            args.state, args.window_size, args.demo_rtt_ms,
        )
        receipt = result["receipt"]
        receipt_path = os.path.join(os.path.dirname(os.path.abspath(args.state)), "receipts", f"{receipt['upload_id']}.json")
        print("\nSubmission accepted")
        print(f"  ID:      {receipt['upload_id']}")
        print(f"  File:    {receipt['filename']}")
        print(f"  Size:    {receipt['size']} bytes")
        print(f"  SHA-256: {receipt['sha256']}")
        print(f"  Time:    {receipt['received_at']}")
        print("  Signed receipt verified with the pinned server public key.")
        print(f"  Saved:   {receipt_path}")
    elif args.command == "status":
        rows = UploadStore(args.data).status_rows()
        if not rows:
            print("No uploads found.")
            return
        print(f"Uploads in {args.data} (stored chunks are server acknowledgements):")
        for row in rows:
            print(
                f"{row['status']:8} {row['upload_id']}  {row['filename']}  "
                f"{row['stored_chunks']}/{row['total_chunks']} chunks  "
                f"{row['stored_bytes']}/{row['size']} bytes  created {row['created_at']}"
            )
    elif args.command == "web":
        serve_dashboard(
            web_host=args.web_host,
            web_port=args.web_port,
            tcp_host=args.tcp_host,
            tcp_port=args.tcp_port,
            server_key=args.server_key,
            state_path=args.state,
            inbox=args.inbox,
        )
    else:
        with open(args.receipt, encoding="utf-8") as receipt_file:
            saved = json.load(receipt_file)
        verify_receipt(saved["receipt"], saved["signature"], args.server_key)
        print(f"Valid signature for accepted upload {saved['receipt']['upload_id']}")


if __name__ == "__main__":
    main()
