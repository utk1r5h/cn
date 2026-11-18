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


def main() -> None:
    parser = argparse.ArgumentParser(prog="proofdrop", description="Resumable, encrypted file submission demo")
    commands = parser.add_subparsers(dest="command", required=True)

    keys = commands.add_parser("keygen", help="Create the server RSA private and public keys")
    keys.add_argument("--dir", default="keys")

    server = commands.add_parser("server", help="Start the TCP upload server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=5050)
    server.add_argument("--data", default="server_data")
    server.add_argument("--private-key", default="keys/server_private.pem")

    client = commands.add_parser("upload", help="Submit a file or resume an interrupted submission")
    add_upload_arguments(client)

    verify = commands.add_parser("verify", help="Verify a saved signed receipt")
    verify.add_argument("receipt", help="JSON receipt saved by the upload command")
    verify.add_argument("--server-key", default="keys/server_public.pem")

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
        result = upload(args.file, args.host, args.port, args.chunk_size, args.server_key, args.state)
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
    else:
        with open(args.receipt, encoding="utf-8") as receipt_file:
            saved = json.load(receipt_file)
        verify_receipt(saved["receipt"], saved["signature"], args.server_key)
        print(f"Valid signature for accepted upload {saved['receipt']['upload_id']}")


if __name__ == "__main__":
    main()
