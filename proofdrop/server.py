"""Threaded TCP server for ProofDrop file submissions."""

from __future__ import annotations

import argparse
import base64
import socketserver

from .protocol import load_private_key, recv_json, send_json, server_handshake
from .receipts import sign_receipt
from .storage import UploadStore


class ProofDropServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, store: UploadStore, signing_key):
        super().__init__(address, handler)
        self.store = store
        self.signing_key = signing_key


class ClientHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        channel = None
        try:
            self.request.settimeout(60)
            channel = server_handshake(self.request, self.server.signing_key)
            start = channel.receive()
            if start.get("action") != "start":
                raise ValueError("First encrypted message must start an upload")
            missing = self.server.store.prepare(start)
            channel.send({"type": "ready", "missing": missing})

            while True:
                message = channel.receive()
                action = message.get("action")
                if action == "chunk":
                    data = base64.b64decode(message["data"], validate=True)
                    self.server.store.put_chunk(
                        str(message["upload_id"]), int(message["index"]), data, str(message["sha256"])
                    )
                    channel.send({"type": "chunk_ack", "index": int(message["index"])})
                elif action == "finalize":
                    receipt = self.server.store.finalize(str(message["upload_id"]))
                    channel.send({
                        "type": "receipt",
                        "receipt": receipt,
                        "signature": sign_receipt(receipt, self.server.signing_key),
                    })
                    return
                else:
                    raise ValueError("Unknown upload action")
        except Exception as exc:
            if channel is not None:
                try:
                    channel.send({"type": "error", "message": str(exc)})
                except Exception:
                    pass
            else:
                print(f"Connection from {self.client_address[0]} failed during handshake: {exc}")


def serve(host: str, port: int, data_dir: str, private_key_path: str) -> None:
    store = UploadStore(data_dir)
    signing_key = load_private_key(private_key_path)
    with ProofDropServer((host, port), ClientHandler, store, signing_key) as server:
        print(f"ProofDrop server listening on {host}:{port}")
        print(f"Stored submissions: {store.submission_root}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1", help="Interface to listen on (default: localhost only)")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--data", default="server_data", help="Directory for the SQLite database and received files")
    parser.add_argument("--private-key", default="keys/server_private.pem")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ProofDrop submission server")
    add_arguments(parser)
    args = parser.parse_args()
    serve(args.host, args.port, args.data, args.private_key)


if __name__ == "__main__":
    main()
