"""Length-prefixed TCP messages and an authenticated encrypted session."""

from __future__ import annotations

import json
import os
import socket
import struct
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_FRAME = 16 * 1024 * 1024
PROTOCOL_LABEL = b"ProofDrop educational protocol v1"
EventCallback = Callable[[dict[str, Any]], None]


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly count bytes, even when TCP splits them across packets."""
    pieces = bytearray()
    while len(pieces) < count:
        part = sock.recv(count - len(pieces))
        if not part:
            raise ConnectionError("Peer closed the connection")
        pieces.extend(part)
    return bytes(pieces)


def send_frame(sock: socket.socket, body: bytes) -> None:
    if len(body) > MAX_FRAME:
        raise ValueError("Message exceeds the protocol frame limit")
    sock.sendall(struct.pack("!I", len(body)) + body)


def recv_frame(sock: socket.socket) -> bytes:
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > MAX_FRAME:
        raise ValueError("Peer sent a frame that exceeds the protocol limit")
    return recv_exact(sock, size)


def send_json(sock: socket.socket, value: dict[str, Any]) -> int:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    send_frame(sock, body)
    return len(body) + 4


def recv_json(sock: socket.socket) -> dict[str, Any]:
    value = json.loads(recv_frame(sock).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


class SecureChannel:
    """AES-GCM messages with separate keys and counters in each direction."""

    def __init__(
        self,
        sock: socket.socket,
        send_key: bytes,
        receive_key: bytes,
        role: str = "client",
        event_callback: EventCallback | None = None,
    ):
        self.sock = sock
        self.send_aes = AESGCM(send_key)
        self.receive_aes = AESGCM(receive_key)
        self.send_counter = 0
        self.receive_counter = 0
        self.role = role
        self.event_callback = event_callback

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return counter.to_bytes(12, "big")

    def _observe(self, direction: str, value: dict[str, Any], plaintext_size: int, frame_size: int) -> None:
        if self.event_callback is None:
            return
        encoded = value.get("data")
        chunk_bytes = None
        if isinstance(encoded, str):
            padding_bytes = len(encoded) - len(encoded.rstrip("="))
            chunk_bytes = max(0, (len(encoded) * 3 // 4) - padding_bytes)
        event = {
            "direction": direction,
            "message": value.get("action", value.get("type", "message")),
            "sequence": value.get("index"),
            "application_bytes": plaintext_size,
            "frame_bytes": frame_size,
            "chunk_bytes": chunk_bytes,
            "encrypted": True,
        }
        digest = value.get("sha256")
        if isinstance(digest, str):
            event["sha256_prefix"] = digest[:12]
        if value.get("action") == "start":
            event["total_chunks"] = value.get("total_chunks")
        if value.get("type") == "ready" and isinstance(value.get("missing"), list):
            event["missing_chunks"] = len(value["missing"])
        try:
            self.event_callback(event)
        except Exception:
            # A display/telemetry callback must never break the file transfer.
            pass

    def send(self, value: dict[str, Any]) -> None:
        plaintext = json.dumps(value, separators=(",", ":")).encode("utf-8")
        nonce = self._nonce(self.send_counter)
        ciphertext = self.send_aes.encrypt(nonce, plaintext, PROTOCOL_LABEL)
        send_frame(self.sock, ciphertext)
        self.send_counter += 1
        direction = "client -> server" if self.role == "client" else "server -> client"
        self._observe(direction, value, len(plaintext), len(ciphertext) + 4)

    def receive(self) -> dict[str, Any]:
        ciphertext = recv_frame(self.sock)
        nonce = self._nonce(self.receive_counter)
        plaintext = self.receive_aes.decrypt(nonce, ciphertext, PROTOCOL_LABEL)
        self.receive_counter += 1
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Expected an encrypted JSON object")
        direction = "server -> client" if self.role == "client" else "client -> server"
        self._observe(direction, value, len(plaintext), len(ciphertext) + 4)
        return value


def client_handshake(
    sock: socket.socket,
    trusted_server_key: rsa.RSAPublicKey,
    event_callback: EventCallback | None = None,
) -> SecureChannel:
    """Prove server key possession and derive fresh, direction-specific keys."""
    client_private = x25519.X25519PrivateKey.generate()
    client_public = client_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    client_hello = {"type": "client_hello", "key": client_public.hex()}
    hello_wire_size = send_json(sock, client_hello)
    if event_callback is not None:
        _notify_handshake(event_callback, "client -> server", client_hello, hello_wire_size)
    reply_bytes = recv_frame(sock)
    reply = json.loads(reply_bytes.decode("utf-8"))
    if not isinstance(reply, dict):
        raise ValueError("Expected a JSON handshake object")
    if event_callback is not None:
        _notify_handshake(event_callback, "server -> client", reply, len(reply_bytes) + 4)
    if reply.get("type") != "server_hello":
        raise ValueError("Server did not complete the key exchange")
    server_public = bytes.fromhex(reply["key"])
    signature = bytes.fromhex(reply["signature"])
    signed_data = PROTOCOL_LABEL + client_public + server_public
    trusted_server_key.verify(
        signature,
        signed_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    shared_secret = client_private.exchange(x25519.X25519PublicKey.from_public_bytes(server_public))
    keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=PROTOCOL_LABEL).derive(shared_secret)
    return SecureChannel(
        sock, send_key=keys[:32], receive_key=keys[32:], role="client",
        event_callback=event_callback,
    )


def _notify_handshake(
    event_callback: EventCallback,
    direction: str,
    value: dict[str, Any],
    frame_bytes: int,
) -> None:
    try:
        event_callback({
            "direction": direction,
            "message": value.get("type", "handshake"),
            "sequence": None,
            "application_bytes": max(0, frame_bytes - 4),
            "frame_bytes": frame_bytes,
            "chunk_bytes": None,
            "encrypted": False,
        })
    except Exception:
        pass


def server_handshake(sock: socket.socket, signing_key: rsa.RSAPrivateKey) -> SecureChannel:
    hello = recv_json(sock)
    if hello.get("type") != "client_hello":
        raise ValueError("Expected a client key exchange")
    client_public = bytes.fromhex(hello["key"])
    if len(client_public) != 32:
        raise ValueError("Invalid client key")
    server_private = x25519.X25519PrivateKey.generate()
    server_public = server_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signed_data = PROTOCOL_LABEL + client_public + server_public
    signature = signing_key.sign(
        signed_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    send_json(sock, {"type": "server_hello", "key": server_public.hex(), "signature": signature.hex()})
    shared_secret = server_private.exchange(x25519.X25519PublicKey.from_public_bytes(client_public))
    keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=PROTOCOL_LABEL).derive(shared_secret)
    return SecureChannel(sock, send_key=keys[32:], receive_key=keys[:32], role="server")


def load_public_key(path: str) -> rsa.RSAPublicKey:
    with open(path, "rb") as stream:
        key = serialization.load_pem_public_key(stream.read())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("The trusted server key must be an RSA public key")
    return key


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as stream:
        key = serialization.load_pem_private_key(stream.read(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("The server identity key must be RSA")
    return key


def generate_server_keys(directory: str) -> tuple[str, str]:
    os.makedirs(directory, exist_ok=True)
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path = os.path.join(directory, "server_private.pem")
    public_path = os.path.join(directory, "server_public.pem")
    with open(private_path, "wb") as stream:
        stream.write(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    os.chmod(private_path, 0o600)
    with open(public_path, "wb") as stream:
        stream.write(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return private_path, public_path
