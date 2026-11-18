"""Length-prefixed TCP messages and an authenticated encrypted session."""

from __future__ import annotations

import json
import os
import socket
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_FRAME = 16 * 1024 * 1024
PROTOCOL_LABEL = b"ProofDrop educational protocol v1"


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


def send_json(sock: socket.socket, value: dict[str, Any]) -> None:
    send_frame(sock, json.dumps(value, separators=(",", ":")).encode("utf-8"))


def recv_json(sock: socket.socket) -> dict[str, Any]:
    value = json.loads(recv_frame(sock).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


class SecureChannel:
    """AES-GCM messages with separate keys and counters in each direction."""

    def __init__(self, sock: socket.socket, send_key: bytes, receive_key: bytes):
        self.sock = sock
        self.send_aes = AESGCM(send_key)
        self.receive_aes = AESGCM(receive_key)
        self.send_counter = 0
        self.receive_counter = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return counter.to_bytes(12, "big")

    def send(self, value: dict[str, Any]) -> None:
        plaintext = json.dumps(value, separators=(",", ":")).encode("utf-8")
        nonce = self._nonce(self.send_counter)
        ciphertext = self.send_aes.encrypt(nonce, plaintext, PROTOCOL_LABEL)
        send_frame(self.sock, ciphertext)
        self.send_counter += 1

    def receive(self) -> dict[str, Any]:
        ciphertext = recv_frame(self.sock)
        nonce = self._nonce(self.receive_counter)
        plaintext = self.receive_aes.decrypt(nonce, ciphertext, PROTOCOL_LABEL)
        self.receive_counter += 1
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Expected an encrypted JSON object")
        return value


def client_handshake(sock: socket.socket, trusted_server_key: rsa.RSAPublicKey) -> SecureChannel:
    """Prove server key possession and derive fresh, direction-specific keys."""
    client_private = x25519.X25519PrivateKey.generate()
    client_public = client_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    send_json(sock, {"type": "client_hello", "key": client_public.hex()})
    reply = recv_json(sock)
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
    return SecureChannel(sock, send_key=keys[:32], receive_key=keys[32:])


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
    return SecureChannel(sock, send_key=keys[32:], receive_key=keys[:32])


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
