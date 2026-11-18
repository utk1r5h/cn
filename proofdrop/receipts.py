"""Canonical receipt encoding and RSA signature verification."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def canonical_bytes(receipt: dict[str, Any]) -> bytes:
    """Serialize the signed fields deterministically so both sides agree."""
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_receipt(receipt: dict[str, Any], private_key: rsa.RSAPrivateKey) -> str:
    signature = private_key.sign(
        canonical_bytes(receipt),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_receipt(receipt: dict[str, Any], signature: str, public_key_path: str) -> None:
    with open(public_key_path, "rb") as stream:
        public_key = serialization.load_pem_public_key(stream.read())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Receipt verification requires an RSA public key")
    public_key.verify(
        base64.b64decode(signature, validate=True),
        canonical_bytes(receipt),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
