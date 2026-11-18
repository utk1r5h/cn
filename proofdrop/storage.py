"""SQLite records and chunk files maintained by the submission server."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from contextlib import contextmanager


class UploadStore:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.chunk_root = os.path.join(self.root, "chunks")
        self.submission_root = os.path.join(self.root, "submissions")
        os.makedirs(self.chunk_root, exist_ok=True)
        os.makedirs(self.submission_root, exist_ok=True)
        self.database = os.path.join(self.root, "proofdrop_server.sqlite3")
        self.lock = threading.RLock()
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS uploads (
                upload_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                chunk_size INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                expected_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'receiving',
                receipt_json TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS chunks (
                upload_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                PRIMARY KEY (upload_id, chunk_index)
            )""")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _valid_id(upload_id: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F-]{36}", upload_id))

    def prepare(self, metadata: dict) -> list[int]:
        upload_id = str(metadata["upload_id"])
        filename = os.path.basename(str(metadata["filename"]))
        size = int(metadata["size"])
        chunk_size = int(metadata["chunk_size"])
        total_chunks = int(metadata["total_chunks"])
        digest = str(metadata["sha256"])
        if not self._valid_id(upload_id) or not filename or filename in (".", ".."):
            raise ValueError("Invalid upload ID or filename")
        if size < 0 or not 1 <= chunk_size <= 2 * 1024 * 1024:
            raise ValueError("Invalid file or chunk size")
        expected_chunks = (size + chunk_size - 1) // chunk_size
        if total_chunks != expected_chunks or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Upload metadata is inconsistent")
        with self.lock, self.connect() as db:
            row = db.execute("SELECT * FROM uploads WHERE upload_id=?", (upload_id,)).fetchone()
            expected = (filename, size, chunk_size, total_chunks, digest)
            if row:
                actual = (row["filename"], row["size"], row["chunk_size"], row["total_chunks"], row["expected_sha256"])
                if actual != expected:
                    raise ValueError("This upload ID already belongs to different file metadata")
                if row["status"] == "complete":
                    return []
            else:
                db.execute(
                    "INSERT INTO uploads(upload_id,filename,size,chunk_size,total_chunks,expected_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                    (upload_id, filename, size, chunk_size, total_chunks, digest, datetime.now(timezone.utc).isoformat()),
                )
            received = set()
            directory = os.path.join(self.chunk_root, upload_id)
            chunk_rows = db.execute(
                "SELECT chunk_index,sha256,size FROM chunks WHERE upload_id=?", (upload_id,)
            ).fetchall()
            for chunk in chunk_rows:
                chunk_path = os.path.join(directory, f"{chunk['chunk_index']:08d}.chunk")
                try:
                    with open(chunk_path, "rb") as stream:
                        data = stream.read()
                except FileNotFoundError:
                    data = b""
                if len(data) == chunk["size"] and hashlib.sha256(data).hexdigest() == chunk["sha256"]:
                    received.add(chunk["chunk_index"])
                else:
                    # Ask the client to resend a chunk if persistent storage is incomplete.
                    db.execute(
                        "DELETE FROM chunks WHERE upload_id=? AND chunk_index=?",
                        (upload_id, chunk["chunk_index"]),
                    )
        return [i for i in range(total_chunks) if i not in received]

    def put_chunk(self, upload_id: str, index: int, data: bytes, claimed_hash: str) -> None:
        with self.lock, self.connect() as db:
            row = db.execute("SELECT * FROM uploads WHERE upload_id=?", (upload_id,)).fetchone()
            if not row or row["status"] != "receiving":
                raise ValueError("Upload is unknown or already finalized")
            if not 0 <= index < row["total_chunks"]:
                raise ValueError("Chunk index is outside the upload")
            expected_size = min(row["chunk_size"], row["size"] - index * row["chunk_size"])
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != expected_size or digest != claimed_hash:
                raise ValueError("Chunk size or SHA-256 check failed")
            previous = db.execute("SELECT sha256 FROM chunks WHERE upload_id=? AND chunk_index=?", (upload_id, index)).fetchone()
            if previous:
                if previous["sha256"] != digest:
                    raise ValueError("A different chunk already occupies this index")
                return
            directory = os.path.join(self.chunk_root, upload_id)
            os.makedirs(directory, exist_ok=True)
            final_path = os.path.join(directory, f"{index:08d}.chunk")
            temp_path = final_path + ".tmp"
            with open(temp_path, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, final_path)
            db.execute("INSERT INTO chunks(upload_id,chunk_index,sha256,size) VALUES(?,?,?,?)", (upload_id, index, digest, len(data)))

    def finalize(self, upload_id: str) -> dict:
        with self.lock, self.connect() as db:
            row = db.execute("SELECT * FROM uploads WHERE upload_id=?", (upload_id,)).fetchone()
            if not row:
                raise ValueError("Unknown upload")
            if row["status"] == "complete":
                return json.loads(row["receipt_json"])
            chunks = db.execute("SELECT chunk_index FROM chunks WHERE upload_id=? ORDER BY chunk_index", (upload_id,)).fetchall()
            if len(chunks) != row["total_chunks"]:
                raise ValueError("Some chunks are still missing")
            source_dir = os.path.join(self.chunk_root, upload_id)
            final_path = os.path.join(self.submission_root, f"{upload_id}_{row['filename']}")
            temp_path = final_path + ".tmp"
            digest = hashlib.sha256()
            size = 0
            with open(temp_path, "wb") as output:
                for index in range(row["total_chunks"]):
                    chunk_path = os.path.join(source_dir, f"{index:08d}.chunk")
                    with open(chunk_path, "rb") as chunk:
                        while part := chunk.read(1024 * 1024):
                            output.write(part)
                            digest.update(part)
                            size += len(part)
                output.flush()
                os.fsync(output.fileno())
            actual_hash = digest.hexdigest()
            if size != row["size"] or actual_hash != row["expected_sha256"]:
                os.remove(temp_path)
                raise ValueError("Reassembled file failed whole-file integrity check")
            os.replace(temp_path, final_path)
            receipt = {
                "upload_id": upload_id,
                "filename": row["filename"],
                "size": size,
                "sha256": actual_hash,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "status": "accepted",
            }
            db.execute("UPDATE uploads SET status='complete', receipt_json=? WHERE upload_id=?", (json.dumps(receipt, sort_keys=True), upload_id))
            return receipt
