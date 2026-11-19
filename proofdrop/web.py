"""Local browser dashboard for uploading files and viewing protocol frames."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from .client import upload
from .protocol import EventCallback

MAX_BROWSER_UPLOAD = 512 * 1024 * 1024
STATIC_DIR = Path(__file__).with_name("static")


class UploadJob:
    def __init__(self, filename: str, size: int, total_chunks: int):
        self.job_id = str(uuid.uuid4())
        self.filename = filename
        self.size = size
        self.total_chunks = total_chunks
        self.status = "queued"
        self.error = None
        self.receipt = None
        self.summary = None
        self.events: list[dict] = []
        self.cursor = 0
        self.stored_before_connection = 0
        self.acknowledged_this_connection = 0
        self.pause_signal = threading.Event()
        self.file_path = ""
        self.chunk_size = 256 * 1024
        self.window_size = 1
        self.demo_rtt_ms = 0
        self.lock = threading.Lock()

    def add_event(self, event: dict, layer: str = "ProofDrop over TCP") -> None:
        with self.lock:
            item = dict(event)
            item["id"] = self.cursor + 1
            item["time"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            item["layer"] = layer
            self.events.append(item)
            self.cursor += 1
            if len(self.events) > 600:
                self.events = self.events[-600:]

            if item.get("message") == "start":
                self.total_chunks = int(item.get("total_chunks", self.total_chunks))
            elif item.get("message") == "ready":
                self.status = "pausing" if self.pause_signal.is_set() else "transferring"
                missing = int(item.get("missing_chunks", self.total_chunks))
                self.stored_before_connection = max(0, self.total_chunks - missing)
                self.acknowledged_this_connection = 0
            elif item.get("message") == "chunk_ack":
                self.acknowledged_this_connection += 1
            elif item.get("message") == "finalize":
                self.status = "verifying file"

    def request_pause(self) -> bool:
        with self.lock:
            if self.status == "pausing":
                return True
            if self.status not in ("queued", "connecting", "transferring"):
                return False
            self.pause_signal.set()
            self.status = "pausing"
            return True

    def begin_finalize(self) -> bool:
        with self.lock:
            if self.pause_signal.is_set():
                return False
            if self.status not in ("connecting", "transferring"):
                return False
            self.status = "verifying file"
            return True

    def snapshot(self, after: int = 0) -> dict:
        with self.lock:
            completed_chunks = min(
                self.total_chunks,
                self.stored_before_connection + self.acknowledged_this_connection,
            )
            return {
                "job_id": self.job_id,
                "filename": self.filename,
                "size": self.size,
                "status": self.status,
                "error": self.error,
                "receipt": self.receipt,
                "summary": self.summary,
                "total_chunks": self.total_chunks,
                "completed_chunks": completed_chunks,
                "progress": completed_chunks / self.total_chunks if self.total_chunks else (1 if self.status == "complete" else 0),
                "events": [event for event in self.events if event["id"] > after],
                "cursor": self.cursor,
            }


class JobRegistry:
    def __init__(self):
        self.jobs: dict[str, UploadJob] = {}
        self.lock = threading.Lock()

    def add(self, job: UploadJob) -> None:
        with self.lock:
            self.jobs[job.job_id] = job
            if len(self.jobs) > 40:
                oldest = next(iter(self.jobs))
                if oldest != job.job_id:
                    self.jobs.pop(oldest, None)

    def get(self, job_id: str) -> UploadJob | None:
        with self.lock:
            return self.jobs.get(job_id)


def run_transfer(job: UploadJob, file_path: str, app, chunk_size: int, window_size: int, demo_rtt_ms: int) -> None:
    with job.lock:
        job.status = "pausing" if job.pause_signal.is_set() else "connecting"
    try:
        result = upload(
            file_path,
            app.tcp_host,
            app.tcp_port,
            chunk_size,
            app.server_key,
            app.state_path,
            window_size,
            demo_rtt_ms,
            event_callback=job.add_event,
            pause_requested=job.pause_signal.is_set,
            before_finalize=job.begin_finalize,
        )
        if result.get("paused"):
            with job.lock:
                job.status = "paused"
            job.add_event({
                "direction": "dashboard -> client",
                "message": "upload paused",
                "sequence": None,
                "application_bytes": None,
                "frame_bytes": None,
                "chunk_bytes": None,
                "encrypted": False,
            }, layer="Dashboard control")
            return
        job.receipt = result["receipt"]
        job.summary = result.get("summary")
        with job.lock:
            job.status = "complete"
        job.add_event({
            "direction": "server -> client",
            "message": "receipt verified",
            "sequence": None,
            "application_bytes": None,
            "frame_bytes": None,
            "chunk_bytes": None,
            "encrypted": True,
        })
    except Exception as exc:
        with job.lock:
            job.status = "failed"
            job.error = str(exc)
        job.add_event({
            "direction": "system",
            "message": "transfer failed",
            "sequence": None,
            "application_bytes": None,
            "frame_bytes": None,
            "chunk_bytes": None,
            "encrypted": False,
            "error": str(exc),
        }, layer="Dashboard")


class DashboardHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, **settings):
        super().__init__(address, handler)
        self.jobs = JobRegistry()
        self.tcp_host = settings["tcp_host"]
        self.tcp_port = settings["tcp_port"]
        self.server_key = settings["server_key"]
        self.state_path = os.path.abspath(settings["state_path"])
        self.inbox = os.path.abspath(settings["inbox"])
        self.chunk_size = settings["chunk_size"]
        self.window_size = settings["window_size"]
        self.demo_rtt_ms = settings["demo_rtt_ms"]
        os.makedirs(self.inbox, exist_ok=True)
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardHTTPServer

    def log_message(self, format: str, *args) -> None:
        print(f"[web] {self.address_string()} - {format % args}")

    def send_json(self, status: int, value: dict) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/api/health":
            self.send_json(200, {"ok": True, "tcp_host": self.server.tcp_host, "tcp_port": self.server.tcp_port})
            return
        if parsed.path == "/api/job":
            query = parse_qs(parsed.query)
            job_id = query.get("id", [""])[0]
            try:
                after = max(0, int(query.get("after", ["0"])[0]))
            except ValueError:
                after = 0
            job = self.server.jobs.get(job_id)
            if job is None:
                self.send_json(404, {"error": "Upload session not found"})
                return
            self.send_json(200, job.snapshot(after))
            return
        if parsed.path == "/" or parsed.path in ("/app.css", "/app.js"):
            filename = "index.html" if parsed.path == "/" else parsed.path.lstrip("/")
            self.send_static(filename)
            return
        self.send_json(404, {"error": "Not found"})

    def send_static(self, filename: str) -> None:
        allowed = {"index.html", "app.css", "app.js"}
        if filename not in allowed:
            self.send_json(404, {"error": "Not found"})
            return
        path = STATIC_DIR / filename
        body = path.read_bytes()
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if content_type.startswith("text/") or filename.endswith(".js"):
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/api/pause":
            job_id = query.get("id", [""])[0]
            job = self.server.jobs.get(job_id)
            if job is None:
                self.send_json(404, {"error": "Upload session not found"})
                return

            if not job.request_pause():
                self.send_json(409, {"error": f"Upload cannot be paused while it is {job.status}"})
                return
            self.send_json(202, {"job_id": job.job_id, "status": job.status})
            return

        if parsed.path != "/api/upload":
            self.send_json(404, {"error": "Not found"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            content_length = -1
        if content_length < 0:
            self.send_json(411, {"error": "A Content-Length header is required"})
            return
        if content_length > MAX_BROWSER_UPLOAD:
            self.send_json(413, {"error": "Browser uploads are limited to 512 MiB"})
            return

        try:
            chunk_size = int(query.get("chunk_size", [str(256 * 1024)])[0])
            window_size = int(query.get("window_size", ["1"])[0])
            demo_rtt_ms = int(query.get("demo_rtt_ms", ["0"])[0])
        except ValueError:
            self.send_json(400, {"error": "Chunk, window, and delay values must be integers"})
            return
        if not 1 <= chunk_size <= 2 * 1024 * 1024 or not 1 <= window_size <= 64 or not 0 <= demo_rtt_ms <= 1000:
            self.send_json(400, {"error": "Chunk size, window, or teaching delay is outside its allowed range"})
            return

        raw_name = unquote(self.headers.get("X-File-Name", "upload.bin")).replace("\\", "/")
        name = Path(raw_name).name
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")[:120] or "upload.bin"
        digest = hashlib.sha256()
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="incoming-", dir=self.server.inbox, delete=False) as stream:
                temporary_path = stream.name
                remaining = content_length
                while remaining:
                    part = self.rfile.read(min(1024 * 1024, remaining))
                    if not part:
                        raise ConnectionError("Browser connection ended before the file was fully received")
                    stream.write(part)
                    digest.update(part)
                    remaining -= len(part)
            content_dir = os.path.join(self.server.inbox, digest.hexdigest())
            os.makedirs(content_dir, exist_ok=True)
            final_path = os.path.join(content_dir, safe_name)
            os.replace(temporary_path, final_path)
        except Exception as exc:
            if temporary_path and os.path.exists(temporary_path):
                os.remove(temporary_path)
            self.send_json(400, {"error": str(exc)})
            return

        total_chunks = (content_length + chunk_size - 1) // chunk_size
        job = UploadJob(safe_name, content_length, total_chunks)
        job.file_path = final_path
        job.chunk_size = chunk_size
        job.window_size = window_size
        job.demo_rtt_ms = demo_rtt_ms
        job.add_event({
            "direction": "browser -> dashboard",
            "message": "HTTP file received",
            "sequence": None,
            "application_bytes": content_length,
            "frame_bytes": None,
            "chunk_bytes": None,
            "encrypted": False,
        }, layer="Dashboard HTTP")
        self.server.jobs.add(job)
        worker = threading.Thread(
            target=run_transfer,
            args=(job, job.file_path, self.server, job.chunk_size, job.window_size, job.demo_rtt_ms),
            daemon=True,
        )
        worker.start()
        self.send_json(202, {"job_id": job.job_id, "filename": safe_name, "size": content_length})


def serve_dashboard(
    web_host: str = "127.0.0.1",
    web_port: int = 8080,
    tcp_host: str = "127.0.0.1",
    tcp_port: int = 5050,
    server_key: str = "keys/server_public.pem",
    state_path: str = ".proofdrop/web_client_state.sqlite3",
    inbox: str = ".proofdrop/web_inbox",
    chunk_size: int = 256 * 1024,
    window_size: int = 1,
    demo_rtt_ms: int = 0,
) -> None:
    settings = {
        "tcp_host": tcp_host,
        "tcp_port": tcp_port,
        "server_key": server_key,
        "state_path": state_path,
        "inbox": inbox,
        "chunk_size": chunk_size,
        "window_size": window_size,
        "demo_rtt_ms": demo_rtt_ms,
    }
    with DashboardHTTPServer((web_host, web_port), DashboardHandler, **settings) as server:
        print(f"ProofDrop dashboard: http://{web_host}:{web_port}")
        print(f"TCP upload target: {tcp_host}:{tcp_port}")
        print("Press Ctrl+C to stop the dashboard")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard stopped")
