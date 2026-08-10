import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from incident_context.adapters import AdapterLimits, LokiAdapter, LokiQuery


class _JsonHandler(BaseHTTPRequestHandler):
    payload = {
        "status": "success",
        "data": {
            "result": [
                {
                    "stream": {"namespace": "avion", "app": "avion-search"},
                    "values": [["1786363200000000000", "ERROR live HTTP boundary"]],
                }
            ]
        },
    }

    def do_GET(self):
        body = json.dumps(self.payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@pytest.fixture
def json_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JsonHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_default_http_transport_exercises_loki_boundary(json_server):
    end = datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc)
    result = LokiAdapter(json_server).query(
        LokiQuery(namespace="avion", start=end - timedelta(minutes=5), end=end)
    )

    assert result.complete is True
    assert result.events[0].message == "ERROR live HTTP boundary"
    assert result.events[0].evidence["source"] == "loki"


def test_default_http_transport_rejects_oversized_body(json_server):
    end = datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc)
    adapter = LokiAdapter(
        json_server,
        limits=AdapterLimits(max_response_bytes=20),
    )

    with pytest.raises(RuntimeError, match="byte limit"):
        adapter.query(LokiQuery(namespace="avion", start=end - timedelta(minutes=5), end=end))
