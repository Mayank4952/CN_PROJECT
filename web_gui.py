"""
Secure Tunnel VPN - Web Dashboard (Group 15)
--------------------------------------------
Serves a sleek HTML5/CSS3/JavaScript responsive web dashboard on http://localhost:5000.
Features:
  - Big toggle 'CONNECT / DISCONNECT' switch
  - Real-time status cards (Virtual IP, Gateway, Latency, Bandwidth)
  - Live activity log feed
  - Server IP & Port settings
  - Zero external pip dependencies (built on standard library http.server)

Run:
  python web_gui.py [--port 5000]
"""

import os
import sys
import json
import time
import queue
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from vpn_client import VpnClient


class WebState:
    """Shared state between web dashboard and VPN client worker."""

    def __init__(self):
        self.client: Optional[VpnClient] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.is_connected = False
        self.is_connecting = False
        self.connected_at = 0.0
        self.virtual_ip = "—"
        self.server_ip = "—"
        self.proxy_port = 1080
        self.latency_ms = 0.0
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.logs = []
        self._lock = threading.Lock()

    def add_log(self, level: str, msg: str):
        with self._lock:
            ts = time.strftime("%H:%M:%S")
            self.logs.append({"time": ts, "level": level, "msg": msg})
            if len(self.logs) > 100:
                self.logs.pop(0)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            uptime = int(time.time() - self.connected_at) if self.is_connected else 0
            mins, secs = divmod(uptime, 60)
            if self.client:
                self.bytes_sent = self.client.bytes_sent
                self.bytes_recv = self.client.bytes_recv
                self.latency_ms = self.client.last_ping_rtt_ms

            return {
                "connected": self.is_connected,
                "connecting": self.is_connecting,
                "virtual_ip": self.virtual_ip,
                "server_ip": self.server_ip,
                "proxy_port": self.proxy_port,
                "latency_ms": round(self.latency_ms, 2),
                "bytes_sent": self.bytes_sent,
                "bytes_recv": self.bytes_recv,
                "uptime": f"{mins:02d}:{secs:02d}",
                "logs": self.logs[-30:],
            }


state = WebState()


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure VPN Dashboard - Group 15</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: #0f172a; color: #f8fafc; min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 24px; }
    .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 24px; width: 100%; max-width: 640px; margin-bottom: 20px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
    .badge { background: #0369a1; color: #38bdf8; font-weight: 700; font-size: 11px; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase; }
    .hero { text-align: center; padding: 10px 0 20px; }
    .status-dot { display: inline-block; width: 12px; height: 12px; border-radius: 50%; background: #64748b; margin-right: 8px; }
    .status-dot.active { background: #10b981; box-shadow: 0 0 12px #10b981; }
    .status-dot.connecting { background: #f59e0b; }
    .btn-toggle { width: 100%; padding: 16px; border: none; border-radius: 10px; font-size: 16px; font-weight: 700; cursor: pointer; transition: all 0.2s; color: white; background: #10b981; margin-top: 16px; }
    .btn-toggle:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn-toggle.connected { background: #ef4444; }
    .btn-toggle.connecting { background: #f59e0b; cursor: not-allowed; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 18px; }
    .stat-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; text-align: center; }
    .stat-title { font-size: 10px; font-weight: 700; color: #94a3b8; text-transform: uppercase; }
    .stat-value { font-size: 15px; font-weight: 700; color: #f8fafc; margin-top: 4px; }
    .form-group { margin-bottom: 12px; }
    label { font-size: 12px; color: #94a3b8; font-weight: 600; display: block; margin-bottom: 4px; }
    input { width: 100%; background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 10px 12px; border-radius: 8px; font-size: 14px; }
    .row { display: flex; gap: 12px; }
    .row > div { flex: 1; }
    .logs-box { background: #020617; border: 1px solid #1e293b; border-radius: 8px; height: 180px; overflow-y: auto; padding: 12px; font-family: monospace; font-size: 11px; color: #94a3b8; }
    .log-line { margin-bottom: 4px; }
    .log-line.SUCCESS { color: #34d399; }
    .log-line.ERROR { color: #f87171; }
    .copy-btn { background: #334155; color: #38bdf8; border: none; padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; margin-top: 8px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h2>🔒 Secure VPN (Group 15)</h2>
      <span class="badge">TLS 1.3 Tunnel</span>
    </div>

    <div class="hero">
      <div>
        <span id="dot" class="status-dot"></span>
        <span id="status-text" style="font-weight: 700; font-size: 14px; color: #94a3b8;">DISCONNECTED</span>
      </div>
      <button id="btn-toggle" class="btn-toggle" onclick="toggleConnect()">CONNECT TO VPN</button>

      <div class="grid">
        <div class="stat-box">
          <div class="stat-title">Virtual IP</div>
          <div id="val-vip" class="stat-value">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-title">Gateway</div>
          <div id="val-gateway" class="stat-value">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-title">Latency</div>
          <div id="val-latency" class="stat-value">—</div>
        </div>
      </div>

      <div style="font-size: 12px; color: #64748b; margin-top: 14px;">
        <span id="val-traffic">Traffic: 0 B Sent | 0 B Recv | Uptime: 00:00</span>
      </div>
    </div>

    <div style="margin-top: 16px; border-top: 1px solid #334155; padding-top: 16px;">
      <div class="row">
        <div class="form-group">
          <label>Server IP / Host</label>
          <input id="cfg-host" type="text" value="127.0.0.1">
        </div>
        <div class="form-group" style="flex: 0 0 100px;">
          <label>Port</label>
          <input id="cfg-port" type="number" value="8443">
        </div>
      </div>
      <div class="row">
        <div class="form-group">
          <label>Auth Secret</label>
          <input id="cfg-secret" type="password" value="supersecretvpnkey">
        </div>
        <div class="form-group" style="flex: 0 0 100px;">
          <label>SOCKS5 Port</label>
          <input id="cfg-proxy" type="number" value="1080">
        </div>
      </div>
      <button class="copy-btn" onclick="copyCurl()">📋 Copy SOCKS5 Curl Test Command</button>
    </div>
  </div>

  <div class="card">
    <h3 style="font-size: 13px; color: #94a3b8; margin-bottom: 10px; text-transform: uppercase;">Real-time Tunnel Logs</h3>
    <div id="logs" class="logs-box"></div>
  </div>

  <script>
    let isConnected = false;
    let isConnecting = false;

    function formatBytes(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(2) + ' MB';
    }

    async function pollStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        isConnected = data.connected;
        isConnecting = data.connecting;

        const btn = document.getElementById('btn-toggle');
        const dot = document.getElementById('dot');
        const txt = document.getElementById('status-text');

        if (isConnected) {
          btn.textContent = "DISCONNECT";
          btn.className = "btn-toggle connected";
          dot.className = "status-dot active";
          txt.textContent = "SECURE & CONNECTED";
          txt.style.color = "#10b981";
        } else if (isConnecting) {
          btn.textContent = "CONNECTING...";
          btn.className = "btn-toggle connecting";
          dot.className = "status-dot connecting";
          txt.textContent = "CONNECTING...";
          txt.style.color = "#f59e0b";
        } else {
          btn.textContent = "CONNECT TO VPN";
          btn.className = "btn-toggle";
          dot.className = "status-dot";
          txt.textContent = "DISCONNECTED";
          txt.style.color = "#94a3b8";
        }

        document.getElementById('val-vip').textContent = data.virtual_ip;
        document.getElementById('val-gateway').textContent = data.server_ip;
        document.getElementById('val-latency').textContent = data.latency_ms > 0 ? data.latency_ms + ' ms' : '< 1 ms';
        document.getElementById('val-traffic').textContent = 
          `Traffic: ${formatBytes(data.bytes_sent)} Sent ↑ | ${formatBytes(data.bytes_recv)} Recv ↓ | Uptime: ${data.uptime}`;

        const logsBox = document.getElementById('logs');
        logsBox.innerHTML = data.logs.map(l => `<div class="log-line ${l.level}">[${l.time}] ${l.msg}</div>`).join('');
        logsBox.scrollTop = logsBox.scrollHeight;
      } catch (e) {}
    }

    async function toggleConnect() {
      if (isConnecting) return;
      if (isConnected) {
        await fetch('/api/disconnect', { method: 'POST' });
      } else {
        const host = document.getElementById('cfg-host').value;
        const port = parseInt(document.getElementById('cfg-port').value);
        const secret = document.getElementById('cfg-secret').value;
        const proxyPort = parseInt(document.getElementById('cfg-proxy').value);

        await fetch('/api/connect', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ host, port, secret, proxyPort })
        });
      }
      pollStatus();
    }

    function copyCurl() {
      const port = document.getElementById('cfg-proxy').value || 1080;
      const cmd = `curl.exe --socks5-hostname 127.0.0.1:${port} https://icanhazip.com`;
      navigator.clipboard.writeText(cmd);
      alert('Copied to clipboard:\\n' + cmd);
    }

    setInterval(pollStatus, 1000);
    pollStatus();
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """Handles REST API and UI dashboard serving."""

    def log_message(self, format, *args):
        pass  # Suppress default server console clutter

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = state.get_status()
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/connect":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            params = json.loads(body.decode("utf-8")) if body else {}

            host = params.get("host", "127.0.0.1")
            port = params.get("port", 8443)
            secret = params.get("secret", "supersecretvpnkey")
            proxy_port = params.get("proxyPort", 1080)

            threading.Thread(target=self._start_vpn_client, args=(host, port, secret, proxy_port), daemon=True).start()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "CONNECTING"}')

        elif self.path == "/api/disconnect":
            self._stop_vpn_client()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "DISCONNECTED"}')

    def _start_vpn_client(self, host: str, port: int, secret: str, proxy_port: int):
        with state._lock:
            state.is_connecting = True
            state.add_log("INFO", f"Connecting to {host}:{port}...")

        try:
            cert_dir = "certs"
            ca_file = os.path.join(cert_dir, "ca.crt")
            cert_file = os.path.join(cert_dir, "client.crt")
            key_file = os.path.join(cert_dir, "client.key")

            client = VpnClient(
                server_host=host,
                server_port=port,
                ca_file=ca_file if os.path.isfile(ca_file) else None,
                cert_file=cert_file if os.path.isfile(cert_file) else None,
                key_file=key_file if os.path.isfile(key_file) else None,
                verify_server=os.path.isfile(ca_file),
                auth_secret=secret,
                client_id=f"web-{os.getpid()}",
                mode="auto",
                proxy_bind_host="127.0.0.1",
                proxy_bind_port=proxy_port,
                verbose=True,
            )

            if client.connect():
                with state._lock:
                    state.client = client
                    state.is_connected = True
                    state.is_connecting = False
                    state.connected_at = time.time()
                    state.virtual_ip = client.virtual_ip
                    state.server_ip = client.server_virtual_ip
                    state.proxy_port = proxy_port
                    state.add_log("SUCCESS", f"Tunnel established! Virtual IP: {client.virtual_ip}")

                client.run_forever()
            else:
                with state._lock:
                    state.is_connecting = False
                    state.add_log("ERROR", "Handshake failed.")
        except Exception as e:
            with state._lock:
                state.is_connecting = False
                state.add_log("ERROR", f"Error: {e}")
        finally:
            with state._lock:
                state.is_connected = False
                state.is_connecting = False
                state.virtual_ip = "—"
                state.server_ip = "—"
                state.client = None
                state.add_log("INFO", "VPN tunnel disconnected.")

    def _stop_vpn_client(self):
        with state._lock:
            if state.client:
                state.add_log("INFO", "Disconnect requested by user.")
                state.client.disconnect()


def run_web_dashboard(bind_port: int = 5000):
    server_addr = ("0.0.0.0", bind_port)
    httpd = HTTPServer(server_addr, DashboardHandler)
    print("=" * 60)
    print(f"🚀 Secure VPN Web Dashboard running (Group 15)!")
    print(f"   Open in your browser: http://localhost:{bind_port}")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down web dashboard...")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure VPN Web Dashboard - Group 15")
    parser.add_argument("--port", type=int, default=5000, help="Web dashboard port (default: 5000)")
    args = parser.parse_args()
    run_web_dashboard(args.port)
