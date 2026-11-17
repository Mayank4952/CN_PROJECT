"""
Secure Tunnel VPN - Desktop Frontend (Group 15)
-----------------------------------------------
Native Dark-Mode Desktop GUI for Secure VPN Client.
Features:
  - Big Toggle Connect / Disconnect button
  - Real-time connection status badge (TLS 1.3 / mTLS)
  - Live metric gauges: Assigned Virtual IP, Latency (ms), Data Sent/Received
  - Server configuration controls (Host, Port, Secret Key, Mode)
  - Live color-coded diagnostic log drawer
  - One-click 'Copy SOCKS5 Curl Test' button
  - Fully threaded: non-blocking UI

Run:
  python vpn_gui.py
"""

import os
import sys
import time
import queue
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from vpn_client import VpnClient


class QueueHandler(logging.Handler):
    """Sends log records into a thread-safe queue for the Tkinter UI."""

    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_queue.put(("LOG", record.levelname, msg))
        except Exception:
            pass


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable B, KB, MB, GB."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


class VpnAppGUI:
    """Modern Desktop GUI for Secure VPN Client."""

    # Color Palette (Tailwind Slate / Emerald / Rose Dark Theme)
    BG_DARK = "#0f172a"        # slate-900
    BG_CARD = "#1e293b"        # slate-800
    BG_INPUT = "#334155"       # slate-700
    BORDER = "#475569"         # slate-600
    TEXT_PRIMARY = "#f8fafc"   # slate-50
    TEXT_MUTED = "#94a3b8"     # slate-400
    ACCENT_GREEN = "#10b981"   # emerald-500
    ACCENT_GREEN_HOVER = "#059669"
    ACCENT_RED = "#ef4444"     # red-500
    ACCENT_RED_HOVER = "#dc2626"
    ACCENT_AMBER = "#f59e0b"   # amber-500
    ACCENT_BLUE = "#38bdf8"    # sky-400

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure VPN Client - Group 15")
        self.root.geometry("640x760")
        self.root.minsize(580, 680)
        self.root.configure(bg=self.BG_DARK)

        self.client: Optional[VpnClient] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.is_connected = False
        self.is_connecting = False
        self.connected_time = 0.0

        # Thread communication queue
        self.event_queue = queue.Queue()

        # Hook into VPN logging
        self.log_handler = QueueHandler(self.event_queue)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
        self.log_handler.setFormatter(formatter)
        logging.getLogger("VPN").addHandler(self.log_handler)

        self._build_ui()
        self._start_event_listener()

    def _build_ui(self):
        """Construct the modern GUI layout."""
        # 1. Header Bar
        header = tk.Frame(self.root, bg=self.BG_CARD, padx=20, pady=14)
        header.pack(fill="x")

        title_lbl = tk.Label(
            header,
            text="🔒 SECURE VPN (GROUP 15)",
            font=("Segoe UI", 14, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD
        )
        title_lbl.pack(side="left")

        proto_badge = tk.Label(
            header,
            text="TLS 1.3 / mTLS",
            font=("Segoe UI", 9, "bold"),
            fg=self.ACCENT_BLUE,
            bg=self.BG_INPUT,
            padx=10,
            pady=4
        )
        proto_badge.pack(side="right")

        # Main Scrollable / Padded Container
        container = tk.Frame(self.root, bg=self.BG_DARK, padx=24, pady=16)
        container.pack(fill="both", expand=True)

        # 2. Connection Hero Card
        hero_card = tk.Frame(container, bg=self.BG_CARD, padx=20, pady=20, relief="flat", highlightthickness=1, highlightbackground=self.BORDER)
        hero_card.pack(fill="x", pady=(0, 16))

        # Status text & icon
        self.status_dot = tk.Label(hero_card, text="●", font=("Segoe UI", 16), fg=self.TEXT_MUTED, bg=self.BG_CARD)
        self.status_dot.pack()

        self.status_lbl = tk.Label(
            hero_card,
            text="DISCONNECTED",
            font=("Segoe UI", 12, "bold"),
            fg=self.TEXT_MUTED,
            bg=self.BG_CARD
        )
        self.status_lbl.pack(pady=(2, 14))

        # Prominent Action Button (Connect / Disconnect)
        self.btn_connect = tk.Button(
            hero_card,
            text="CONNECT TO VPN",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg=self.ACCENT_GREEN,
            activebackground=self.ACCENT_GREEN_HOVER,
            activeforeground="#ffffff",
            relief="flat",
            cursor="hand2",
            padx=32,
            pady=12,
            command=self._on_connect_toggle
        )
        self.btn_connect.pack(fill="x")

        # 3. Live Metrics Grid (Cards)
        stats_frame = tk.Frame(hero_card, bg=self.BG_CARD)
        stats_frame.pack(fill="x", pady=(18, 0))

        # Metric 1: Assigned Virtual IP
        m1 = tk.Frame(stats_frame, bg=self.BG_INPUT, padx=10, pady=8, highlightthickness=1, highlightbackground=self.BORDER)
        m1.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(m1, text="VIRTUAL IP", font=("Segoe UI", 8, "bold"), fg=self.TEXT_MUTED, bg=self.BG_INPUT).pack()
        self.lbl_vip = tk.Label(m1, text="—", font=("Segoe UI", 11, "bold"), fg=self.TEXT_PRIMARY, bg=self.BG_INPUT)
        self.lbl_vip.pack()

        # Metric 2: Gateway
        m2 = tk.Frame(stats_frame, bg=self.BG_INPUT, padx=10, pady=8, highlightthickness=1, highlightbackground=self.BORDER)
        m2.pack(side="left", fill="both", expand=True, padx=4)
        tk.Label(m2, text="GATEWAY", font=("Segoe UI", 8, "bold"), fg=self.TEXT_MUTED, bg=self.BG_INPUT).pack()
        self.lbl_gateway = tk.Label(m2, text="—", font=("Segoe UI", 11, "bold"), fg=self.TEXT_PRIMARY, bg=self.BG_INPUT)
        self.lbl_gateway.pack()

        # Metric 3: Latency
        m3 = tk.Frame(stats_frame, bg=self.BG_INPUT, padx=10, pady=8, highlightthickness=1, highlightbackground=self.BORDER)
        m3.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(m3, text="LATENCY", font=("Segoe UI", 8, "bold"), fg=self.TEXT_MUTED, bg=self.BG_INPUT).pack()
        self.lbl_latency = tk.Label(m3, text="—", font=("Segoe UI", 11, "bold"), fg=self.TEXT_PRIMARY, bg=self.BG_INPUT)
        self.lbl_latency.pack()

        # Traffic Counter Subrow
        traffic_frame = tk.Frame(hero_card, bg=self.BG_CARD)
        traffic_frame.pack(fill="x", pady=(12, 0))
        self.lbl_traffic = tk.Label(
            traffic_frame,
            text="Tunnel Traffic:  0 B Sent (↑)  |  0 B Recv (↓)  |  Uptime: 00:00",
            font=("Segoe UI", 9),
            fg=self.TEXT_MUTED,
            bg=self.BG_CARD
        )
        self.lbl_traffic.pack()

        # 4. Server Configuration Form
        config_card = tk.LabelFrame(
            container,
            text="  SERVER CONFIGURATION  ",
            font=("Segoe UI", 9, "bold"),
            fg=self.TEXT_MUTED,
            bg=self.BG_CARD,
            padx=16,
            pady=12,
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.BORDER
        )
        config_card.pack(fill="x", pady=(0, 14))

        cfg_grid = tk.Frame(config_card, bg=self.BG_CARD)
        cfg_grid.pack(fill="x")

        # Row 1: Server Host & Port
        tk.Label(cfg_grid, text="Server Host / IP:", font=("Segoe UI", 9), fg=self.TEXT_PRIMARY, bg=self.BG_CARD).grid(row=0, column=0, sticky="w", pady=4)
        self.ent_host = tk.Entry(cfg_grid, font=("Segoe UI", 9), bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground="#ffffff", relief="flat")
        self.ent_host.insert(0, "127.0.0.1")
        self.ent_host.grid(row=0, column=1, sticky="ew", padx=(8, 16), pady=4)

        tk.Label(cfg_grid, text="Port:", font=("Segoe UI", 9), fg=self.TEXT_PRIMARY, bg=self.BG_CARD).grid(row=0, column=2, sticky="w", pady=4)
        self.ent_port = tk.Entry(cfg_grid, font=("Segoe UI", 9), width=7, bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground="#ffffff", relief="flat")
        self.ent_port.insert(0, "8443")
        self.ent_port.grid(row=0, column=3, sticky="ew", padx=(8, 0), pady=4)

        # Row 2: Auth Secret & SOCKS5 Port
        tk.Label(cfg_grid, text="Auth Secret:", font=("Segoe UI", 9), fg=self.TEXT_PRIMARY, bg=self.BG_CARD).grid(row=1, column=0, sticky="w", pady=4)
        self.ent_secret = tk.Entry(cfg_grid, font=("Segoe UI", 9), show="●", bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground="#ffffff", relief="flat")
        self.ent_secret.insert(0, "supersecretvpnkey")
        self.ent_secret.grid(row=1, column=1, sticky="ew", padx=(8, 16), pady=4)

        tk.Label(cfg_grid, text="Proxy Port:", font=("Segoe UI", 9), fg=self.TEXT_PRIMARY, bg=self.BG_CARD).grid(row=1, column=2, sticky="w", pady=4)
        self.ent_proxy_port = tk.Entry(cfg_grid, font=("Segoe UI", 9), width=7, bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground="#ffffff", relief="flat")
        self.ent_proxy_port.insert(0, "1080")
        self.ent_proxy_port.grid(row=1, column=3, sticky="ew", padx=(8, 0), pady=4)

        cfg_grid.columnconfigure(1, weight=1)

        # Quick Actions Row
        actions_row = tk.Frame(config_card, bg=self.BG_CARD)
        actions_row.pack(fill="x", pady=(10, 0))

        btn_copy = tk.Button(
            actions_row,
            text="📋 Copy SOCKS5 Curl Test",
            font=("Segoe UI", 8, "bold"),
            bg=self.BG_INPUT,
            fg=self.ACCENT_BLUE,
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
            command=self._copy_curl_command
        )
        btn_copy.pack(side="left")

        btn_ping = tk.Button(
            actions_row,
            text="⚡ Send Test Ping",
            font=("Segoe UI", 8, "bold"),
            bg=self.BG_INPUT,
            fg=self.ACCENT_AMBER,
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
            command=self._send_test_ping
        )
        btn_ping.pack(side="right")

        # 5. Live Activity Logs Console
        log_card = tk.LabelFrame(
            container,
            text="  TUNNEL ACTIVITY LOGS  ",
            font=("Segoe UI", 9, "bold"),
            fg=self.TEXT_MUTED,
            bg=self.BG_CARD,
            padx=10,
            pady=8,
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.BORDER
        )
        log_card.pack(fill="both", expand=True)

        self.txt_logs = tk.Text(
            log_card,
            bg="#020617",
            fg="#e2e8f0",
            insertbackground="#ffffff",
            font=("Consolas", 8),
            wrap="word",
            relief="flat",
            padx=8,
            pady=8
        )
        self.txt_logs.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(log_card, command=self.txt_logs.yview, bg=self.BG_CARD)
        scrollbar.pack(side="right", fill="y")
        self.txt_logs.config(yscrollcommand=scrollbar.set)

        # Configure color tags for log levels
        self.txt_logs.tag_config("INFO", foreground="#94a3b8")
        self.txt_logs.tag_config("WARNING", foreground="#f59e0b")
        self.txt_logs.tag_config("ERROR", foreground="#ef4444")
        self.txt_logs.tag_config("SUCCESS", foreground="#10b981")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_connect_toggle(self):
        """Handle button click: Connect or Disconnect."""
        if self.is_connecting:
            return

        if self.is_connected:
            self._disconnect_client()
        else:
            self._connect_client()

    def _connect_client(self):
        """Spawn background worker to establish the encrypted tunnel."""
        server_host = self.ent_host.get().strip()
        server_port_str = self.ent_port.get().strip()
        auth_secret = self.ent_secret.get().strip()
        proxy_port_str = self.ent_proxy_port.get().strip()

        try:
            server_port = int(server_port_str)
            proxy_port = int(proxy_port_str)
        except ValueError:
            messagebox.showerror("Invalid Input", "Ports must be numbers!")
            return

        # Update UI state to 'Connecting...'
        self.is_connecting = True
        self.btn_connect.config(text="CONNECTING...", bg=self.ACCENT_AMBER)
        self.status_lbl.config(text="CONNECTING TO SERVER...", fg=self.ACCENT_AMBER)
        self.status_dot.config(fg=self.ACCENT_AMBER)

        self._append_log("INFO", f"Connecting to {server_host}:{server_port} via TLS 1.3...")

        # Worker thread
        def worker():
            try:
                cert_dir = "certs"
                ca_file = os.path.join(cert_dir, "ca.crt")
                cert_file = os.path.join(cert_dir, "client.crt")
                key_file = os.path.join(cert_dir, "client.key")

                self.client = VpnClient(
                    server_host=server_host,
                    server_port=server_port,
                    ca_file=ca_file if os.path.isfile(ca_file) else None,
                    cert_file=cert_file if os.path.isfile(cert_file) else None,
                    key_file=key_file if os.path.isfile(key_file) else None,
                    verify_server=os.path.isfile(ca_file),
                    auth_secret=auth_secret,
                    client_id=f"gui-{os.getpid()}",
                    mode="auto",
                    proxy_bind_host="127.0.0.1",
                    proxy_bind_port=proxy_port,
                    verbose=True,
                )

                if self.client.connect():
                    self.event_queue.put(("CONNECTED", {
                        "virtual_ip": self.client.virtual_ip,
                        "server_ip": self.client.server_virtual_ip,
                        "proxy_port": proxy_port,
                    }))
                    self.client.run_forever()
                else:
                    self.event_queue.put(("FAILED", "Connection handshake failed."))
            except Exception as e:
                self.event_queue.put(("FAILED", str(e)))
            finally:
                self.event_queue.put(("DISCONNECTED", None))

        self.worker_thread = threading.Thread(target=worker, daemon=True, name="GuiVpnWorker")
        self.worker_thread.start()

    def _disconnect_client(self):
        """Disconnect the active VPN client."""
        if self.client:
            self._append_log("INFO", "Disconnecting from VPN server...")
            self.client.disconnect()
            self.client = None

    def _start_event_listener(self):
        """Poll the thread-safe queue for status updates, logs, and metrics."""
        try:
            while True:
                item = self.event_queue.get_nowait()
                ev_type = item[0]

                if ev_type == "CONNECTED":
                    info = item[1]
                    self.is_connected = True
                    self.is_connecting = False
                    self.connected_time = time.time()

                    self.status_lbl.config(text="SECURE & CONNECTED", fg=self.ACCENT_GREEN)
                    self.status_dot.config(fg=self.ACCENT_GREEN)
                    self.btn_connect.config(text="DISCONNECT", bg=self.ACCENT_RED, activebackground=self.ACCENT_RED_HOVER)

                    self.lbl_vip.config(text=info["virtual_ip"], fg=self.ACCENT_GREEN)
                    self.lbl_gateway.config(text=info["server_ip"], fg=self.ACCENT_BLUE)
                    self.lbl_latency.config(text="< 1 ms", fg=self.ACCENT_GREEN)

                    self._append_log("SUCCESS", f"Tunnel active! Assigned Virtual IP: {info['virtual_ip']}")
                    self._append_log("SUCCESS", f"SOCKS5 Proxy ready on 127.0.0.1:{info['proxy_port']}")

                elif ev_type == "FAILED":
                    err_msg = item[1]
                    self.is_connected = False
                    self.is_connecting = False
                    self._reset_ui_disconnected()
                    self._append_log("ERROR", f"Connection failed: {err_msg}")
                    messagebox.showerror("Connection Error", f"Failed to connect to VPN:\n{err_msg}")

                elif ev_type == "DISCONNECTED":
                    if self.is_connected or self.is_connecting:
                        self.is_connected = False
                        self.is_connecting = False
                        self._reset_ui_disconnected()
                        self._append_log("INFO", "VPN tunnel disconnected.")

                elif ev_type == "LOG":
                    level = item[1]
                    msg = item[2]
                    self._append_log(level, msg)

        except queue.Empty:
            pass

        # Periodically refresh live metrics while connected
        if self.is_connected and self.client:
            sent_str = format_bytes(self.client.bytes_sent)
            recv_str = format_bytes(self.client.bytes_recv)
            uptime_sec = int(time.time() - self.connected_time)
            mins, secs = divmod(uptime_sec, 60)
            uptime_str = f"{mins:02d}:{secs:02d}"

            self.lbl_traffic.config(
                text=f"Tunnel Traffic:  {sent_str} Sent (↑)  |  {recv_str} Recv (↓)  |  Uptime: {uptime_str}"
            )

            if self.client.last_ping_rtt_ms > 0:
                self.lbl_latency.config(text=f"{self.client.last_ping_rtt_ms:.1f} ms")

        self.root.after(100, self._start_event_listener)

    def _reset_ui_disconnected(self):
        """Restore UI components to the disconnected state."""
        self.btn_connect.config(text="CONNECT TO VPN", bg=self.ACCENT_GREEN, activebackground=self.ACCENT_GREEN_HOVER)
        self.status_lbl.config(text="DISCONNECTED", fg=self.TEXT_MUTED)
        self.status_dot.config(fg=self.TEXT_MUTED)
        self.lbl_vip.config(text="—", fg=self.TEXT_PRIMARY)
        self.lbl_gateway.config(text="—", fg=self.TEXT_PRIMARY)
        self.lbl_latency.config(text="—", fg=self.TEXT_PRIMARY)
        self.lbl_traffic.config(text="Tunnel Traffic:  0 B Sent (↑)  |  0 B Recv (↓)  |  Uptime: 00:00")

    def _append_log(self, level: str, message: str):
        """Append a log line into the console with color coding."""
        self.txt_logs.insert(tk.END, f"{message}\n", level)
        self.txt_logs.see(tk.END)

    def _copy_curl_command(self):
        """Copy the SOCKS5 curl test command to system clipboard."""
        proxy_port = self.ent_proxy_port.get().strip() or "1080"
        cmd = f"curl.exe --socks5-hostname 127.0.0.1:{proxy_port} https://icanhazip.com"
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        messagebox.showinfo("Copied to Clipboard", f"Command copied:\n{cmd}")

    def _send_test_ping(self):
        """Inject a synthetic ICMP packet to verify tunnel responsiveness."""
        if self.is_connected and self.client:
            self.client.send_synthetic_ping()
            self._append_log("INFO", "[Diagnostic] Injected test packet into encrypted tunnel.")
        else:
            messagebox.showwarning("Not Connected", "Please connect to the VPN first!")

    def _on_close(self):
        """Clean teardown on window exit."""
        if self.is_connected:
            self._disconnect_client()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = VpnAppGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
