import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ttkbootstrap as tb  # Enhanced styling using ttkbootstrap
from ttkbootstrap.constants import *
import http.server
import socket
import urllib.parse
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random


# Bencode function for encoding responses
def bencode(data):
    if isinstance(data, int):
        return b'i' + str(data).encode() + b'e'
    elif isinstance(data, bytes):
        return str(len(data)).encode() + b':' + data
    elif isinstance(data, str):
        return str(len(data)).encode() + b':' + data.encode()
    elif isinstance(data, list):
        return b'l' + b''.join(bencode(i) for i in data) + b'e'
    elif isinstance(data, dict):
        return b'd' + b''.join(bencode(k) + bencode(v) for k, v in data.items()) + b'e'
    else:
        raise ValueError(f"Unsupported data type for bencoding: {type(data)}")


# Custom HTTP request handler for the Torrent Tracker
class TorrentTracker(http.server.SimpleHTTPRequestHandler):
    torrents = {}

    def log_message(self, format, *args):
        # Custom log handler to forward logs to the GUI
        if hasattr(self.server, 'gui_ref'):
            self.server.gui_ref.log(format % args)

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == '/announce':
            self.handle_announce(parsed_path)
        else:
            self.send_response(404)
            self.end_headers()
            self.log_message("404: Path not found %s", self.path)

    def handle_announce(self, parsed_path):
        params = urllib.parse.parse_qs(parsed_path.query)
        info_hash = params.get('info_hash', [None])[0]
        peer_id = params.get('peer_id', [None])[0]
        port = int(params.get('port', [0])[0])
        event = params.get('event', [None])[0]

        if info_hash is None or peer_id is None:
            self.send_response(400)
            self.end_headers()
            self.log_message("400: Bad request")
            return

        if info_hash not in self.torrents:
            self.torrents[info_hash] = {'peers': [], 'created': time.time()}

        if event == 'started':
            peer_info = {'peer_id': peer_id, 'port': port, 'ip': self.client_address[0]}
            if peer_info not in self.torrents[info_hash]['peers'] and peer_info['ip'] != '0.0.0.0':
                self.torrents[info_hash]['peers'].append(peer_info)
                self.log_message("Peer %s started on torrent %s", peer_id, info_hash)
        elif event == 'stopped':
            self.torrents[info_hash]['peers'] = [
                peer for peer in self.torrents[info_hash]['peers'] if peer['peer_id'] != peer_id
            ]
            self.log_message("Peer %s stopped on torrent %s", peer_id, info_hash)

        peers = self.torrents[info_hash]['peers']
        compact_peers = b''.join(socket.inet_aton(peer['ip']) + peer['port'].to_bytes(2, 'big') for peer in peers)
        response = {
            'interval': 30,
            'peers': [{'peer_id': peer['peer_id'], 'ip': peer['ip'], 'port': peer['port']} for peer in peers],
            'peers_compact': compact_peers if peers else b''
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/x-bittorrent')
        self.end_headers()
        self.wfile.write(bencode(response))
        self.log_message("200: Response sent for announce request")


# Function to start the torrent tracker server
def run_tracker(gui_ref, port=6969):
    handler_class = TorrentTracker
    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, handler_class)
    httpd.gui_ref = gui_ref  # Pass the GUI reference to the server for logging
    gui_ref.httpd = httpd  # Pass the httpd instance to the GUI for control
    print(f"Starting torrent tracker on port {port}...")
    gui_ref.log(f"Starting torrent tracker on port {port}...")
    httpd.serve_forever()


# GUI for managing the torrent tracker
class TorrentTrackerGUI:
    def __init__(self, root):
        self.httpd = None
        self.root = root
        self.style = tb.Style('cyborg')  # Enhanced dark mode with the "cyborg" theme
        self.root.title("Advanced Torrent Tracker")
        self.root.geometry("900x700")

        # Title Label
        self.title_label = tb.Label(root, text="Advanced Torrent Tracker", font=("Arial", 24, "bold"), foreground="white")
        self.title_label.pack(pady=10)

        # Add a frame for server control
        self.server_frame = tb.Frame(root)
        self.server_frame.pack(fill=tk.X, pady=10)

        # Start Server Button
        self.start_button = tb.Button(self.server_frame, text="Start Tracker", bootstyle="success",
                                      command=self.start_tracker)
        self.start_button.pack(side=tk.LEFT, padx=10)

        # Stop Server Button
        self.stop_button = tb.Button(self.server_frame, text="Stop Tracker", bootstyle="danger",
                                     command=self.stop_tracker, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        # Refresh Button
        self.refresh_button = tb.Button(self.server_frame, text="Refresh", bootstyle="info", command=self.refresh_info,
                                        state=tk.DISABLED)
        self.refresh_button.pack(side=tk.LEFT, padx=10)

        # Tabbed View for Torrents and Log
        self.tab_control = ttk.Notebook(root)
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab2 = ttk.Frame(self.tab_control)
        self.tab3 = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab1, text='Torrents')
        self.tab_control.add(self.tab2, text='Server Log')
        self.tab_control.add(self.tab3, text='Live Stats')
        self.tab_control.pack(expand=1, fill='both')

        # Torrent Table
        self.tracker_info = ttk.Treeview(self.tab1, columns=("Torrent", "Peers"), show="headings", height=8)
        self.tracker_info.heading("Torrent", text="Torrent Info Hash")
        self.tracker_info.heading("Peers", text="Number of Peers")
        self.tracker_info.pack(fill=tk.BOTH, expand=True)

        # Log Text Box
        self.log_text = scrolledtext.ScrolledText(self.tab2, wrap=tk.WORD, height=15, background="#2E2E2E", foreground="white")
        self.log_text.pack(expand=True, fill='both')

        # Real-time Chart Section
        self.chart_frame = tb.Frame(self.tab3)
        self.chart_frame.pack(fill=tk.BOTH, expand=True)

        self.fig, self.ax = plt.subplots(figsize=(5, 4), facecolor='#2E2E2E')
        self.ax.set_facecolor('#2E2E2E')
        self.ax.set_title("Live Peer Stats", color='white')
        self.ax.set_xlabel("Time", color='white')
        self.ax.set_ylabel("Number of Peers", color='white')
        self.ax.tick_params(colors='white')

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Server State
        self.server_running = False
        self.peer_count_history = []

        # Automatically refresh stats every 5 seconds
        self.update_chart()

    def log(self, message):
        """Function to log messages to the GUI"""
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.yview(tk.END)

    def start_tracker(self):
        if not self.server_running:
            try:
                server_thread = threading.Thread(target=run_tracker, args=(self,))
                server_thread.daemon = True
                server_thread.start()
                self.server_running = True
                self.log("Tracker started on port 6969...")
                messagebox.showinfo("Tracker Started", "Torrent tracker is running.")
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.refresh_button.config(state=tk.NORMAL)
            except Exception as e:
                self.log(f"Failed to start tracker: {e}")

    def stop_tracker(self):
        if self.server_running and self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_running = False
            self.log("Tracker stopped.")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.refresh_button.config(state=tk.DISABLED)

    def refresh_info(self):
        self.tracker_info.delete(*self.tracker_info.get_children())
        for info_hash, data in TorrentTracker.torrents.items():
            self.tracker_info.insert('', tk.END, values=(info_hash, len(data['peers'])))
        self.log("Tracker info refreshed.")

    def update_chart(self):
        if self.server_running:
            total_peers = sum(len(data['peers']) for data in TorrentTracker.torrents.values())
            self.peer_count_history.append(total_peers)
            if len(self.peer_count_history) > 10:
                self.peer_count_history.pop(0)

            self.ax.clear()
            self.ax.set_facecolor('#2E2E2E')
            self.ax.set_title("Live Peer Stats", color='white')
            self.ax.set_xlabel("Time", color='white')
            self.ax.set_ylabel("Number of Peers", color='white')
            self.ax.plot(self.peer_count_history, color='lightgreen')
            self.canvas.draw()

        self.root.after(5000, self.update_chart)


if __name__ == "__main__":
    root = tk.Tk()
    app = TorrentTrackerGUI(root)
    root.mainloop()
