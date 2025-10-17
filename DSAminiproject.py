import socket
import struct
import threading
import time
import random
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog

PACKET_BUFFER_SIZE = 50

class PacketAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Packet Analyzer — Subtle Edition")
        self.master.geometry("1000x650")
        self.packet_buffer = []
        self.stats_protocol = {'TCP': 0, 'UDP': 0, 'Other': 0}
        self.stats_ports = {}
        self.stats_ips = {}
        self.running = False
        self.paused = False
        self.capture_thread = None
        self.start_time = None
        self.error_count = 0
        self.packet_limit = PACKET_BUFFER_SIZE
        self.demo_mode = True  # Default to demo

        # Toolbar
        toolbar = tb.Frame(self.master, style="light", padding=12)
        toolbar.pack(fill="x", pady=(8,2))
        self.start_button = tb.Button(toolbar, text="Start", width=11, bootstyle=SECONDARY, command=self.start_capture)
        self.start_button.pack(side="left", padx=8)
        self.stop_button = tb.Button(toolbar, text="Stop", width=11, bootstyle=LIGHT, command=self.stop_capture)
        self.stop_button.pack(side="left", padx=8)
        self.pause_button = tb.Button(toolbar, text="Pause", width=11, bootstyle=INFO, command=self.toggle_pause)
        self.pause_button.pack(side="left", padx=8)
        self.mode_button = tb.Button(toolbar, text="Demo Mode", width=12, bootstyle=PRIMARY, command=self.toggle_mode)
        self.mode_button.pack(side="left", padx=16)
        tb.Label(toolbar, text="Protocol:", bootstyle=LIGHT).pack(side="left", padx=(20,2))
        self.protocol_filter = tb.StringVar(value="ALL")
        self.protocol_select = tb.Combobox(toolbar, textvariable=self.protocol_filter, state="readonly", width=8, values=["ALL","TCP","UDP","Other"])
        self.protocol_select.pack(side="left")
        self.protocol_select.bind("<<ComboboxSelected>>", lambda _: self.refresh_table())
        tb.Label(toolbar, text="Port:", bootstyle=LIGHT).pack(side="left", padx=8)
        self.port_filter = tb.Entry(toolbar, width=8)
        self.port_filter.pack(side="left")
        self.port_filter.bind("<KeyRelease>", lambda _: self.refresh_table())
        tb.Button(toolbar, text="Clear", width=10, bootstyle=WARNING, command=self.clear_display).pack(side="left", padx=12)
        tb.Button(toolbar, text="Save CSV", width=10, bootstyle=LIGHT, command=self.save_to_csv).pack(side="right", padx=12)
        tb.Button(toolbar, text="About", width=8, bootstyle=SECONDARY, command=self.show_about).pack(side="right", padx=11)

        # Progress bar
        self.progress = tb.Progressbar(self.master, maximum=PACKET_BUFFER_SIZE, style="info-striped")
        self.progress.pack(fill="x", pady=(6,0), padx=33)
        self.progress["value"] = 0

        # Stats panel
        stats_panel = tb.Frame(self.master, style="light", padding=9)
        stats_panel.pack(fill="x", pady=(6,0))
        self.stats_label = tb.Label(stats_panel, text="Packets: 0  TCP: 0  UDP: 0  Other: 0", bootstyle=INFO)
        self.stats_label.pack(side="left", padx=14)
        self.top_ip_label = tb.Label(stats_panel, text="Top IPs: -", bootstyle=LIGHT)
        self.top_ip_label.pack(side="left", padx=16)
        self.top_port_label = tb.Label(stats_panel, text="Top Ports: -", bootstyle=LIGHT)
        self.top_port_label.pack(side="left", padx=16)
        self.timer_label = tb.Label(stats_panel, text="00:00", bootstyle=INFO)
        self.timer_label.pack(side="right", padx=18)

        # Table panel
        table_panel = tb.Frame(self.master, style="light")
        table_panel.pack(fill="both", expand=True, padx=20, pady=14)
        columns = ("idx","src","sport","dst","dport","proto")
        self.packet_table = tb.Treeview(table_panel, columns=columns, show="headings", height=21, bootstyle="light")
        self.packet_table.heading("idx", text="#")
        self.packet_table.heading("src", text="Source IP")
        self.packet_table.heading("sport", text="Src Port")
        self.packet_table.heading("dst", text="Destination IP")
        self.packet_table.heading("dport", text="Dst Port")
        self.packet_table.heading("proto", text="Protocol")
        self.packet_table.column("idx", width=55)
        self.packet_table.column("src", width=145)
        self.packet_table.column("sport", width=105)
        self.packet_table.column("dst", width=145)
        self.packet_table.column("dport", width=105)
        self.packet_table.column("proto", width=110)
        # Gentle row colors
        self.packet_table.tag_configure('oddrow', background='#f9f9fc')
        self.packet_table.tag_configure('evenrow', background='#f3f6f9')
        self.packet_table.pack(fill="both", expand=True, pady=3)
        self.packet_table.bind("<Double-1>", self.show_packet_details)

        # Status bar
        self.status_var = tb.StringVar(value="Ready.")
        statusbar = tb.Label(self.master, textvariable=self.status_var, bootstyle=LIGHT, anchor="w", font=("Segoe UI", 10))
        statusbar.pack(fill="x", side="bottom", pady=(0,2))

        self.update_timer()
        self.refresh_table()
        self.update_stats_display()

    def toggle_mode(self):
        self.demo_mode = not self.demo_mode
        if self.demo_mode:
            self.mode_button.config(text="Demo Mode", bootstyle=PRIMARY)
            self.status_var.set("Demo mode enabled, instant fast capture.")
        else:
            self.mode_button.config(text="Live Mode", bootstyle=SECONDARY)
            self.status_var.set("Live mode enabled, real packet capture (admin/root).")

    def create_fake_packet(self):
        protocols = ["TCP", "UDP", "Other"]
        src_ip = f"192.168.1.{random.randint(1,254)}"
        dst_ip = f"192.168.1.{random.randint(1,254)}"
        proto = random.choice(protocols)
        sport = random.randint(1000, 9000)
        dport = random.randint(1000, 9000)
        raw = b"FAKEPACKETDATA" + bytes(random.randint(0,255) for _ in range(45))
        return {
            "src": src_ip, "dst": dst_ip, "proto": proto,
            "sport": sport, "dport": dport, "raw": raw
        }

    def parse_packet(self, raw_data):
        try:
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            proto_num = iph[6]
            proto = {6:'TCP', 17:'UDP'}.get(proto_num, 'Other')
            iph_length = (iph[0] & 0xF) * 4
            sport = dport = "-"
            if proto == "TCP":
                tcp_header = raw_data[iph_length:iph_length+4]
                tcph = struct.unpack('!HH', tcp_header)
                sport, dport = tcph[0], tcph[1]
            elif proto == "UDP":
                udp_header = raw_data[iph_length:iph_length+4]
                udph = struct.unpack('!HH', udp_header)
                sport, dport = udph[0], udph[1]
            return {
                "src": src_ip, "dst": dst_ip, "proto": proto,
                "sport": sport, "dport": dport, "raw": raw_data
            }
        except Exception:
            self.error_count += 1
            return {
                "src": "ERR", "dst": "-", "proto": "Other",
                "sport": "-", "dport": "-", "raw": b''
            }

    def capture_packets(self):
        cnt = 0
        if self.demo_mode:
            while self.running and cnt < self.packet_limit:
                info = self.create_fake_packet()
                self.packet_buffer.append(info)
                self.stats_protocol[info['proto']] = self.stats_protocol.get(info['proto'], 0) + 1
                for port_key in ['sport','dport']:
                    val = info[port_key]
                    if val != "-" and isinstance(val, int):
                        self.stats_ports[val] = self.stats_ports.get(val,0)+1
                for ipkey in ['src','dst']:
                    val = info[ipkey]
                    if val != "ERR":
                        self.stats_ips[val] = self.stats_ips.get(val,0)+1
                if cnt % 2 == 0:
                    self.master.after(0, self.refresh_table)
                    self.master.after(0, self.update_stats_display)
                    self.master.after(0, lambda v=cnt: self.progress.config(value=v))
                cnt += 1
                time.sleep(0.07)
            self.running = False
            self.status_var.set(f"Demo finished. {cnt} packets.")
        else:
            try:
                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sniffer.bind(('0.0.0.0', 0))
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except Exception as e:
                self.master.after(0, lambda: self.status_var.set(f"Socket creation failed: {e}"))
                return

            while self.running and cnt < self.packet_limit:
                try:
                    raw_data, _ = sniffer.recvfrom(65565)
                    info = self.parse_packet(raw_data)
                    self.packet_buffer.append(info)
                    proto = info['proto']
                    self.stats_protocol[proto] = self.stats_protocol.get(proto,0)+1
                    for port_key in ['sport','dport']:
                        val = info[port_key]
                        if val != "-" and isinstance(val, int):
                            self.stats_ports[val] = self.stats_ports.get(val,0)+1
                    for ipkey in ['src','dst']:
                        val = info[ipkey]
                        if val != "ERR":
                            self.stats_ips[val] = self.stats_ips.get(val,0)+1
                    if cnt % 2 == 0:
                        self.master.after(0, self.refresh_table)
                        self.master.after(0, self.update_stats_display)
                        self.master.after(0, lambda v=cnt: self.progress.config(value=v))
                    cnt += 1
                    time.sleep(0.03)
                except Exception:
                    self.error_count += 1
                    continue
            self.running = False
            self.status_var.set(f"Capture finished. {cnt} packets.")

    def start_capture(self):
        if self.running:
            return
        self.running = True
        self.paused = False
        self.packet_buffer.clear()
        self.progress["value"] = 0
        self.stats_protocol = {'TCP': 0, 'UDP': 0, 'Other': 0}
        self.stats_ports = {}
        self.stats_ips = {}
        self.error_count = 0
        self.start_time = time.time()
        self.status_var.set("Capture started.")
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.running = False
        self.status_var.set(f"Capture stopped, {self.error_count} packet errors.")

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_button.config(text="Resume" if self.paused else "Pause")
        self.status_var.set("Paused." if self.paused else "Resumed.")

    def clear_display(self):
        self.packet_buffer.clear()
        self.progress["value"] = 0
        self.refresh_table()
        self.status_var.set("Display cleared.")

    def save_to_csv(self):
        if len(self.packet_buffer) == 0:
            messagebox.showinfo("No Data", "No packets to save.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if filename:
            with open(filename, "w") as f:
                f.write("Index,Source,SourcePort,Destination,DestinationPort,Protocol\n")
                for idx, info in enumerate(self.packet_buffer):
                    f.write(f"{idx+1},{info['src']},{info['sport']},{info['dst']},{info['dport']},{info['proto']}\n")
            self.status_var.set(f"Saved packet table to {filename}")

    def show_about(self):
        messagebox.showinfo("About", "Network Packet Analyzer — Subtle Journal Edition\nClean interface, modern flat buttons, light colors, Demo Mode for instant test.\nSwitch to Live mode for real capture.")

    def update_stats_display(self):
        total = len(self.packet_buffer)
        t = self.stats_protocol['TCP']
        u = self.stats_protocol['UDP']
        o = self.stats_protocol['Other']
        self.stats_label.config(text=f"Packets: {total}  TCP: {t}  UDP: {u}  Other: {o}  Errors: {self.error_count}")

        if self.stats_ips:
            topips = sorted(self.stats_ips.items(), key=lambda kv: -kv[1])[:3]
            topipstr = ", ".join([f"{ip}({c})" for ip,c in topips])
        else:
            topipstr = "-"
        self.top_ip_label.config(text=f"Top IPs: {topipstr}")

        if self.stats_ports:
            topports = sorted(self.stats_ports.items(), key=lambda kv: -kv[1])[:3]
            topportstr = ", ".join([f"{port}({c})" for port,c in topports])
        else:
            topportstr = "-"
        self.top_port_label.config(text=f"Top Ports: {topportstr}")

    def get_port_filter(self):
        try:
            val = self.port_filter.get().strip()
            if val == "":
                return None
            num = int(val)
            return num
        except Exception:
            return None

    def refresh_table(self):
        self.packet_table.delete(*self.packet_table.get_children())
        protofilt = self.protocol_filter.get()
        portfilt = self.get_port_filter()
        shown = 0
        for idx, info in enumerate(self.packet_buffer[-100:]):
            tag = 'evenrow' if (idx % 2 == 0) else 'oddrow'
            if protofilt != "ALL" and info['proto'] != protofilt:
                continue
            if portfilt and (info['sport'] != portfilt and info['dport'] != portfilt):
                continue
            self.packet_table.insert("", "end", values=(idx+1, info['src'], info['sport'], info['dst'], info['dport'], info['proto']), tags=(tag,))
            shown += 1
        self.status_var.set(f"Table refreshed. Showing {shown} packets.")

    def show_packet_details(self, event):
        sel = self.packet_table.selection()
        if not sel:
            return
        iid = sel[0]
        vals = self.packet_table.item(iid)["values"]
        idx = int(vals[0])-1
        pkt = self.packet_buffer[idx]
        msg = f"""Source IP: {pkt['src']}
Source Port: {pkt['sport']}
Destination IP: {pkt['dst']}
Destination Port: {pkt['dport']}
Protocol: {pkt['proto']}
Raw header (first 45B):\n{pkt['raw'][:45]!r}"""
        messagebox.showinfo(f"Packet #{vals[0]}", msg)

    def update_timer(self):
        if self.start_time and self.running:
            elapsed = int(time.time() - self.start_time)
            mins = elapsed // 60
            secs = elapsed % 60
            self.timer_label.config(text=f"{mins:02}:{secs:02}")
        self.master.after(1000, self.update_timer)

if __name__ == "__main__":
    root = tb.Window(themename="journal")  # "journal" = minimal flat, "pulse" and "morph" also good
    app = PacketAnalyzerGUI(root)
    root.mainloop()
