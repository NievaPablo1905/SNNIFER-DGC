#!/usr/bin/env python3
"""
SNNIFER-DGC - Sniffer GUI v10

- Persistencia de historial en SQLite (DB dentro de carpeta de evidencia).
- Exportar bitácora GUI a .txt y .csv desde la app.
- Visualizador interactivo: doble-clic en Listbox muestra detalles de AP/cliente/dispositivo.
- Integración básica con parsers de pcap (parse_pcap_summary) y opción para abrir NetworkMiner si existe.
- Detección de plataforma y guard rails para Windows/macOS (avisa cuando captura no disponible).
- Mejoras de robustez y modularidad.
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import subprocess
import threading
import os
import time
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import sqlite3
import platform
import shutil

# scapy and report generator
try:
    import scapy.all as scapy
except Exception:
    scapy = None

from report_integrado_Version2 import generar_pdf_integrado

# UI colors
BG_DARK = "#202333"
PANEL = "#282a40"
ACCENT1 = "#00bfae"
BTN = "#1976d2"
BTN2 = "#43a047"
BTN_TXT = "#fff"

# Channels
CANALES_24GHZ = list(range(1, 14))
CANALES_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]

MAX_LISTBOX_ITEMS = 2000
LOG_FILENAME = "snifferdgc.log"
LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 5

# Logger
logger = logging.getLogger("snifferdgc")
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = RotatingFileHandler(LOG_FILENAME, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logger.addHandler(fh)


class DBStore:
    """Simple SQLite persistence for detections and logs."""
    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.conn = sqlite3.connect(dbpath, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS lan_devices(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        mac TEXT,
                        ts TEXT
                    )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wifi_aps(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        bssid TEXT UNIQUE,
                        essid TEXT,
                        channel TEXT,
                        ts TEXT
                    )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wifi_clients(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        bssid TEXT,
                        client_mac TEXT,
                        ts TEXT
                    )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS logs(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        level TEXT,
                        msg TEXT,
                        ts TEXT
                    )""")
        self.conn.commit()

    def insert_lan(self, ip, mac):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO lan_devices(ip,mac,ts) VALUES(?,?,?)", (ip, mac, datetime.utcnow().isoformat()))
        self.conn.commit()

    def insert_ap(self, bssid, essid, channel):
        cur = self.conn.cursor()
        try:
            cur.execute("INSERT OR REPLACE INTO wifi_aps(bssid,essid,channel,ts) VALUES(?,?,?,?)",
                        (bssid, essid, str(channel), datetime.utcnow().isoformat()))
            self.conn.commit()
        except Exception:
            logger.exception("DB insert_ap failed for %s", bssid)

    def insert_client(self, bssid, client_mac):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO wifi_clients(bssid,client_mac,ts) VALUES(?,?,?)", (bssid, client_mac, datetime.utcnow().isoformat()))
        self.conn.commit()

    def insert_log(self, level, msg):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO logs(level,msg,ts) VALUES(?,?,?)", (level, msg, datetime.utcnow().isoformat()))
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


class SnifferDGC_GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNNIFER-DGC - Escaneo Forense LAN y Aire WiFi (Multicanal Tiempo real) - v10")
        self.geometry("1280x820")

        # State
        self.lan_historial = []
        self.wifi_historial = {}
        self.wifi_clientes = {}
        self.escuchando = {"lan": False, "wifi": False}
        self.threads = {"lan": None, "wifi": None}
        self.carpeta_evidencia = None
        self.wifi_timer_running = False
        self.db = None  # DBStore once evidence folder created

        # Build UI
        self._build_scrollable_area()
        self.create_widgets()
        self.configure(bg=BG_DARK)

        logger.info("SNNIFER-DGC GUI started (v10)")

    # ---------- UI scaffolding ----------
    def _build_scrollable_area(self):
        self.canvas = tk.Canvas(self, bg=BG_DARK, highlightthickness=0)
        self.v_scroll = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.h_scroll = tk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=self.v_scroll.set, xscrollcommand=self.h_scroll.set)
        self.v_scroll.pack(side="right", fill="y")
        self.h_scroll.pack(side="bottom", fill="x")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner_frame = tk.Frame(self.canvas, bg=BG_DARK)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")
        self.inner_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.canvas_window, width=e.width))

    def crear_carpeta_evidencia(self):
        fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_default = f"evidencia_{fecha}"
        nombre = simpledialog.askstring("Nombre carpeta de evidencia",
                                        "Nombre para la carpeta de evidencia:",
                                        initialvalue=nombre_default, parent=self)
        if not nombre:
            nombre = nombre_default
        base_ruta = filedialog.askdirectory(title="Selecciona carpeta base para evidencia") or os.path.abspath(".")
        carpeta = os.path.join(base_ruta, nombre)
        os.makedirs(carpeta, exist_ok=True)
        self.carpeta_evidencia = carpeta

        # add evidence log handler
        try:
            evid_log_path = os.path.join(carpeta, "evidence_log.txt")
            fh_evidence = RotatingFileHandler(evid_log_path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
            fh_evidence.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
            logger.addHandler(fh_evidence)
            logger.info(f"Evidence folder set: {carpeta}. Log handler created at {evid_log_path}")
        except Exception:
            logger.exception("Failed to create evidence log handler")

        # create sqlite db inside evidence folder
        try:
            dbpath = os.path.join(carpeta, "evidence.db")
            self.db = DBStore(dbpath)
            logger.info("SQLite DB created at %s", dbpath)
            self.log_event(f"Carpeta de evidencia configurada: {carpeta}", color="#ffe940")
        except Exception:
            logger.exception("Failed to create evidence DB")
            self.log_event("No se pudo crear DB de evidencia", color="red")

        messagebox.showinfo("Carpeta de evidencia", f"Todos los archivos se guardarán en:\n{carpeta}")

    def create_widgets(self):
        top = tk.Frame(self.inner_frame, bg=PANEL)
        top.pack(fill="x")
        ttk.Label(top, text="SNNIFER-DGC - Escaneo LAN y Aire WiFi (MULTICANAL REAL) - v10",
                  font=("Arial", 20, "bold"), background=PANEL, foreground=BTN_TXT).pack(pady=12)

        frame = tk.Frame(self.inner_frame, bg=BG_DARK)
        frame.pack(pady=6, fill="x")

        # Buttons row (now includes export & analyze)
        tk.Button(frame, text="Crear carpeta evidencia", font=("Arial", 11, "bold"),
                  command=self.crear_carpeta_evidencia, fg=BTN_TXT, bg=BTN, width=20).grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.btn_lan = tk.Button(frame, text="Escuchar LAN tiempo real", font=("Arial", 11, "bold"),
                                 fg=BTN_TXT, bg=BTN, width=20, command=self.boot_lan_real)
        self.btn_lan.grid(row=0, column=1, padx=6)
        self.btn_wifi = tk.Button(frame, text="Escuchar WiFi MULTICANAL", font=("Arial", 11, "bold"),
                                  fg=BTN_TXT, bg=BTN2, width=22, command=self.boot_wifi_multicanal_real)
        self.btn_wifi.grid(row=0, column=2, padx=6)
        tk.Button(frame, text="Capturar .pcap LAN + NM", font=("Arial", 11), fg=BTN_TXT, bg="#8642d2", width=20,
                  command=self.capture_lan_pcap).grid(row=0, column=3, padx=6)
        tk.Button(frame, text="Capturar .pcap WiFi + NM", font=("Arial", 11), fg=BTN_TXT, bg="#3c82d2", width=20,
                  command=self.capture_wifi_pcap).grid(row=0, column=4, padx=6)
        tk.Button(frame, text="Generar informe PDF", font=("Arial", 11), fg=BTN_TXT, bg=ACCENT1, width=16,
                  command=self.generar_informe_pdf).grid(row=0, column=5, padx=6)
        tk.Button(frame, text="Exportar bitácora", font=("Arial", 11), fg=BTN_TXT, bg="#ff8a00", width=14,
                  command=self.export_log_menu).grid(row=0, column=6, padx=6)

        # Interface selectors
        tk.Label(frame, text="Interfaz LAN:", bg=BG_DARK, fg=ACCENT1, font=("Arial", 10)).grid(row=1, column=0, padx=2, sticky="w")
        self.iface_lan = tk.StringVar(value="eth0")
        tk.Entry(frame, textvariable=self.iface_lan, width=12, font=("Arial", 10)).grid(row=1, column=1, padx=2, sticky="w")

        tk.Label(frame, text="Interfaz WiFi:", bg=BG_DARK, fg=ACCENT1, font=("Arial", 10)).grid(row=1, column=2, padx=2, sticky="w")
        self.iface_wifi = tk.StringVar(value="wlan0")
        tk.Entry(frame, textvariable=self.iface_wifi, width=12, font=("Arial", 10)).grid(row=1, column=3, padx=2, sticky="w")

        tk.Label(frame, text="Dur. Canal WiFi (s):", bg=BG_DARK, fg=ACCENT1, font=("Arial", 10)).grid(row=1, column=4, padx=2, sticky="w")
        self.duracion_wifi = tk.IntVar(value=3)
        tk.Entry(frame, textvariable=self.duracion_wifi, width=6, font=("Arial", 10)).grid(row=1, column=5, padx=2, sticky="w")

        # Options: multichannel and bands
        self.multicanal_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="Escaneo Multi-canal", font=("Arial", 10), variable=self.multicanal_var,
                       bg=BG_DARK, fg=BTN_TXT, selectcolor=ACCENT1).grid(row=2, column=0, sticky="w")
        self.band_24_var = tk.BooleanVar(value=True)
        self.band_5_var = tk.BooleanVar(value=False)
        tk.Checkbutton(frame, text="2.4GHz", font=("Arial", 10), variable=self.band_24_var, bg=BG_DARK,
                       fg=BTN_TXT, selectcolor=ACCENT1).grid(row=2, column=1, sticky="w")
        tk.Checkbutton(frame, text="5GHz", font=("Arial", 10), variable=self.band_5_var, bg=BG_DARK,
                       fg=BTN_TXT, selectcolor=ACCENT1).grid(row=2, column=2, sticky="w")

        # Notebook for results
        self.result_notebook = ttk.Notebook(self.inner_frame)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=BTN_TXT, font=("Arial", 11, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT1)], foreground=[("selected", "#222")])

        self.lan_tab = tk.Frame(self.result_notebook, bg=BG_DARK)
        self.aire_tab = tk.Frame(self.result_notebook, bg=BG_DARK)
        self.result_notebook.add(self.lan_tab, text="Resultados LAN")
        self.result_notebook.add(self.aire_tab, text="Resultados Aire WiFi")
        self.result_notebook.pack(fill="both", expand=True, padx=10, pady=6)

        # LAN results Listbox + scrollbar
        lan_frame = tk.Frame(self.lan_tab, bg=BG_DARK)
        lan_frame.pack(fill="both", expand=True)
        self.lan_listbox = tk.Listbox(lan_frame, font=("Consolas", 10), bg="#252855", fg=BTN_TXT, activestyle="none")
        self.lan_scroll = tk.Scrollbar(lan_frame, orient="vertical", command=self.lan_listbox.yview)
        self.lan_listbox.config(yscrollcommand=self.lan_scroll.set)
        self.lan_listbox.pack(side="left", fill="both", expand=True)
        self.lan_scroll.pack(side="right", fill="y")
        self.lan_listbox.bind("<Double-Button-1>", self.on_lan_double_click)

        # Aire WiFi results Listbox + scrollbar and Clients listbox
        aire_top = tk.Frame(self.aire_tab, bg=BG_DARK)
        aire_top.pack(fill="both", expand=True)
        self.aire_listbox = tk.Listbox(aire_top, font=("Consolas", 10), bg="#235855", fg=BTN_TXT, activestyle="none")
        aire_scroll = tk.Scrollbar(aire_top, orient="vertical", command=self.aire_listbox.yview)
        self.aire_listbox.config(yscrollcommand=aire_scroll.set)
        self.aire_listbox.pack(side="left", fill="both", expand=True)
        aire_scroll.pack(side="right", fill="y")
        self.aire_listbox.bind("<Double-Button-1>", self.on_aire_double_click)

        # Clients area
        clients_frame = tk.Frame(self.aire_tab, bg=BG_DARK)
        clients_frame.pack(fill="both")
        tk.Label(clients_frame, text="Clientes WiFi (por BSSID):", bg=BG_DARK, fg=ACCENT1, font=("Arial", 10, "bold")).pack(anchor="w")
        self.clients_listbox = tk.Listbox(clients_frame, font=("Consolas", 10), bg="#1f3a3a", fg=BTN_TXT)
        clients_scroll = tk.Scrollbar(clients_frame, orient="vertical", command=self.clients_listbox.yview)
        self.clients_listbox.config(yscrollcommand=clients_scroll.set)
        self.clients_listbox.pack(side="left", fill="both", expand=True)
        clients_scroll.pack(side="right", fill="y")
        self.clients_listbox.bind("<Double-Button-1>", self.on_client_double_click)

        # Console / log area (Text) below
        sep1 = tk.Label(self.inner_frame, text="", bg=BG_DARK)
        sep1.pack(pady=4)
        cons_frame = tk.Frame(self.inner_frame, bg="#191b1e")
        cons_frame.pack(fill="x", padx=8, pady=4)
        tk.Label(cons_frame, text="📝 Consola eventos / errores:", fg=ACCENT1, bg="#191b1e", font=("Arial", 11, "bold")).pack(anchor="w")
        self.logarea = tk.Text(cons_frame, font=("Consolas", 11), height=7, bg="#232333", fg="#fff")
        self.logarea.pack(fill="both", expand=True)

        # Timer display
        self.timer_frame = tk.Frame(self.inner_frame, bg=BG_DARK)
        self.timer_var = tk.StringVar(value="")
        self.timer_lbl = tk.Label(self.timer_frame, textvariable=self.timer_var, bg=BG_DARK, fg="#ffef00", font=("Arial", 12, "bold"))
        self.timer_lbl.pack()
        self.timer_frame.pack(fill="x")

    # ---------- callbacks for double click (visualizer) ----------
    def on_lan_double_click(self, event):
        sel = self.lan_listbox.curselection()
        if not sel:
            return
        row = self.lan_listbox.get(sel[0])
        messagebox.showinfo("Detalle dispositivo LAN", row)

    def on_aire_double_click(self, event):
        sel = self.aire_listbox.curselection()
        if not sel:
            return
        row = self.aire_listbox.get(sel[0])
        # parse bssid if present
        # show AP details and list clients if present
        parts = row.split("BSSID:")
        details = row
        if len(parts) > 1:
            bssid = parts[-1].strip()
            clients = list(self.wifi_clientes.get(bssid, []))
            details = f"{row}\n\nClientes asociados ({len(clients)}):\n" + ("\n".join(clients) if clients else "Ninguno")
        messagebox.showinfo("Detalle AP", details)

    def on_client_double_click(self, event):
        sel = self.clients_listbox.curselection()
        if not sel:
            return
        row = self.clients_listbox.get(sel[0])
        messagebox.showinfo("Detalle cliente", row)

    # ---------- LAN sniffing ----------
    def boot_lan_real(self):
        if not self.escuchando["lan"]:
            self.escuchando["lan"] = True
            self.btn_lan.config(text="DETENER ESCUCHA LAN", bg="red")
            self.lan_listbox.delete(0, tk.END)
            self.lan_historial.clear()
            th = threading.Thread(target=self._lan_real_thread, daemon=True)
            self.threads["lan"] = th
            th.start()
            self.log_event("Iniciada escucha LAN en tiempo real.")
            logger.info("LAN listener started")
        else:
            self.escuchando["lan"] = False
            self.btn_lan.config(text="Escuchar LAN tiempo real", bg=BTN)
            self.log_event("Escucha LAN detenida.")
            logger.info("LAN listener stopped")

    def _lan_real_thread(self):
        if scapy is None:
            self.after(0, lambda: self.log_event("scapy no está disponible, instálalo con 'pip install scapy'", color="red"))
            logger.error("scapy not available")
            return
        iface = self.iface_lan.get()
        macs_vistos = set()

        def pkt_handler(pkt):
            try:
                if pkt.haslayer(scapy.Ether):
                    mac = pkt[scapy.Ether].src
                    ip = "-"
                    try:
                        if hasattr(pkt, "payload") and hasattr(pkt.payload, "payload") and hasattr(pkt.payload.payload, "src"):
                            ip = pkt.payload.payload.src
                    except Exception:
                        ip = "-"
                    if mac not in macs_vistos:
                        macs_vistos.add(mac)
                        self.lan_historial.append({'ip': ip, 'mac': mac})
                        if self.db:
                            try:
                                self.db.insert_lan(ip, mac)
                            except Exception:
                                logger.exception("DB insert lan failed")
                        row = f"Dispositivo LAN: {ip:15}  MAC: {mac}"
                        self.after(0, lambda r=row: self._insert_lan_row(r))
                        self.log_event(f"[VIVO][LAN] {ip} - {mac}", color="#7cf37f")
                        logger.info("LAN detected: %s %s", ip, mac)
            except Exception as e:
                logger.exception("Error in LAN packet handler: %s", e)
                self.after(0, lambda: self.log_event(f"Error LAN pkt handler: {e}", color="red"))

        try:
            scapy.sniff(iface=iface, prn=pkt_handler, store=0, stop_filter=lambda x: not self.escuchando["lan"])
        except Exception as e:
            logger.exception("Error in LAN sniffing: %s", e)
            self.after(0, lambda: self.log_event(f"Error en escaneo LAN: {e}", color="red"))
        finally:
            self.after(0, lambda: self._insert_lan_row("Escucha LAN finalizada."))
            self.escuchando["lan"] = False
            logger.info("LAN listener finished")

    def _insert_lan_row(self, text):
        self.lan_listbox.insert(tk.END, text)
        self.lan_listbox.see(tk.END)
        if self.lan_listbox.size() > MAX_LISTBOX_ITEMS:
            self.lan_listbox.delete(0, self.lan_listbox.size() - MAX_LISTBOX_ITEMS)

    # ---------- WIFI sniffing (multicanal) ----------
    def boot_wifi_multicanal_real(self):
        if not self.escuchando["wifi"]:
            self.escuchando["wifi"] = True
            self.btn_wifi.config(text="DETENER ESCUCHA WIFI", bg="red")
            self.aire_listbox.delete(0, tk.END)
            self.clients_listbox.delete(0, tk.END)
            self.wifi_historial.clear()
            self.wifi_clientes.clear()
            canales = []
            if self.multicanal_var.get():
                if self.band_24_var.get():
                    canales += CANALES_24GHZ
                if self.band_5_var.get():
                    canales += CANALES_5GHZ
                if not canales:
                    canales = [1]
            else:
                canales = [1]
            dur_total = max(1, self.duracion_wifi.get()) * len(canales)
            self.wifi_timer_running = True
            self.timer_var.set(f"Tiempo restante: {dur_total} s")
            th = threading.Thread(target=self._wifi_realtime_multicanal_thread,
                                  args=(self.iface_wifi.get(), canales[:], self.duracion_wifi.get(), dur_total),
                                  daemon=True)
            self.threads["wifi"] = th
            th.start()
            self._start_timer(dur_total)
            self.log_event(f"Iniciada escucha WiFi multicanal en tiempo real ({len(canales)} canales).")
            logger.info("WiFi listener started")
        else:
            self.escuchando["wifi"] = False
            self.btn_wifi.config(text="Escuchar WiFi MULTICANAL", bg=BTN2)
            self.wifi_timer_running = False
            self.timer_var.set("")
            self.log_event("Escucha WiFi detenida.")
            logger.info("WiFi listener stopped")

    def _wifi_realtime_multicanal_thread(self, iface, canales, duracion_por_canal, tiempo_total):
        if scapy is None:
            self.after(0, lambda: self.log_event("scapy no está disponible, instálalo con 'pip install scapy'", color="red"))
            logger.error("scapy not available")
            return
        bssids_vistos = set()
        tiempo_inicial = time.time()

        try:
            # Check interface mode (best-effort; on Windows/macOS may not be available)
            try:
                if platform.system().lower() == "linux":
                    iwconfig_out = subprocess.check_output(['iwconfig', iface], stderr=subprocess.STDOUT).decode(errors="ignore")
                    if "Mode:Monitor" not in iwconfig_out and "Monitor" not in iwconfig_out:
                        self.after(0, lambda: self.log_event(f"¡Atención! La interfaz {iface} no está en modo monitor.", color="red"))
                        self.after(0, lambda: self._insert_aire_row(f"¡ERROR! {iface} no está en modo monitor."))
                        self.escuchando["wifi"] = False
                        logger.warning("Interface not in monitor mode: %s", iface)
                        return
                else:
                    # On non-linux platforms, we can't rely on iwconfig; warn user if needed
                    self.after(0, lambda: self.log_event(f"Plataforma {platform.system()} detectada. Asegúrate que la interfaz está en modo monitor si aplica.", color="#ffdd57"))
            except Exception as errchk:
                self.after(0, lambda: self.log_event(f"Error chequeando modo monitor: {errchk}", color="red"))
                self.escuchando["wifi"] = False
                logger.exception("iwconfig check failed: %s", errchk)
                return

            def pkt_handler(pkt):
                try:
                    if not pkt.haslayer(scapy.Dot11):
                        return
                    dot11 = pkt[scapy.Dot11]
                    # Beacon (AP)
                    if dot11.type == 0 and dot11.subtype == 8:
                        bssid = dot11.addr2
                        essid = dot11.info.decode(errors="ignore") if hasattr(dot11, "info") else "<oculto>"
                        channel = None
                        # populate channel best-effort
                        try:
                            # scapy Dot11Elt parsing
                            for elt in pkt.iterpayloads():
                                if getattr(elt, "ID", None) == 3 and hasattr(elt, "info"):
                                    channel = ord(elt.info[:1]) if elt.info else None
                        except Exception:
                            channel = None
                        channel = channel or getattr(pkt, "channel", None) or "?"
                        if bssid and bssid not in bssids_vistos:
                            bssids_vistos.add(bssid)
                            self.wifi_historial[bssid] = {"essid": essid, "bssid": bssid, "channel": channel}
                            if self.db:
                                try:
                                    self.db.insert_ap(bssid, essid, channel)
                                except Exception:
                                    logger.exception("DB insert_ap error")
                            row = f"AP (canal {channel}): {essid}  BSSID: {bssid}"
                            self.after(0, lambda r=row: self._insert_aire_row(r))
                            self.after(0, lambda can=channel, es=essid, bs=bssid:
                                       self.log_event(f"[VIVO][AIRE] Canal {can}: {es} - {bs}", color="#09dfd0"))
                            logger.info("AP detected: %s %s ch=%s", bssid, essid, channel)
                    # Data frames -> client detection
                    elif dot11.type == 2:
                        bssid = dot11.addr3 or dot11.addr1 or None
                        client_mac = None
                        if dot11.addr2 and dot11.addr1:
                            if bssid and dot11.addr2 != bssid:
                                client_mac = dot11.addr2
                            elif bssid and dot11.addr1 != bssid:
                                client_mac = dot11.addr1
                            else:
                                client_mac = dot11.addr2
                        if bssid and client_mac:
                            bkey = bssid
                            if bkey not in self.wifi_clientes:
                                self.wifi_clientes[bkey] = set()
                            if client_mac not in self.wifi_clientes[bkey]:
                                self.wifi_clientes[bkey].add(client_mac)
                                if self.db:
                                    try:
                                        self.db.insert_client(bkey, client_mac)
                                    except Exception:
                                        logger.exception("DB insert_client error")
                                self.after(0, lambda b=bkey, c=client_mac: self._insert_client(b, c))
                                self.after(0, lambda b=bkey, c=client_mac:
                                           self.log_event(f"[VIVO][CLIENTE] BSSID {b}: cliente {c}", color="#ffd166"))
                                logger.info("Client detected: %s for BSSID %s", client_mac, bkey)
                except Exception as e:
                    logger.exception("Error in WiFi pkt_handler: %s", e)
                    self.after(0, lambda: self.log_event(f"Error en pkt_handler WiFi: {e}", color="red"))

            # main loop
            while self.escuchando["wifi"]:
                for canal in canales:
                    if not self.escuchando["wifi"]:
                        break
                    try:
                        if platform.system().lower() == "linux":
                            subprocess.call(["iwconfig", iface, "channel", str(canal)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(0.25)
                    except Exception as e:
                        self.after(0, lambda: self.log_event(f"Error cambiando canal: {e}", color="red"))
                        logger.exception("Error changing channel: %s", e)
                        continue
                    try:
                        scapy.sniff(iface=iface, prn=pkt_handler, timeout=duracion_por_canal, store=0,
                                    stop_filter=lambda x: not self.escuchando["wifi"])
                    except Exception as e:
                        logger.exception("scapy.sniff error: %s", e)
                        self.after(0, lambda: self.log_event(f"Error en escaneo WiFi: {e}", color="red"))
                    elapsed = time.time() - tiempo_inicial
                    if not self.escuchando["wifi"] or elapsed >= tiempo_total:
                        break
                if not self.escuchando["wifi"] or (time.time() - tiempo_inicial) >= tiempo_total:
                    break

            # finish
            self.escuchando["wifi"] = False
            self.after(0, lambda: self._insert_aire_row("Escucha WiFi multicanal finalizada."))
            self.wifi_timer_running = False
            self.timer_var.set("")
            self.log_event("Escucha WiFi multicanal finalizada.")
            logger.info("WiFi listener finished")
        except Exception as err:
            logger.exception("Fatal error in WiFi thread: %s", err)
            self.after(0, lambda: self.log_event(f"Error fatal en hilo WiFi: {err}", color="red"))
            self.after(0, lambda: self._insert_aire_row(f"Error en hilo WiFi: {err}"))

    def _insert_aire_row(self, text):
        self.aire_listbox.insert(tk.END, text)
        self.aire_listbox.see(tk.END)
        if self.aire_listbox.size() > MAX_LISTBOX_ITEMS:
            self.aire_listbox.delete(0, self.aire_listbox.size() - MAX_LISTBOX_ITEMS)

    def _insert_client(self, bssid, client_mac):
        line = f"{bssid} -> {client_mac}"
        self.clients_listbox.insert(tk.END, line)
        self.clients_listbox.see(tk.END)
        if self.clients_listbox.size() > MAX_LISTBOX_ITEMS:
            self.clients_listbox.delete(0, self.clients_listbox.size() - MAX_LISTBOX_ITEMS)

    # ---------- Timer ----------
    def _start_timer(self, total_secs):
        def update():
            if not self.wifi_timer_running:
                self.timer_var.set("")
                return
            nonlocal_secs = getattr(update, "secs", total_secs)
            mins = nonlocal_secs // 60
            secs = nonlocal_secs % 60
            self.timer_var.set(f"Tiempo restante: {mins:02d}:{secs:02d}")
            if nonlocal_secs > 0 and self.escuchando["wifi"]:
                update.secs = nonlocal_secs - 1
                self.after(1000, update)
            else:
                self.timer_var.set("")
                self.wifi_timer_running = False
        update.secs = total_secs
        self.after(0, update)

    # ---------- PCAP capture & parse ----------
    def capture_lan_pcap(self):
        if platform.system().lower() != "linux":
            self.log_event("Captura LAN .pcap sólo soportada en Linux en esta versión.", color="orange")
            return
        if not self.carpeta_evidencia:
            self.crear_carpeta_evidencia()
        iface = self.iface_lan.get()
        pcap_path = os.path.join(self.carpeta_evidencia, "captura_lan.pcap")
        duracion = simpledialog.askinteger("Duración", "Duración de la captura (segundos):", initialvalue=30, parent=self)
        if not duracion:
            return
        self.log_event(f"Capturando .pcap LAN en {iface} durante {duracion}s...")
        logger.info("Starting tcpdump capture on %s for %ss", iface, duracion)
        try:
            proc = subprocess.Popen(["tcpdump", "-i", iface, "-w", pcap_path, "-G", str(duracion), "-W", "1"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.wait(timeout=duracion + 10)
            self.log_event(f"Archivo .pcap LAN guardado: {pcap_path}", color="#ffe940")
            logger.info("LAN pcap saved: %s", pcap_path)
            self.parse_pcap_summary(pcap_path)
            self._abrir_networkminer(pcap_path)
        except Exception as e:
            logger.exception("tcpdump capture error: %s", e)
            self.log_event(f"Error de captura LAN: {e}", color="red")

    def capture_wifi_pcap(self):
        if platform.system().lower() != "linux":
            self.log_event("Captura WiFi .pcap sólo soportada en Linux en esta versión.", color="orange")
            return
        if not self.carpeta_evidencia:
            self.crear_carpeta_evidencia()
        iface = self.iface_wifi.get()
        canales = []
        if self.multicanal_var.get():
            if self.band_24_var.get(): canales += CANALES_24GHZ
            if self.band_5_var.get(): canales += CANALES_5GHZ
        else:
            canales = [1]
        canal = canales[0] if canales else 1
        pcap_base = os.path.join(self.carpeta_evidencia, "captura_wifi")
        duracion = simpledialog.askinteger("Duración", "Duración de la captura (segundos):", initialvalue=30, parent=self)
        if not duracion:
            return
        self.log_event(f"Capturando .pcap WiFi en {iface} (canal {canal}) durante {duracion}s...")
        logger.info("Starting airodump-ng capture on %s channel %s for %s s", iface, canal, duracion)
        try:
            proc = subprocess.Popen([
                "airodump-ng", "-w", pcap_base, "--output-format", "pcap", "-c", str(canal), iface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(duracion):
                if proc.poll() is not None:
                    break
                time.sleep(1)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            gener_file = pcap_base + "-01.pcap"
            if os.path.exists(gener_file):
                pcap_path = os.path.join(self.carpeta_evidencia, "captura_wifi.pcap")
                os.rename(gener_file, pcap_path)
                self.log_event(f"Archivo .pcap WiFi guardado: {pcap_path}", color="#ffe940")
                logger.info("WiFi pcap saved: %s", pcap_path)
                self.parse_pcap_summary(pcap_path)
                self._abrir_networkminer(pcap_path)
            else:
                self.log_event("No se encontró el .pcap resultante.", color="red")
                logger.warning("airodump-ng did not produce expected file: %s", gener_file)
        except Exception as e:
            logger.exception("airodump-ng error: %s", e)
            self.log_event(f"Error de captura WiFi: {e}", color="red")

    def parse_pcap_summary(self, pcap_path):
        """Basic parser using scapy to produce a human-readable summary file."""
        if scapy is None:
            self.log_event("scapy no está disponible para parseo de pcap.", color="red")
            return
        try:
            pkts = scapy.rdpcap(pcap_path)
            total = len(pkts)
            unique_macs = set()
            bssids = set()
            ips = set()
            for p in pkts:
                try:
                    if hasattr(p, "src"): unique_macs.add(p.src)
                    if p.haslayer(scapy.Dot11):
                        if getattr(p[scapy.Dot11], "addr2", None):
                            bssids.add(p[scapy.Dot11].addr2)
                    if p.haslayer(scapy.IP):
                        ips.add(p[scapy.IP].src)
                except Exception:
                    continue
            summary_path = pcap_path + ".summary.txt"
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(f"PCAP Summary: {pcap_path}\n")
                f.write(f"Total packets: {total}\n")
                f.write(f"Unique MACs seen: {len(unique_macs)}\n")
                f.write(f"Unique IPs seen: {len(ips)}\n")
                f.write(f"Unique BSSIDs (Dot11.addr2): {len(bssids)}\n")
                f.write("\nSample MACs:\n")
                for m in list(unique_macs)[:20]:
                    f.write(f"{m}\n")
            self.log_event(f"Resumen pcap guardado: {summary_path}", color="#00ffc0")
            logger.info("PCAP parsed, summary saved: %s", summary_path)
        except Exception as e:
            logger.exception("parse_pcap_summary error: %s", e)
            self.log_event(f"Error parseando pcap: {e}", color="red")

    def _abrir_networkminer(self, pcap_path):
        rutas = [
            "C:\\Program Files\\NetworkMiner\\NetworkMiner.exe",
            "C:\\NetworkMiner\\NetworkMiner.exe",
            "/opt/NetworkMiner/NetworkMiner"
        ]
        nm = next((ruta for ruta in rutas if os.path.exists(ruta)), None)
        if nm:
            try:
                subprocess.Popen([nm, pcap_path])
                self.log_event(f"Se abrió NetworkMiner con:\n{pcap_path}", color="#00FFC0")
                logger.info("Opened NetworkMiner for %s", pcap_path)
            except Exception:
                logger.exception("Failed to open NetworkMiner")
                self.log_event("NetworkMiner no pudo abrir el archivo.", color="orange")
        else:
            self.log_event("NetworkMiner no encontrado en rutas usuales.", color="orange")
            logger.info("NetworkMiner not found in standard paths")

    # ---------- PDF report ----------
    def generar_informe_pdf(self):
        if not self.carpeta_evidencia:
            self.crear_carpeta_evidencia()
        pdf_path = os.path.join(self.carpeta_evidencia, "reporte.pdf")
        resumen_lan = [{"iface": self.iface_lan.get(), "network": "-", "dispositivos": self.lan_historial}]
        try:
            generar_pdf_integrado(
                resumen_lan,
                self.wifi_historial,
                {k: list(v) for k, v in self.wifi_clientes.items()},
                pdf_path, carpeta_evidencia=self.carpeta_evidencia,
                pcap_lan=os.path.join(self.carpeta_evidencia, "captura_lan.pcap"),
                pcap_wifi=os.path.join(self.carpeta_evidencia, "captura_wifi.pcap")
            )
            messagebox.showinfo("Informe PDF", f"Informe generado:\n{pdf_path}")
            self.log_event(f"Informe PDF generado en: {pdf_path}", color="#ffe940")
            logger.info("PDF generated: %s", pdf_path)
        except Exception as e:
            logger.exception("PDF generation error: %s", e)
            self.log_event(f"Error al generar el PDF: {e}", color="red")

    # ---------- Log export ----------
    def export_log_menu(self):
        choice = messagebox.askquestion("Exportar bitácora", "Exportar bitácora como .txt (Sí) o .csv (No)?")
        if choice == "yes":
            self.export_log_txt()
        else:
            self.export_log_csv()

    def export_log_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if not path:
            return
        content = self.logarea.get("1.0", "end").strip()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.log_event(f"Bitácora exportada a: {path}", color="#00ffc0")
        logger.info("Log exported txt: %s", path)

    def export_log_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        # simple CSV: timestamp, message (no parsing of colors)
        lines = self.logarea.get("1.0", "end").strip().splitlines()
        with open(path, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(f"\"{datetime.utcnow().isoformat()}\",\"{ln.replace('\"','\\\"')}\"\n")
        self.log_event(f"Bitácora exportada a: {path}", color="#00ffc0")
        logger.info("Log exported csv: %s", path)

    # ---------- GUI logging ----------
    def log_event(self, txt, color="#ffffff"):
        try:
            self.logarea.insert("end", "\n")
            self.logarea.insert("end", txt)
            self.logarea.tag_add(color, "end-1l", "end-1c linestart")
            self.logarea.tag_config(color, foreground=color)
            self.logarea.see("end")
            if self.db:
                try:
                    self.db.insert_log("INFO", txt)
                except Exception:
                    logger.exception("Failed to insert log to DB")
            # write to main logger as well
            if "error" in str(txt).lower() or color == "red":
                logger.error(txt)
            else:
                logger.info(txt)
        except Exception:
            logger.exception("Failed to log_event to GUI")

    def on_close(self):
        try:
            if self.db:
                self.db.close()
        except Exception:
            pass
        self.destroy()

# ---------- main ----------
if __name__ == "__main__":
    app = SnifferDGC_GUI()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()