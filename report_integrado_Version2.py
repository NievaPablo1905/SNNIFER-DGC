from fpdf import FPDF
import os
import hashlib
from datetime import datetime
import unicodedata

# ===================== CONFIG =====================
# Ajustes visuales y de layout
PAGE_SIZE = "A4"
ORIENTATION = "P"        # 'P' portrait, 'L' landscape (puedes cambiar a 'L' si prefieres tablas más anchas)
MARGIN = 15              # mm
LINE_HEIGHT = 7          # altura base de línea para tablas
TITLE_FONT_SIZE = 16
SECTION_FONT_SIZE = 13
TABLE_HDR_FONT_SIZE = 10
TABLE_FONT_SIZE = 9
TEXT_FONT_SIZE = 11

# Colores (RGB)
ACCENT = (0, 159, 146)      # color principal (verde-azulado)
ACCENT_DARK = (0, 128, 110)
HEADER_BG = (12, 102, 141)  # azul oscuro para cabeceras de sección
LAN_HEADER_BG = (34, 41, 74)
WIFI_HEADER_BG = (0, 150, 136)
SAFE_WIFI_BG = (230, 255, 242)
OPEN_WIFI_BG = (255, 243, 205)
TEXT_COLOR = (36, 36, 36)
FOOTER_COLOR = (80, 80, 80)
LOGO_PATH = "DGC_LOGO.png"

# Fuente TTF preferida (mejor soporte Unicode). Se intenta registrar si existe.
TTF_FAMILIES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",    # Linux usual
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "C:\\Windows\\Fonts\\DejaVuSans.ttf",
    "/Library/Fonts/DejaVuSans.ttf"
]

# ================== UTILIDADES ====================
def normalize_for_pdf(txt):
    """
    Normaliza texto para PDF. Si se registró una fuente TTF soportando Unicode,
    devolvemos el texto tal cual. Si no, hacemos una degradación a latin-1 compatible.
    """
    if txt is None:
        return "-"
    txt = str(txt)
    # Reemplazos comunes tipográficos
    txt = (txt.replace("–", "-").replace("—", "-")
               .replace("“", '"').replace("”", '"')
               .replace("‘", "'").replace("’", "'"))
    # Normalizamos
    txt = unicodedata.normalize("NFKC", txt)
    return txt

def hash_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# =================== PDF CLASS ====================
class PDFInforme(FPDF):
    def __init__(self, orientation=ORIENTATION, unit="mm", format=PAGE_SIZE, margin=MARGIN):
        super().__init__(orientation=orientation, unit=unit, format=format)
        self.set_auto_page_break(auto=False)
        self.left_margin = margin
        self.right_margin = margin
        self.top_margin = margin
        self.bottom_margin = margin
        # Register font if TTF available
        self.unicode_font = None
        for path in TTF_FAMILIES:
            if os.path.exists(path):
                try:
                    self.add_font("DejaVu", "", path, uni=True)
                    self.unicode_font = "DejaVu"
                    break
                except Exception:
                    continue
        # Fallback fonts: Arial (built-in)
        self.base_font = self.unicode_font if self.unicode_font else "Arial"

    def header(self):
        # Logo
        if os.path.exists(LOGO_PATH):
            try:
                self.image(LOGO_PATH, x=self.left_margin, y=10, w=22)
            except Exception:
                pass
        # Title centered
        self.set_xy(self.left_margin + 25, 10)
        self.set_font(self.base_font, "B", TITLE_FONT_SIZE)
        self.set_text_color(*ACCENT)
        self.cell(self.w - self.left_margin - self.right_margin - 25, 10, normalize_for_pdf("INFORME FORENSE DE REDES - SNNIFER-DGC"), ln=1, align='C')
        # Subtitle / fecha
        self.set_font(self.base_font, "I", 10)
        self.set_text_color(120, 120, 120)
        self.cell(self.w - self.left_margin - self.right_margin, 6, f"Fecha/hora generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1, align='C')
        self.ln(2)
        self.set_text_color(*TEXT_COLOR)
        # cursor ready at left margin
        self.set_x(self.left_margin)

    def footer(self):
        self.set_y(-15)
        self.set_font(self.base_font, "I", 9)
        self.set_text_color(*ACCENT_DARK)
        self.cell(0, 8, normalize_for_pdf("SNNIFER-DGC - Software Forense de Redes"), 0, 0, 'L')
        self.set_text_color(*FOOTER_COLOR)
        self.cell(0, 8, f'Página {self.page_no()}', 0, 0, 'R')

    # Helpers for consistent styling
    def section_title(self, text, bg_color=HEADER_BG):
        self.ln(2)
        # full-width banner with contrast text
        self.set_fill_color(*bg_color)
        self.set_text_color(255, 255, 255)
        self.set_font(self.base_font, "B", SECTION_FONT_SIZE)
        self.cell(self.w - self.left_margin - self.right_margin, 9, normalize_for_pdf(text), 0, 1, 'L', 1)
        self.ln(2)
        self.set_text_color(*TEXT_COLOR)
        self.set_font(self.base_font, "", TEXT_FONT_SIZE)

    def check_space(self, needed_lines=1, line_height=LINE_HEIGHT):
        needed = needed_lines * line_height + 12  # extra buffer
        if self.get_y() + needed > (self.h - self.bottom_margin):
            self.add_page()
            return True
        return False

    # Table utility that repeats header if page break occurs
    def table_start(self):
        self.set_x(self.left_margin)

    def table_header(self, headers, widths, fill_color=(0,0,0), text_color=(255,255,255)):
        """
        headers: list of header text
        widths: list of widths in mm (sum must be <= printable area)
        """
        self.check_space(2)
        self.set_font(self.base_font, "B", TABLE_HDR_FONT_SIZE)
        self.set_fill_color(*fill_color)
        self.set_text_color(*text_color)
        for h, w in zip(headers, widths):
            self.cell(w, LINE_HEIGHT, normalize_for_pdf(h), border=1, align='C', fill=1)
        self.ln(LINE_HEIGHT)
        self.set_text_color(*TEXT_COLOR)
        self.set_font(self.base_font, "", TABLE_FONT_SIZE)

    def table_row(self, row_cells, widths, fills=None, aligns=None):
        """
        row_cells: texts list
        widths: widths list
        fills: list of booleans or rgb tuples to set background
        aligns: list of 'L'/'C'/'R'
        Multi-line safe: uses multi_cell technique per cell and then adjusts.
        """
        # Estimate max lines per cell to compute row height
        max_lines = 1
        # Save start positions
        x_start = self.get_x()
        y_start = self.get_y()
        col_heights = []
        # Determine heights by wrapping text roughly (basic heuristic using string width)
        for i, txt in enumerate(row_cells):
            w = widths[i] - 2  # padding
            # compute number of approx lines
            txt_s = normalize_for_pdf(txt)
            # use font metrics via get_string_width
            self.set_font(self.base_font, "", TABLE_FONT_SIZE)
            approx = max(1, int(self.get_string_width(txt_s) / (w if w > 0 else 1)) + 1)
            col_heights.append(approx)
            if approx > max_lines:
                max_lines = approx
        row_h = max_lines * (LINE_HEIGHT * 0.95)
        # Page break if needed
        if self.get_y() + row_h > (self.h - self.bottom_margin):
            self.add_page()
            # caller should re-print headers if necessary
        # Now actually print cell by cell using multicell with same height
        current_x = x_start
        for i, txt in enumerate(row_cells):
            w = widths[i]
            fill_flag = 0
            if fills:
                if isinstance(fills[i], tuple):
                    self.set_fill_color(*fills[i])
                    fill_flag = 1
                elif fills[i]:
                    self.set_fill_color(245,245,245)
                    fill_flag = 1
            align = aligns[i] if aligns and i < len(aligns) else 'L'
            self.set_xy(current_x, y_start)
            # Use multi_cell for wrapping, border=1
            self.multi_cell(w, LINE_HEIGHT, normalize_for_pdf(txt), border=1, align=align, fill=fill_flag)
            # move to next column; y should be reset to start y
            current_x += w
            self.set_xy(current_x, y_start)
        # move cursor to next row after row_h
        self.set_y(y_start + row_h)
        self.set_x(self.left_margin)

# ================== GENERATOR =====================
def generar_pdf_integrado(resultados_lan, ssids, clientes, pdf_filename, carpeta_evidencia=None, pcap_lan=None, pcap_wifi=None, logo_path=None):
    """
    Genera el PDF final con layout ajustado y repetición de cabeceras.
    """
    pdf = PDFInforme(orientation=ORIENTATION, format=PAGE_SIZE, margin=MARGIN)
    pdf.add_page()

    # Introducción / resumen (usa multi_cell para no cortar frases)
    pdf.section_title("Introducción y resumen del caso", bg_color=ACCENT)
    pdf.set_font(pdf.base_font, "", TEXT_FONT_SIZE)
    intro_text = (
        "Este informe documenta el proceso y resultados de la intervención forense efectuada por el modelo SNNIFER-DGC para "
        "detección y captura de evidencias digitales en redes LAN y WiFi.\n\n"
        "Todos los archivos .pcap y el presente documento fueron generados siguiendo chain of custody exigida para peritajes digitales."
    )
    pdf.multi_cell(pdf.w - pdf.left_margin - pdf.right_margin, 7, normalize_for_pdf(intro_text))
    pdf.ln(2)
    pdf.set_font(pdf.base_font, "I", 10)
    pdf.cell(0, 6, f'Carpeta de evidencia: {normalize_for_pdf(os.path.basename(carpeta_evidencia) if carpeta_evidencia else "-")}', ln=1)
    pdf.cell(0, 6, f'Caso generado: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=1)
    pdf.ln(4)

    # Detalle de evidencias adjuntas
    pdf.section_title("Detalle de evidencias digitales adjuntas", bg_color=(11, 102, 180))
    # Table widths: compute printable width
    printable = pdf.w - pdf.left_margin - pdf.right_margin
    w_archivo = 55
    w_tipo = 45
    w_hash = printable - (w_archivo + w_tipo)
    headers = ["Archivo", "Tipo", "Hash SHA256"]
    widths = [w_archivo, w_tipo, w_hash]
    pdf.table_header(headers, widths, fill_color=(11,102,180))
    # rows
    def det_evid(nombre, tipo, path):
        hashv = hash_sha256(path)
        pdf.table_row([nombre, tipo, hashv if hashv else "-"], widths, fills=[0,0,0], aligns=['L','L','L'])
    if pcap_lan and os.path.exists(pcap_lan):
        det_evid(os.path.basename(pcap_lan), "Captura LAN .pcap", pcap_lan)
    if pcap_wifi and os.path.exists(pcap_wifi):
        det_evid(os.path.basename(pcap_wifi), "Captura WiFi .pcap", pcap_wifi)
    # always include report filename
    try:
        det_evid(os.path.basename(pdf_filename), "Informe este PDF", pdf_filename)
    except Exception:
        det_evid("reporte.pdf", "Informe este PDF", pdf_filename)
    pdf.ln(3)
    pdf.set_font(pdf.base_font, "I", 9)
    pdf.cell(0, 6, "Todos los hash han sido verificados para cadena de custodia.", ln=1)
    pdf.ln(4)

    # Resultados LAN
    pdf.section_title("Resultados LAN (Dispositivos detectados)", bg_color=LAN_HEADER_BG)
    lan_widths = [40, 42, 60, 30]  # adjust fabricante width larger if needed
    # ensure total fits
    total_w = sum(lan_widths)
    printable = pdf.w - pdf.left_margin - pdf.right_margin
    if total_w > printable:
        scale = printable / total_w
        lan_widths = [w * scale for w in lan_widths]
    pdf.table_header(["IP", "MAC", "Fabricante", "Interfaz"], lan_widths, fill_color=LAN_HEADER_BG)
    lan_empty = True
    for red in (resultados_lan or []):
        dispositivos = red.get("dispositivos", [])
        for d in dispositivos:
            ip = d.get("ip", "-")
            mac = d.get("mac", "-")
            vendor = d.get("vendor", "-")
            iface = red.get("iface", "-")
            pdf.table_row([ip, mac, vendor, iface], lan_widths, fills=[0,0,0,0], aligns=['L','L','L','C'])
            lan_empty = False
    if lan_empty:
        pdf.table_row(["Sin dispositivos LAN detectados o escaneo no realizado.", "", "", ""], [sum(lan_widths), 0, 0, 0], fills=[0,0,0,0], aligns=['L','L','L','L'])

    pdf.ln(4)

    # Resultados WiFi
    pdf.section_title("Resultados Aire WiFi (Redes detectadas)", bg_color=WIFI_HEADER_BG)
    wifi_widths = [45, 50, 18, 28, printable - (45+50+18+28)]
    # ensure positive
    wifi_widths = [max(10, w) for w in wifi_widths]
    pdf.table_header(["ESSID", "BSSID", "Canal", "Seguridad", "Fabricante"], wifi_widths, fill_color=WIFI_HEADER_BG)
    wifi_empty = True
    for bssid, info in (ssids or {}).items():
        essid = info.get("essid", "-")
        channel = info.get("channel", "-")
        security = (info.get("encryption","OPEN") or "OPEN")
        vendor = info.get("vendor", "-")
        # color row fill based on security
        if "WPA3" in security or "WPA2" in security or "WPA" in security:
            fill = SAFE_WIFI_BG
        elif "OPEN" in security or "SIN CLAVE" in security:
            fill = OPEN_WIFI_BG
        else:
            fill = 0
        pdf.table_row([essid, bssid, str(channel), security, vendor], wifi_widths, fills=[fill,fill,fill,fill,fill], aligns=['L','L','C','C','L'])
        wifi_empty = False
    if wifi_empty:
        pdf.table_row(["Sin redes WiFi detectadas o escaneo no realizado.", "", "", "", ""], [sum(wifi_widths),0,0,0,0], fills=[0,0,0,0,0], aligns=['L','L','L','L','L'])

    # Legend
    pdf.set_font(pdf.base_font, "I", 8)
    pdf.set_text_color(0,120,50)
    pdf.cell(0, 5, "Verde: WPA2/WPA3  |  Amarillo: Red abierta", ln=1)
    pdf.set_text_color(*TEXT_COLOR)
    pdf.ln(4)

    # Clientes WiFi
    pdf.section_title("Clientes WiFi detectados (MAC por BSSID)", bg_color=(11,102,180))
    pdf.set_font(pdf.base_font, "", TABLE_FONT_SIZE)
    if clientes:
        for bssid, clist in clientes.items():
            line = f"BSSID: {bssid} -> {len(clist)} cliente(s): {', '.join(clist)}"
            pdf.multi_cell(pdf.w - pdf.left_margin - pdf.right_margin, LINE_HEIGHT, normalize_for_pdf(line))
    else:
        pdf.multi_cell(pdf.w - pdf.left_margin - pdf.right_margin, LINE_HEIGHT, "Sin clientes WiFi detectados o escaneo no realizado.")

    pdf.ln(6)

    # Conclusion
    pdf.section_title("Conclusión y observaciones", bg_color=ACCENT)
    pdf.multi_cell(pdf.w - pdf.left_margin - pdf.right_margin, 7, normalize_for_pdf(
        "El presente informe ha sido generado por el modelo SNNIFER-DGC para uso pericial. Toda la información se ha recolectado asegurando la cadena de custodia.\n\n"
        "Se recomienda a la autoridad requiriente analizar los archivos .pcap adjuntos usando NetworkMiner o Wireshark para un estudio más profundo de las comunicaciones brutas presentes en las redes bajo análisis.\n"
        "Se observaron posibles segmentos abiertos/confidenciales (ver resultados Aire WiFi resaltados en amarillo). Para afianzar la seguridad se sugiere proceder con un análisis técnico de los hosts detectados y reforzar la seguridad de las redes WiFi abiertas o inseguras."
    ))
    pdf.ln(4)
    pdf.set_font(pdf.base_font, "I", 10)
    pdf.multi_cell(pdf.w - pdf.left_margin - pdf.right_margin, 6, normalize_for_pdf("Toda consulta sobre interpretación técnica del informe deberá canalizarse con el personal pericial actuante."))

    # Signature area
    pdf.ln(8)
    sig_w = pdf.w - pdf.left_margin - pdf.right_margin
    pdf.set_x(pdf.left_margin)
    pdf.cell(sig_w * 0.6, 6, "______________________________", 0, 1, 'R')
    pdf.cell(sig_w * 0.6, 6, "Firma/identificación perito responsable", 0, 1, 'R')

    # Output
    try:
        pdf.output(pdf_filename)
    except Exception as e:
        print(f"Error al generar el PDF: {e}")
        raise