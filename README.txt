SNNIFER-DGC v10 - README
========================

Resumen
-------
SNNIFER-DGC v10 es una interfaz gráfica en Tkinter para auditoría forense de red con mejoras:
- Persistencia de historial en SQLite (evidence.db dentro de carpeta evidencia)
- Exportar bitácora GUI a .txt y .csv
- Visualizador interactivo (doble-clic) para ver detalles de APs, clientes y dispositivos LAN
- Parser básico de archivos .pcap (resumen generado con scapy)
- Integración con NetworkMiner si está instalado
- Compatibilidad multi-plataforma a nivel de avisos (captura directa soportada en Linux)
- Ajustes de rendimiento (Listbox + límites) y logging rotativo

Archivos principales
-------------------
- snifferdgc_integrado_pro_Version10.py  -> Aplicación principal (GUI & mejoras)
- report_integrado_Version2.py          -> Generador de PDF (debe estar presente)
- snifferdgc.log                       -> Archivo de log rotativo en el directorio de trabajo
- <evidence_folder>/evidence.db        -> SQLite DB con tablas lan_devices, wifi_aps, wifi_clients, logs
- <evidence_folder>/evidence_log.txt   -> Copia de logs dentro de la carpeta de evidencia (al crearla)
- <evidence_folder>/captura_lan.pcap
- <evidence_folder>/captura_wifi.pcap
- <evidence_folder>/captura_*.pcap.summary.txt -> resumen generado del pcap
- <evidence_folder>/reporte.pdf

Requisitos del sistema
----------------------
- OS recomendado: Linux (Kali/Ubuntu). Windows/macOS funcionalidad limitada para captura.
- Python 3.8+
- Paquetes Python:
    pip3 install scapy fpdf2
    (tkinter suele venir con Python; si falta: apt install python3-tk)
- Herramientas en sistema (Linux):
    tcpdump
    airodump-ng (aircrack-ng)
    iwconfig (wireless-tools)
- Hardware: tarjeta WiFi compatible con modo monitor para la funcionalidad WiFi (preferible adaptadores USB que soporten monitor).

Instalación (ejemplo Debian/Ubuntu/Kali)
---------------------------------------
sudo apt update
sudo apt install -y python3 python3-pip python3-tk tcpdump aircrack-ng wireless-tools
pip3 install scapy fpdf2

Ejecución
---------
1. (Recomendado) Poner interfaz WiFi en modo monitor:
   sudo ip link set wlan0 down
   sudo iwconfig wlan0 mode monitor
   sudo ip link set wlan0 up
   o:
   sudo airmon-ng start wlan0

2. Ejecutar la app:
   sudo python3 snifferdgc_integrado_pro_Version10.py

3. Flujo típico:
   - Crear carpeta evidencia (se crea evidence.db y evidence_log.txt)
   - Configurar interfaces (LAN y WiFi)
   - Iniciar escucha LAN o WiFi (multicanal)
   - Ver detecciones en tiempo real en las pestañas y en la bitácora
   - Doble-clic en una fila para ver detalles (AP, clientes, dispositivo)
   - Capturar .pcap (LAN o WiFi). Se genera resumen .summary.txt y se intenta abrir en NetworkMiner si disponible
   - Exportar bitácora a .txt o .csv
   - Generar informe PDF

Notas sobre plataformas (Windows/macOS)
--------------------------------------
- Capturas y cambio de canal requieren herramientas de bajo nivel (tcpdump/airodump-ng/iwconfig) disponibles en Linux.
- En Windows/macOS la app seguirá mostrando y permitiendo visualización y export, pero las opciones de captura y cambio de canal pueden notificar que no están soportadas. El programa avisa al usuario si la función no está soportada.

Persistencia SQLite
-------------------
- Al crear carpeta de evidencia se crea evidence.db con tablas:
  lan_devices(id,ip,mac,ts)
  wifi_aps(id,bssid,essid,channel,ts)
  wifi_clients(id,bssid,client_mac,ts)
  logs(id,level,msg,ts)
- Inserción automática de detecciones y logs en la DB para búsquedas posteriores.

Exportar bitácora
-----------------
- Botón "Exportar bitácora" -> pregunta TXT o CSV -> guarda archivo con el contenido actual del panel de logs.

Visualizador interactivo
------------------------
- Doble-clic en:
  - Resultados LAN -> muestra ventana con detalle del dispositivo
  - Resultados Aire -> muestra AP y lista de clientes asociados (si los hay)
  - Clientes -> muestra detalle cliente

Análisis de PCAP
----------------
- Después de crear/capturar un pcap, la app ejecuta parse_pcap_summary que genera un archivo pcap.summary.txt con conteo básico:
  total packets, unique MACs, unique IPs, unique BSSIDs y muestra sample MACs.
- Útil como primer paso antes de abrir en NetworkMiner o Wireshark.

Recomendaciones de uso y troubleshooting
---------------------------------------
- Si no ves detecciones WiFi: comprueba modo monitor y la interfaz (wlan0mon vs wlan0).
- Aumenta "Dur. Canal WiFi (s)" si los APs no se detectan (beacons pueden ser escasos).
- Revisa snifferdgc.log y <evidence_folder>/evidence_log.txt para trazas detalladas.
- Si scapy no está instalado, varias funciones (sniff y parse pcap) no funcionarán.

Extensiones posibles (futuro)
----------------------------
- Interfaz para consultar DB (historial) con filtros (fecha, bssid, ip).
- Exportar DB a CSV/JSON.
- Enriquecimiento OUI para fabricantes (lookup OUI).
- Integración con parsers forenses más avanzados y automatización de análisis.

Contacto
--------
Si quieres que implemente la interfaz de consulta de la DB o la exportación masiva, dime
prioridad y lo preparo con ejemplo de uso y tests.