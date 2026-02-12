"""
# HOME_SNIFFER v2.0 - Network Protocol Analyzer
# ---------------------------------------------------------
# ARQUITECTURA: Modular (MVC - Model View Controller simplified)
#   - core_sniffer.py: Motor de red asíncrono basado en Scapy.
#   - ui_app.py: Interfaz de usuario TUI construida con Textual.
#   - styles.css: Definición estética externa.
#
# FLUJO DE DATOS:
#   1. El motor captura paquetes en hilos independientes (lo, eth0).
#   2. Se procesan alertas (HTTP inseguro, puertos críticos) en tiempo real.
#   3. El motor notifica a la UI mediante un callback reactivo.
#   4. La UI renderiza los datos usando Markdown y Rich para máxima legibilidad.
#
# REQUISITOS: Ejecutar con privilegios de superusuario (root) para acceso a sockets.
# ---------------------------------------------------------
"""

from core_sniffer import SnifferEngine
from ui_app import HomeSnifferApp

if __name__ == "__main__":
    def on_packet(pkt, info, payload):
        app.handle_new_packet(pkt, info, payload)

    engine = SnifferEngine(packet_callback=on_packet, log_callback=None)
    app = HomeSnifferApp(engine)
    app.run()