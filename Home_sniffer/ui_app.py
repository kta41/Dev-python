from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Input
from textual.containers import Horizontal
from rich.text import Text
from scapy.all import wrpcap, Raw, IP, TCP, UDP
from datetime import datetime
from rich.markdown import Markdown
import re

class HomeSnifferApp(App):
    CSS_PATH = "styles.css"
    BINDINGS = [("s", "save_pcap", "Guardar"), ("x", "clear", "Limpiar")]

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.all_data = []
        self.packet_history = {}
        self.search_filter = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="[ BUSCAR... ]", id="search-bar")
        with Horizontal():
            yield Static("SISTEMA DE ANÁLISIS\nESPERANDO TRÁFICO...", id="details")
            yield DataTable()
        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("PROTO", "ORIGEN", "DESTINO", "PUERTO", "INFO")
        self.engine.start()

    def handle_new_packet(self, pkt, info, payload):
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
        src, dst = pkt[IP].src, pkt[IP].dst
        port = str(pkt.sport) if (TCP in pkt or UDP in pkt) else "-"
        
        entry = (pkt, proto, src, dst, port, info, payload)
        self.all_data.append(entry)
        
        search_str = f"{proto} {src} {dst} {port} {info} {payload}".lower()
        if self.search_filter.lower() in search_str:
            self.call_from_thread(self.add_row_to_table, pkt, proto, src, dst, port, info)

    def add_row_to_table(self, pkt, proto, src, dst, port, info):
        table = self.query_one(DataTable)
        row_key = table.add_row(proto, src, dst, port, Text.from_markup(info) if info else "")
        self.packet_history[row_key] = pkt
        if len(table.rows) > 50:
            table.remove_row(list(table.rows.keys())[0])

    def on_input_changed(self, event: Input.Changed) -> None:
        self.search_filter = event.value
        table = self.query_one(DataTable)
        table.clear()
        self.packet_history.clear()
        
        for pkt, proto, src, dst, port, info, payload in reversed(self.all_data[-200:]):
            search_str = f"{proto} {src} {dst} {port} {info} {payload}".lower()
            if self.search_filter.lower() in search_str:
                rk = table.add_row(proto, src, dst, port, Text.from_markup(info))
                self.packet_history[rk] = pkt

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        pkt = self.packet_history.get(event.row_key)
        if pkt:
            detail_view = self.query_one("#details", Static)
            
            raw_struct = pkt.show(dump=True)
            pretty_struct = re.sub(r"###\[ (\w+) \]###", r"\n\n### \1\n---", raw_struct)

            payload_section = ""
            if pkt.haslayer(Raw):
                try:
                    raw_bytes = pkt[Raw].load
                    try:
                        decoded = raw_bytes.decode('utf-8', errors='ignore')
                        payload_section = f"### CONTENIDO DATA\n```text\n{decoded[:500]}\n```"
                    except:
                        payload_section = f"### CONTENIDO BINARIO (HEX)\n```\n{raw_bytes.hex()[:400]}\n```"
                except: pass

            md_text = f"""
# ANÁLISIS DE PAQUETE
**Resumen:** `{pkt.summary()}`

{payload_section}

{pretty_struct}
"""
            detail_view.update(Markdown(md_text))

    def action_save_pcap(self):
        if self.engine.captured_raw:
            filename = f"cap_{datetime.now().strftime('%H%M%S')}.pcap"
            detail_view = self.query_one("#details", Static)
            try:
                wrpcap(filename, self.engine.captured_raw)
                aviso_md = f"""
# ✅ SISTEMA DE ALMACENAMIENTO
---
**ESTADO:** Archivo guardado correctamente.
**NOMBRE:** `{filename}`
**UBICACIÓN:** Directorio del proyecto.
---
*Selecciona un paquete en la tabla para volver al análisis.*
"""
                detail_view.update(Markdown(aviso_md))
            except Exception as e:
                detail_view.update(Markdown(f"# ❌ ERROR AL GUARDAR\n---\n{str(e)}"))

    def action_clear(self):
        self.all_data.clear()
        self.packet_history.clear()
        self.engine.captured_raw.clear()
        self.query_one(DataTable).clear()
        self.query_one("#details", Static).update("DATOS LIMPIADOS - ESPERANDO TRÁFICO...")