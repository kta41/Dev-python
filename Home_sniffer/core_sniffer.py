from scapy.all import sniff, IP, TCP, Raw
import threading

class SnifferEngine:
    def __init__(self, packet_callback, log_callback):
        self.packet_callback = packet_callback
        self.log_callback = log_callback
        self.captured_raw = []

    def start(self):
        interfaces = ["lo", "eth0"]
        for iface in interfaces:
            thread = threading.Thread(target=self._run_sniff, args=(iface,), daemon=True)
            thread.start()

    def _run_sniff(self, iface):
        try:
            sniff(iface=iface, prn=self._process, store=False)
        except Exception:
            pass

    def _process(self, pkt):
        if IP in pkt:
            # Filtro Kubernetes
            if TCP in pkt and (pkt.dport in [6443, 6444] or pkt.sport in [6443, 6444]):
                return
            
            self.captured_raw.append(pkt)
            
            # Lógica de detección
            info = ""
            payload_str = ""
            if pkt.haslayer(Raw):
                try:
                    raw_data = pkt[Raw].load
                    payload_str = raw_data.decode(errors="replace")
                    verbos = [b"GET ", b"POST ", b"HTTP/1", b"PUT ", b"DELETE "]
                    if any(v in raw_data for v in verbos):
                        if TCP in pkt and pkt.dport != 443 and pkt.sport != 443:
                            info = "[bold red]! HTTP INSEGURO[/]"
                except: pass

            if not info and TCP in pkt and pkt.dport in [22, 23, 3389]:
                info = "[bold magenta]! PUERTO CRITICO[/]"

            # Enviamos los datos procesados de vuelta a la UI
            self.packet_callback(pkt, info, payload_str)