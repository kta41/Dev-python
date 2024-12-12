import socket
import struct
import sys
import time
import signal
import textwrap
from colorama import Fore, Style, init

# Inicializar colorama
init()

# Clase para duplicar la salida a consola y archivo
class Logger:
    def __init__(self, file_name):
        self.terminal = sys.stdout
        self.log = open(file_name, "a")
    
    def write(self, message):
        self.terminal.write(message)  # Mostrar en consola
        self.log.write(message)       # Escribir en archivo
    
    def flush(self):
        self.terminal.flush()  # Asegurarse de que la consola se actualice
        self.log.flush()       # Asegurarse de que el archivo se actualice

# Manejador de la señal de interrupción
def signal_handler(sig, frame):
    print(F"\n{Fore.RED}{Style.BRIGHT}Captura detenida por el usuario.{Style.RESET_ALL}")
    sys.exit(0)

def main():
    if not hasattr(socket, 'AF_PACKET'):
        print(f"{Fore.RED}Este script solo funciona en sistemas Linux.{Style.RESET_ALL}")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)

    capture_traffic()

# Desempaquetar frame Ethernet
def ethernet_frame(data):
    if len(data) < 14:
        raise ValueError("Paquete malformado.")
    dest_mac, origen_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(origen_mac), socket.htons(proto), data[14:]

# Formatear direcciones MAC (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Desempaquetar cabecera IPv4
def ipv4_packet(data):
    if len(data) < 20:
        raise ValueError("Paquete IPv4 malformado.")
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Convertir direcciones IPv4
def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    if len(data) < 20:
        raise ValueError("Segmento TCP malformado.")
    # Desempaquetar los campos principales de la cabecera TCP (mínimo 20 bytes)
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    
    offset = (offset_reserved_flags >> 12) * 4  # Tamaño de la cabecera TCP en bytes
    if len(data) < offset:
        raise ValueError("Datos insuficientes para el segmento TCP completo.")
    
    # Extraer las banderas TCP
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Desempaquetar cabecera UDP
def udp_segment(data):
    if len(data) < 8:
        raise ValueError("Segmento UDP malformado.")
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Desempaquetar ICMP 
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def format_multi_line(string, size=80):
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    # Convertir el string de hex a texto legible (ASCII)
    string = bytes.fromhex(string.replace(r'\x', '')).decode('ascii', errors='ignore')
    
    # Dividir el string en líneas según el tamaño especificado
    return '\n'.join(['\t\t\t' + line for line in textwrap.wrap(string, size)])

# Capturar tráfico
def capture_traffic():

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print(f"{Fore.RED}Necesitas ejecutar este script como superusuario.{Style.RESET_ALL}")
        sys.exit(1)

    # Usar el Logger para redirigir la salida tanto a consola como a archivo
    sys.stdout = Logger("output.txt")

    print(f"{Fore.RED}{Style.BRIGHT}\nCapturando tráfico... Presiona Ctrl+C para detener.{Style.RESET_ALL}")

    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        len_data = len(raw_data)
        try:
            dest_mac, origen_mac, eth_proto, data = ethernet_frame(raw_data)

            timestamp = time.strftime('%H:%M:%S', time.localtime())
            
            print(f'\n{Fore.BLUE}[{timestamp}] - Ethernet Frame:')
            print(f'{Fore.BLUE}Destino: {Style.BRIGHT}{dest_mac}{Style.RESET_ALL}, {Fore.BLUE}Origen: {Style.BRIGHT}{origen_mac}{Style.RESET_ALL}, {Fore.BLUE}Protocolo: {Style.BRIGHT}{eth_proto}{Style.RESET_ALL}{Style.RESET_ALL}')

            # Procesar paquetes IPv4
            if eth_proto == 8:  # IPv4
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print(f'\t{Fore.BLUE}IPv4 Packet:{Style.RESET_ALL}')
                print(f'\t{Fore.BLUE}Origen: {Style.BRIGHT}{src}{Style.RESET_ALL}, {Fore.BLUE}Destino: {Style.BRIGHT}{target}{Style.RESET_ALL}, {Fore.BLUE}TTL: {ttl}, {Fore.BLUE}Protocolo: {proto}{Style.RESET_ALL}')
                print(f'{Fore.GREEN}{format_multi_line(data)}{Style.RESET_ALL}')

                # Procesar segmentos TCP o UDP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(f'\t\t{Fore.BLUE}ICMP Packet{Style.RESET_ALL}')
                    print(f'\t\t{Fore.BLUE}Type: {Style.BRIGHT}{icmp_type}{Style.RESET_ALL}, {Fore.BLUE}Code:{Style.BRIGHT}{code}{Style.RESET_ALL}, {Fore.BLUE}Checksum:{Style.BRIGHT}{checksum}{Style.RESET_ALL}')
                    print(f'{Fore.GREEN}{format_multi_line(data)}{Style.RESET_ALL}')

                if proto == 6:  # TCP
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    print(f'\t\t{Fore.BLUE}TCP Segment:{Style.RESET_ALL}')
                    print(f'\t\t{Fore.BLUE}Origen: {Style.BRIGHT}{src_port}{Style.RESET_ALL}, {Fore.BLUE}Destino: {Style.BRIGHT}{dest_port}{Style.RESET_ALL}, {Fore.BLUE}Secuencia: {Style.BRIGHT}{sequence}{Style.RESET_ALL}, {Fore.BLUE}ACK: {Style.BRIGHT}{acknowledgment}{Style.RESET_ALL}')
                    print(f'\t\t{Fore.BLUE}Flags: {Fore.BLUE}URG={Style.BRIGHT}{flag_urg}{Style.RESET_ALL}, {Fore.BLUE}ACK={Style.BRIGHT}{flag_ack}{Style.RESET_ALL}, {Fore.BLUE}PSH={Style.BRIGHT}{flag_psh}{Style.RESET_ALL}, {Fore.BLUE}RST={Style.BRIGHT}{flag_rst}{Style.RESET_ALL}, {Fore.BLUE}SYN={Style.BRIGHT}{flag_syn}{Style.RESET_ALL}, {Fore.BLUE}FIN={Style.BRIGHT}{flag_fin}{Style.RESET_ALL}')
                    print(f'{Fore.GREEN}{format_multi_line(data)}{Style.RESET_ALL}')

        except ValueError as e:
            print(f"Error procesando paquete: {e}")

    
        

if __name__ == "__main__":
    main()
