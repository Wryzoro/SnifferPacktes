from scapy.all import sniff, IP, TCP, UDP
import datetime

def packet_callback(packet):
    # Verificar se o pacote possui camada IP
    if IP in packet:
        src_ip = packet[IP].src  # IP de origem
        dst_ip = packet[IP].dst  # IP de destino
        proto = packet[IP].proto  # Protocolo
        
        # Verificar protocolo e exibir portas se for TCP/UDP
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{datetime.datetime.now()}] TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{datetime.datetime.now()}] UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        else:
            print(f"[{datetime.datetime.now()}] IP | {src_ip} -> {dst_ip} | Protocolo: {proto}")
    else:
        print(f"[{datetime.datetime.now()}] Pacote não-IP capturado.")

# Capturar pacotes
if __name__ == "__main__":
    print("Iniciando captura de pacotes... Pressione Ctrl+C para interromper.")
    try:
        sniff(prn=packet_callback, store=False)  # Captura contínua de pacotes
    except KeyboardInterrupt:
        print("\nCaptura encerrada.")
