# capture_packets_with_stop.py
import sys
import time
from pathlib import Path
from scapy.all import AsyncSniffer, wrpcap

def capture_packets(output_path, stop_file_path):
    packets = []
    sniffer = AsyncSniffer(prn=lambda pkt: packets.append(pkt), store=False)
    sniffer.start()
    try:
        # Controllo periodico del file di interruzione
        while not stop_file_path.exists():
            time.sleep(1)
        sniffer.stop()
        wrpcap(output_path, packets)
    finally:
        sniffer.stop()


output_path = sys.argv[1]
stop_file_path = Path(sys.argv[2])
capture_packets(output_path, stop_file_path)
