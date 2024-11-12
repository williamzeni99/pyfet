import os
import subprocess
import sys
import time
import scapy.all as scapy
import requests


def get_mitmdump_path():
    """
    Returns the path to mitmdump in the virtual environment.
    """
    if sys.prefix != sys.base_prefix:
        # We are in a virtual environment
        return os.path.join(sys.prefix, 'bin', 'mitmdump')
    else:
        # If not in a virtual environment, use the system path for mitmdump
        return "mitmdump"

def start_mitmproxy():
    """
    Starts mitmproxy in transparent mode on the specified port, with SSL key logging enabled.
    """
    mitm_cmd = [
        get_mitmdump_path()
    ]
    
    # Set up the environment with SSLKEYLOGFILE
    env={
        'SSLKEYLOGFILE': "./keys.txt",
        **os.environ
    }
    
    proxy_process = subprocess.Popen(mitm_cmd, env=env, stdout=subprocess.PIPE)
    time.sleep(5)
    print("mitmproxy started with SSL key logging enabled.")
    return proxy_process


packets =[]
# Callback per gestire i pacchetti catturati
def packet_callback(packet):
    global packets
    packets.append(packet)

# Se il programma non è in esecuzione con sudo, rilanciarlo con sudo
if os.geteuid() != 0:
    python_path = sys.executable
    print("Questo programma richiede i permessi di amministratore (sudo). Rilancio con sudo...")
    
    # Rilancia il programma mantenendo l'ambiente con sudo -E
    subprocess.run(["sudo", "-E", python_path] + sys.argv)
    sys.exit()  # Esci dal programma attuale



proxy_process = start_mitmproxy()

t1=scapy.AsyncSniffer(prn=packet_callback, store=False)
t1.start()

cert_path = '/home/williamzeni/Documents/pyfet/mitmproxy-ca-cert.pem'

os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8080'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8080'
os.environ["REQUESTS_CA_BUNDLE"] = cert_path
# Define the proxy
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080',
}

for i in range(3):
    print(f"REQUEST {i}")
    requests.get(url="https://it.wikipedia.org/wiki/Wikipedia")
    time.sleep(4)

t1.stop()

proxy_process.kill()

output_file="captured_packets.pcap"
print("saving..")
scapy.wrpcap(output_file, packets)
print(f"Captured packets saved to {output_file}")
