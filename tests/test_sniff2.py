import os
import subprocess
import time
from scapy.all import sniff, wrpcap
import atexit
import sys
import requests

MITMPROXY_PORT = 8080
PCAP_FILE = "traffic.pcap"
KEYLOG_FILE = "/home/williamzeni/Documents/pyfet/tests/sslkeys.log"
CAPTURE_DURATION = 10  # Capture duration in seconds

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
        "sudo", "-E", get_mitmdump_path(), "--mode", "transparent",
        "--listen-port", str(MITMPROXY_PORT),
        "--ssl-insecure"
    ]
    
    # Set up the environment with SSLKEYLOGFILE
    env = os.environ.copy()
    env["SSLKEYLOGFILE"] = os.path.abspath(KEYLOG_FILE)
    
    proxy_process = subprocess.Popen(mitm_cmd)
    print("mitmproxy started with SSL key logging enabled.")
    return proxy_process

def setup_iptables():
    """
    Sets up iptables to redirect all HTTP and HTTPS traffic to mitmproxy.
    Requires root privileges.
    """
    try:
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(MITMPROXY_PORT)],
            check=True
        )
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(MITMPROXY_PORT)],
            check=True
        )
        print("iptables rules set to redirect HTTP and HTTPS traffic to mitmproxy.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting up iptables: {e}")
        reset_iptables()
        raise

def reset_iptables():
    """
    Clears the iptables rules set by this script.
    """
    try:
        subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], check=True)
        print("iptables rules cleared.")
    except subprocess.CalledProcessError as e:
        print(f"Error resetting iptables: {e}")

def capture_traffic(output_pcap=PCAP_FILE, duration=CAPTURE_DURATION):
    """
    Capture packets and save them to a pcap file.
    """
    print(f"Starting packet capture for {duration} seconds...")
    packets = sniff(timeout=duration)
    wrpcap(output_pcap, packets)
    print(f"Traffic saved to {output_pcap}")

def stop_mitmproxy(proxy_process):
    """
    Stops the mitmproxy process.
    """
    proxy_process.terminate()
    proxy_process.wait()
    print("mitmproxy stopped.")



# Se il programma non è in esecuzione con sudo, rilanciarlo con sudo
if os.geteuid() != 0:
    python_path = sys.executable
    print("Questo programma richiede i permessi di amministratore (sudo). Rilancio con sudo...")
    
    # Rilancia il programma mantenendo l'ambiente con sudo -E
    subprocess.run(["sudo", "-E", python_path] + sys.argv)
    sys.exit()  # Esci dal programma attuale

    # Register the cleanup function to run on script exit
# atexit.register(reset_iptables)

# # Start mitmproxy in a subprocess
# proxy_process = start_mitmproxy()

# # Set up iptables to redirect all traffic to mitmproxy
# setup_iptables()

# # Capture traffic for the specified duration
# try:
#     capture_traffic()
# finally:
#     # Reset iptables and stop mitmproxy after capture
#     reset_iptables()
#     stop_mitmproxy(proxy_process)

# # Session keys are saved to `sslkeys.log` for decryption in Wireshark
# print("Session keys saved at 'sslkeys.log'. Load this in Wireshark with the pcap for decryption.")

#setup_iptables()

#reset_iptables()
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


output_file="captured_packets.pcap"
print("saving..")

print(f"Captured packets saved to {output_file}")