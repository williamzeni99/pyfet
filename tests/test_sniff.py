import os
import platform
import requests
import scapy.all as scapy
import time
import sys
import subprocess


# Funzione per impostare la variabile SSLKEYLOGFILE
def set_sslkeylogfile():
    # Ottieni il sistema operativo corrente
    current_os = platform.system()

    if current_os == "Linux":
        # Ottieni la directory dello script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Imposta il percorso per il file delle chiavi
        sslkeylogfile_path = os.path.join(script_dir, "sslkeys.log")
        os.environ["SSLKEYLOGFILE"] = sslkeylogfile_path
        print(f"SSLKEYLOGFILE set to: {sslkeylogfile_path}")
        
        # Avvia Firefox come utente normale
        subprocess.Popen(["sudo", "-u",f"{os.getlogin()}", f"SSLKEYLOGFILE={sslkeylogfile_path}","firefox"])
        time.sleep(10)
    else:
        print("This program only runs on Linux. Exiting.")
        sys.exit(1)


packets =[]
# Callback per gestire i pacchetti catturati
def packet_callback(packet):
    global packets
    packets.append(packet)

# Funzione per acquisire il traffico con Scapy per un tempo specificato

    

# Funzione per chiudere Firefox
def close_firefox():
    print("Chiudo tutti i processi di Firefox...")
    subprocess.run(["pkill", "firefox"], check=False)
    # Attendi un momento per assicurarti che tutti i processi siano terminati
    time.sleep(5)

# Se il programma non è in esecuzione con sudo, rilanciarlo con sudo
if os.geteuid() != 0:
    python_path = sys.executable
    print("Questo programma richiede i permessi di amministratore (sudo). Rilancio con sudo...")
    
    # Rilancia il programma mantenendo l'ambiente con sudo -E
    subprocess.run(["sudo", "-E", python_path] + sys.argv)
    sys.exit()  # Esci dal programma attuale

# Chiudi tutti i processi di Firefox prima di avviarlo
close_firefox()

# Imposta la variabile SSLKEYLOGFILE e avvia Firefox
set_sslkeylogfile()

# Acquisisci il traffico per 30 secondi utilizzando Scapy

t1=scapy.AsyncSniffer(prn=packet_callback, store=False)
t1.start()

for i in range(3):
    print(f"REQUEST {i}")
    requests.get("https://it.wikipedia.org/wiki/Wikipedia")
    time.sleep(4)

t1.stop()


output_file="captured_packets.pcap"
print("saving..")
scapy.wrpcap(output_file, packets)
print(f"Captured packets saved to {output_file}")
