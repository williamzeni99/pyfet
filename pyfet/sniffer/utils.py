

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import scapy.all as scapy


class ForensicSniffer:
    #THIS CLASS MUST BE EXECUTED AS ROOT

    class ForensicFile:
        def __init__(self, path:Path) -> None:
            with open(path, 'rb') as file:
                self.filename= path.name
                self.raw = file.read()

            self.sha256 = hashlib.sha256(self.raw).hexdigest()
            self.sha1 = hashlib.sha1(self.raw).hexdigest()
            self.md5 = hashlib.md5(self.raw).hexdigest()

    def __init__(self, save_path:Path) -> None:
        self.save_path= save_path

        self.start_time = None
        self.save_file = None
        self.sniff_process = None
        self.session_keys_file = None
        self.stop_file_path = Path(__file__).resolve().parent / "STOP"


    def start_sniff(self):
        self.start_time= datetime.utcnow()
        self.save_file_path = self.save_path / f"sniffed-{self.start_time}.pcap"

        if self.stop_file_path.exists():
            self.stop_file_path.unlink()
        
        self.sniff_process = subprocess.Popen(
            ["sudo", sys.executable, f"{Path(__file__).resolve().parent / 'sniffer_script.py'}", str(self.save_file_path), str(self.stop_file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        

    def stop_sniff(self):
        try:
            self.stop_file_path.touch()
            self.sniff_process.wait()
            self.sniff_process = None
            self.save_file = self.ForensicFile(self.save_file_path)
            pattern = re.compile(r"^sessionkeys\.\d+\.\d+$")
            for file in self.save_path.iterdir():
                if file.is_file() and pattern.match(file.name):
                    new_path= file.rename(f"sessionkeys-{self.start_time}.log")
                    session_keys_file_path = new_path.resolve()
                    self.session_keys_file = self.ForensicFile(session_keys_file_path)
                    break
            
        except Exception as e:
            self.abort_sniff()
            raise e
    
    def abort_sniff(self):
        try:
            self.stop_file_path.touch()   
            self.sniff_process.wait()     
        except:
            pass

        self.sniff_process = None
        pattern = re.compile(r"^sessionkeys\.\d+\.\d+$")
        for file in self.save_path.iterdir():
            if file.is_file() and pattern.match(file.name):
                file.unlink()
                break
    
    



