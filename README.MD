# 1. Termux/Kali chroot:

pkg update
pkg install root-repo aircrack-ng hcxtools hashcat python tsu

# 2. Magisk Module (WAJIB):

# Magisk → Modules → "WiFi Monitor Mode Enabler"

# REBOOT!

# 3. Jalankan:

su
python3 main.py

su -c "iwconfig wlan0 mode monitor && iwconfig wlan0 up"

# Kalau "Mode:Monitor" → READY!

python3 main.py --duration 180
