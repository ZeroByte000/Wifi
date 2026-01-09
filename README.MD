# 🔥 Redmi Native WiFi Cracker

**Tool Audit WiFi Berbasis Python untuk Android**

Script ini dirancang untuk melakukan audit keamanan WiFi menggunakan serangan PMKID. Versi ini sudah dioptimalkan untuk menggunakan perintah native Linux/Android (`iw` dan `nl80211`),

> ⚠️ **PERINGATAN HUKUM**
> Tool ini hanya dibuat untuk tujuan **EDUKASI dan AUDIT KEAMANAN**. Penggunaan tool ini untuk menyerang jaringan yang bukan milik Anda atau tanpa izin adalah tindakan ilegal. Saya tidak bertanggung jawab atas penyalahgunaan alat ini.

---

## ✨ Fitur Utama

- **PMKID Attack:** Menangkap PMKID (handshake alternatif) yang lebih cepat tanpa perlu user terhubung ke WiFi.
- **Optimized for Mobile:** Dikonfigurasi untuk performa CPU/GPU ARM (Snapdragon/Qualcomm).
- **Auto Wordlist:** Mendownload wordlist otomatis jika belum ada.

---

## 📋 Persyaratan (Requirements)

Sebelum menjalankan script ini, pastikan perangkat Anda memenuhi syarat berikut:

1.  **Device:** Android (device dengan Kernel 5.15+).
2.  **Root:** Wajib sudah di-Root (KernelSU, Magisk, atau root manager lainnya).
3.  **Termux:** Versi terbaru (Download dari F-Droid, **bukan Play Store** untuk akses storage).
4.  **Kernel Support:** Kernel bawaan Anda **harus mendukung** perintah `iw` (nl80211) untuk masuk monitor mode tanpa patch. Jika kernel stok sangat ketat, monitor mode mungkin gagal.

---

## 🛠️ Cara Instalasi

Buka aplikasi **Termux** dan jalankan perintah berikut secara berurutan:

### 1. Update Termux

```bash
pkg update && pkg upgrade
```

_Jika diminta untuk menginstal ulang, pilih `y`._

### 2. Install Alat Pendukung

Kita membutuhkan Python, Git, dan alat-alat auditing WiFi.

```bash
pkg install python git wget curl termux-exec aircrack-ng hcxtools hashcat
```

> **Catatan:** Jika `hashcat` gagal terinstall karena keterbatasan arsitektur, gunakan versi CLI dari repo luar atau pastikan `termux-exec` berjalan.

### 3. Clone atau Buat Script

Jika Anda punya repository, git clone. Jika tidak, buat file baru.

```bash
git clone https://github.com/ZeroByte000/Wifi
cd Wifi
```

### 4. Beri Izin Eksekusi

```bash
chmod +x main.py
```

---

## 🚀 Cara Penggunaan

Jalankan script menggunakan Python dengan akses root (su).

### Langkah 1: Jalankan Script

```bash
tsu
python main.py
```

_Pastikan muncul tanda `#` di kiri prompt Terminal (menandakan root aktif)._

### Langkah 2: Monitor Mode Otomatis

Script akan otomatis mendeteksi interface (misal: `wlan0`) dan mencoba mengaktifkan Monitor Mode.

- ✅ Jika berhasil, akan muncul pesan `MONITOR MODE ACTIVE`.
- ❌ Jika gagal, lihat bagian Troubleshooting di bawah.

### Langkah 3: Scanning Target

Script akan menjalankan `airodump-ng` selama 20 detik default. Tunggu proses selesai.

### Langkah 4: Pilih Target

Pilih nomor jaringan (WPA2) yang ingin diuji keamanannya.

### Langkah 5: Serangan PMKID

Script akan menjalankan `hcxdumptool` untuk menangkap hash PMKID. Biarkan berjalan selama waktu durasi yang ditentukan (default 120 detik).

### Langkah 6: Cracking Password

Jika hash PMKID didapat, script akan otomatis menjalankan `hashcat` menggunakan wordlist yang terdownload.

---

## ⚠️ Troubleshooting (Masalah Umum)

### Masalah 1: "Monitor Mode Failed"

Ini terjadi karena script berjalan native tanpa patch Magisk.

- **Solusi:** Pastikan aplikasi Termux sudah mendapatkan akses Root (Storage Access mungkin perlu diberikan di pengaturan Android untuk Termux).
- **Solusi Kernel:** Jika kernel vendor (Xiaomi) sangat ketat mengunci monitor mode, perintah `iw dev wlan0 set type monitor` bisa ditolak. Jika ini terjadi, opsi terakhir adalah menggunakan kernel custom yang memang membuka akses nl80211, atau kembali menggunakan modul Magisk jika memang diminta oleh hardware.

### Masalah 2: Interface tidak terdeteksi

Jika `wlan0` tidak muncul, cek nama interface Anda:

```bash
su
ip link show
```

Jika nama interface Anda `wlan1` atau `mlan0`, jalankan script dengan argumen:

```bash
python main.py --iface wlan1
```

### Masalah 3: Hashcat Error `clCreateContext`

Ini biasanya error driver GPU pada Android.

- Script sudah diset menggunakan flag `--force`. Jika masih error, perangkat mungkin hanya bisa menggunakan CPU, atau perlu instalasi versi hashcat khusus ARM (OpenCL).

---

## 📂 Struktur File

```
Wifi/
├── main.py           # Script utama
├── rockyou.txt       # Wordlist password (auto download)
├── scan-01.csv # Hasil scan target
├── capture_*.pcapng  # Packet capture data
├── cracked.txt       # Hasil password jika berhasil
└── hashcat.potfile   # Database hashcat
```

---

## 👮‍♂️ Disclaimer

Hacking jaringan WiFi tanpa izin adalah ilegal. Gunakan tool ini hanya untuk belajar keamanan jaringan pada perangkat milik Anda sendiri.

---

_Dibuat untuk komunitas Termux & Mobile Security._
