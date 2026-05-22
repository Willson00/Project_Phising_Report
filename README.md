# Project Phising Report - OpenClaw V3

Sistem deteksi ancaman phishing email otomatis berbasis heuristik dan DNSBL (Spamhaus). Sistem ini memantau email masuk melalui protokol IMAP, menganalisis indikator ancaman (URL Shortener & Raw IP), dan mengirimkan laporan forensik dalam bentuk berkas PDF secara real-time ke Telegram Administrator.

## 🛠️ Arsitektur Sistem
1. **Ingestion Layer:** Membaca email masuk dari Gmail via IMAP (Port 993).
2. **Analysis Layer (Python):** - Deteksi pola URL menggunakan Regex.
   - Pengecekan IP/Domain reputasi buruk via DNSBL (Spamhaus).
3. **Notification Layer:** Pembuatan dokumen PDF laporan dan pengiriman via Telegram Bot API.

## 🚀 Cara Instalasi & Penggunaan

### 1. Kloning Repositori
```bash
git clone [https://github.com/Willson00/Project_Phising_Report.git](https://github.com/Willson00/Project_Phising_Report.git)
cd Project_Phising_Report
## 📺 Video Demonstrasi Aplikasi
Berikut adalah link video demonstrasi jalannya sistem Project Phising Report di Kali Linux:

👉 [https://drive.google.com/drive/u/0/folders/1thA1QkUjHOVtLnDpk0GTgb5-KcBS8ZsL)
Certif dan dokumentasi ada di link tersebut
