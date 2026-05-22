# -*- coding: utf-8 -*-
import os
from datetime import datetime

def generate_risk_report(subject, sender, recipient, raw_email, ai_analysis, risk_level):
    """
    Fungsi untuk menghasilkan laporan analisis risiko rekayasa sosial / phishing
    dalam bentuk file teks (.txt) yang rapi untuk kebutuhan dokumentasi kuliah/praktikum.
    """
    risk_level = risk_level.upper()
    if risk_level == "TINGGI":
        status_str = "🔴 TINGGI (CRITICAL - SEGERA TINDAK LANJUTI)"
    elif risk_level == "SEDANG":
        status_str = "🟡 SEDANG (WARNING - MEMERLUKAN VERIFIKASI)"
    else:
        status_str = "🟢 RENDAH (INFO - AMAN / FALSE POSITIVE)"

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"Laporan_Analisis_Risiko_{file_timestamp}.txt"

    report_template = f"""================================================================================
                 LAPORAN HASIL ANALISIS RISIKO REKAYASA SOSIAL
                      DETEKSI PHISHING BERBASIS AI AGENT
================================================================================

[A] INFORMASI UMUM LAPORAN
--------------------------------------------------------------------------------
Waktu Analisis       : {current_time}
Platform Penguji     : Kali Linux (VirtualBox) & OpenClaw AI Gateway
Kanal Deteksi        : Telegram Bot Integration (@tugasrekayasasosial_bot)
Analis / Penguji     : Tim Praktikum Rekayasa Sosial

[B] METADATA EMAIL YANG DIUJI
--------------------------------------------------------------------------------
Subjek Email         : {subject}
Indikasi Pengirim    : {sender}
Target Penerima      : {recipient}
Kesimpulan Risiko    : {status_str}

[C] BUKTI FISIK / ISI EMAIL ASLI (RAW EMAIL TEXT)
--------------------------------------------------------------------------------
{raw_email.strip()}

--------------------------------------------------------------------------------

[D] HASIL ANALISIS MENDALAM AI AGENT (OPENCLAW DETECTOR LOG)
--------------------------------------------------------------------------------
{ai_analysis.strip()}

--------------------------------------------------------------------------------

[E] REKOMENDASI TINDAKAN & MITIGASI RISIKO (DEFENSE MECHANISM)
--------------------------------------------------------------------------------
1. ISOLASI & BLOKIR:
   - JANGAN sekali-kali berinteraksi dengan tautan (link), tombol, maupun mengunduh 
     berkas lampiran yang ada di dalam email tersebut.
   - Tambahkan alamat pengirim ({sender}) ke dalam daftar cekal/blokir (blacklist) 
     pada mail server / gateway keamanan organisasi.

2. PENANGANAN INFRASTRUKTUR (KORBAN & SIMULASI):
   - Jika pengujian ini menggunakan GoPhish, catat metrik keberhasilan simulasi 
     (apakah korban mengklik tautan atau memasukkan kredensial data sensitif).
   - Segera lakukan takedown/pencabutan tautan berbahaya jika terdeteksi di luar lab.

3. EDUKASI PENGGUNA (ANTI-SOCIAL ENGINEERING):
   - Sosialisasikan taktik ancaman (scareware) yang menuntut tindakan segera (urgency).
   - Terapkan prinsip Zero-Trust: selalu verifikasi saluran komunikasi secara sekunder 
     (misal: menanyakan langsung via telepon resmi, bukan membalas email tersebut).

================================================================================
                    DOKUMEN INI DIHASILKAN SECARA OTOMATIS
               LABORATORIUM FORENSIK DIGITAL & REKAYASA SOSIAL
================================================================================
"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_template)
        print(f"\n[+] BERHASIL: File laporan telah dibuat dengan nama: {filename}")
        print(f"[+] Lokasi File: {os.path.abspath(filename)}")
        print("-" * 80)
        print("KONTEN LAPORAN YANG DIHASILKAN:")
        print("-" * 80)
        print(report_template)
    except Exception as e:
        print(f"[-] GAGAL membuat file laporan: {str(e)}")

if __name__ == "__main__":
    print("=" * 60)
    print("      PROGRAM GENERATOR LAPORAN PHISHING (VS CODE / KALI)     ")
    print("=" * 60)
    
    # --- DATA CONTOH (SILAKAN DIUBAH / DI-EDIT SESUAI HASIL DARI BOT TELEGRAM ANDA) ---
    subjek_email = "Pemberitahuan Keamanan: Atur Ulang Kata Sandi Anda Sekarang!"
    pengirim_email = "security-update@gophish-simulation.local"
    penerima_email = "korban@target-perusahaan.com"
    
    isi_email_mentah = """Yth. Pengguna,
Kami mendeteksi adanya aktivitas login yang sangat mencurigakan pada akun perbankan / email Anda dari perangkat di luar negeri. 

Silakan klik link di bawah ini untuk memverifikasi identitas Anda dalam waktu kurang dari 24 jam. Jika Anda mengabaikan pesan ini, akun Anda akan ditangguhkan secara permanen untuk alasan keamanan.

Tautan Verifikasi: http://127.0.0.1/reset-password-login-portal"""
    
    # Bagian ini diisi dengan teks copy-paste balasan analisis dari bot Telegram Anda
    hasil_analisis_bot_telegram = """Hasil Analisis Otomatis OpenClaw AI Agent:
1. Sinyal Bahaya Utama: Ditemukan teknik Urgensi Palsu (Ancaman pemblokiran akun dalam waktu 24 jam) yang merupakan ciri khas rekayasa sosial.
2. Analisis Tautan (URL): Link eksternal mengarah ke IP Address lokal (127.0.0.1) dan bukan ke domain resmi instansi terkait, mengindikasikan serangan Phishing / credential harvesting.
3. Struktur Bahasa: Menggunakan metode intimidasi psikologis (Scareware) agar korban panik dan langsung bertindak tanpa berpikir panjang."""
    
    tingkat_risiko = "TINGGI" # Isikan pilihan: TINGGI / SEDANG / RENDAH
    
    # Menjalankan fungsi generator laporan
    generate_risk_report(
        subject=subjek_email,
        sender=pengirim_email,
        recipient=penerima_email,
        raw_email=isi_email_mentah,
        ai_analysis=hasil_analisis_bot_telegram,
        risk_level=tingkat_risiko
    )
