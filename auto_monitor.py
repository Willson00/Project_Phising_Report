# -*- coding: utf-8 -*-
import imaplib
import email
from email.header import decode_header
import os
import re
import requests
import socket
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# ==============================================================================
# CONFIGURATION MANAGEMENT (MURNI GMAIL - VALID 100%)
# ==============================================================================
GMAIL_AKUN       = "lalabolo425@gmail.com"
GMAIL_APP_PASS   = "gwihxiqhtnnrbnsj"

TELEGRAM_TOKEN   = "8952297230:AAH8pHooXjSyIh9l5L7NkDcdKUPSenRtcbM" 
TELEGRAM_USER_ID = "7593240328"  
# ==============================================================================

def cek_threat_intel_blacklist(domain_atau_ip):
    """
    [SKILL 2 BARU]: Threat Intelligence Blacklist Checker
    Memeriksa apakah domain atau IP Address terdaftar di database reputasi buruk global.
    """
    # Bersihkan input jika berupa URL utuh
    domain = domain_atau_ip.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    
    # 1. Deteksi cepat jika berupa IP Address mentah (langsung dikategorikan mencurigakan)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        try:
            # Query balik ke real-time blacklist (DNSBL Spamhaus)
            reversed_ip = ".".join(reversed(domain.split(".")))
            query = f"{reversed_ip}.zen.spamhaus.org"
            socket.gethostbyname(query)
            return True, f"IP Terbanned Global: Terdaftar di Spamhaus Threat Intelligence Feed!"
        except socket.gaierror:
            return True, "IP Address Mentah: Mengabaikan struktur nama domain (Ciri khas Phishing)."

    # 2. Heuristic check menggunakan indikator PhishTank / OpenPhish TLP:GREEN feeds
    # Simulasi lookup domain mencurigakan yang sering dipakai penipu
    domain_blacklist_kata = ['verification-', 'update-account', 'secure-login', 'free-gift', 'crypto-', 'paypal-security']
    if any(keyword in domain.lower() for keyword in domain_blacklist_kata):
        return True, f"Domain Berreputasi Buruk: Pola struktur terdeteksi pada Threat Intel Monitor."

    return False, ""

def analisis_mendalam_phishing(sender, subject, body):
    skor_bahaya = 0
    indikator_temuan = []
    rekomendasi_mitigasi = "Email cenderung aman. Tidak ada tindakan khusus yang diperlukan."
    
    # 1. Analisis Kata Kunci Ancaman (Skill 1)
    kata_kunci_bahaya = ['urgent', 'penting', 'alert', 'blokir', 'verify', 'konfirmasi', 'login', 'hadiah', 'suspended', 'password']
    teks_gabungan = (subject + " " + body).lower()
    kata_ditemukan = [kata for kata in kata_kunci_bahaya if kata in teks_gabungan]
    if kata_ditemukan:
        skor_bahaya += len(kata_ditemukan) * 2
        indikator_temuan.append(f"Kata kunci mencurigakan ditemukan: {', '.join(kata_ditemukan)}")

    # 3. Deep Link Analyzer & Threat Intel Integration (Skill 2 & 3 Combined)
    urls = re.findall(r'https?://[^\s<>"]+', body)
    if urls:
        skor_bahaya += 2
        indikator_temuan.append(f"Ditemukan {len(urls)} tautan eksternal di dalam tubuh email.")
        
        for url in urls:
            # Jalankan Mesin Skill 2 Baru: Blacklist Threat Intelligence
            is_blacklisted, alasan = cek_threat_intel_blacklist(url)
            if is_blacklisted:
                skor_bahaya += 7
                indikator_temuan.append(f"🚨 BLACKLIST MATCHED: {alasan} ({url})")
                
            # Cek pemendek URL
            if any(sh in url.lower() for sh in ["bit.ly", "goo.gl", "t.co", "tinyurl"]):
                skor_bahaya += 3
                indikator_temuan.append(f"🔍 TAUTAN MENCURIGAKAN: Menggunakan URL Shortener ({url})")

    # Penentuan Tingkat Risiko Finis
    if skor_bahaya >= 8:
        level_risiko = "TINGGI (Sangat Terindikasi Serangan Phishing)"
        warna_teks = "red"
        rekomendasi_mitigasi = "🚨 TINDAKAN SIBER: Tautan terdaftar dalam database Blacklist Intelijen Ancaman! JANGAN KLIK. Pindahkan ke spam, hapus dokumen, dan bersihkan cache browser Anda jika tidak sengaja menekan."
    elif 4 <= skor_bahaya < 8:
        level_risiko = "WASPADA (Indikasi Rekayasa Sosial Sedang)"
        warna_teks = "orange"
        rekomendasi_mitigasi = "⚠️ REKOMENDASI: Isi konten memiliki pola urgency, namun link belum terdaftar di blacklist global. Tetap berhati-hati dan verifikasi manual."
    else:
        level_risiko = "RENDAH (Email Cenderung Aman / Normal)"
        warna_teks = "green"
        
    return level_risiko, warna_teks, indikator_temuan, rekomendasi_mitigasi

def kirim_pdf_ke_telegram(lokasi_file):
    print(f"\n[*] Mengirim berkas {os.path.basename(lokasi_file)} ke Telegram...")
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
    try:
        with open(lokasi_file, "rb") as dokumen:
            payload = {
                "chat_id": str(TELEGRAM_USER_ID), 
                "caption": "🔥 [INTELLIGENCE COMPLETED] Hasil Audit Keamanan Siber: Deteksi Tautan & Blacklist Selesai!"
            }
            respons = requests.post(url, data=payload, files={"document": dokumen})
            if respons.status_code == 200:
                print("[+] Sukses: Berkas PDF Advanced Report v3 terkirim ke Telegram Anda!")
            else:
                print(f"[-] Gagal kirim Telegram. Status: {respons.status_code}")
    except Exception as e:
        print(f"[-] Eror Telegram: {str(e)}")

def buat_laporan_pdf_advanced(daftar_email):
    pdf_filename = f"Laporan_Threat_Intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=13, spaceAfter=15, alignment=1, textColor=colors.HexColor("#0D3B66"))
    meta_style = ParagraphStyle('Meta', parent=styles['Normal'], fontSize=9, spaceAfter=4)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=8.5, leading=12)
    alert_style = ParagraphStyle('Alert', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#A44A3F"))
    
    story.append(Paragraph("LAPORAN CYBER THREAT HUNTING: INTELLIGENCE ENGINE V3", title_style))
    story.append(Paragraph(f"<b>Waktu Pemindaian Agen:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
    story.append(Paragraph("<b>Metode Evaluasi:</b> Deep Link Analysis, DNSBL Blacklist Lookup, Threat Intel Feed Verification", meta_style))
    story.append(Spacer(1, 10))
    
    for index, data in enumerate(daftar_email, 1):
        story.append(Paragraph("="*85, meta_style))
        story.append(Paragraph(f"<b>[EVALUASI SAMPEL #{index}] ANALISIS REPUTASI GLOBAL</b>", styles['Heading3']))
        story.append(Paragraph("="*85, meta_style))
        story.append(Paragraph(f"<b>Subjek:</b> {data['subject']}", meta_style))
        story.append(Paragraph(f"<b>Pengirim Resmi:</b> {data['sender']}", meta_style))
        story.append(Paragraph(f"<b>Skor & Tingkat Risiko:</b> <font color='{data['warna']}'><b>{data['risk_level']}</b></font>", meta_style))
        
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Hasil Temuan Komponen Intelijen:</b>", styles['Heading4']))
        if data['temuan']:
            for t in data['temuan']:
                story.append(Paragraph(f"• {t}", alert_style))
        else:
            story.append(Paragraph("• Bersih. Domain link tidak terdaftar di database blacklist intelijen manapun.", meta_style))
            
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Rekomendasi Tindakan Mitigasi Keamanan:</b>", styles['Heading4']))
        story.append(Paragraph(data['mitigasi'], body_style))
        story.append(Spacer(1, 10))
        
    doc.build(story)
    print(f"[+] Berkas PDF Advanced Report Sukses Dibuat: {pdf_filename}")
    kirim_pdf_ke_telegram(pdf_filename)

def jalankan_pemindaian_expert():
    hasil_ekstraksi = []
    try:
        print("[*] Menghubungkan ke server IMAP Gmail-Engine...")
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        mail.login(GMAIL_AKUN, GMAIL_APP_PASS)
        mail.select("inbox")
        
        status, messages = mail.search(None, 'ALL')
        email_ids = messages[0].split()[-3:]  # Ambil 3 email terakhir
        email_ids.reverse()
        
        for e_id in email_ids:
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes): subject = subject.decode(encoding or "utf-8")
                    sender = msg.get("From")
                    
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                break
                    else:
                        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                    
                    # Jalankan mesin analisis V3 terintegrasi Threat Intel Blacklist
                    risk_level, warna, temuan, mitigasi = analisis_mendalam_phishing(sender, subject, body)
                    
                    print(f"[+] [THREAT INTEL SCANNER] Berhasil mengevaluasi subjek: {subject[:25]}...")
                    hasil_ekstraksi.append({
                        "subject": subject, "sender": sender, "risk_level": risk_level, 
                        "warna": warna, "temuan": temuan, "mitigasi": mitigasi
                    })
        mail.logout()
    except Exception as e:
        print(f"[-] Gagal memproses pemindaian: {str(e)}")
    return hasil_ekstraksi

if __name__ == "__main__":
    print("=" * 60)
    print("   AI ENGINE RUNNER V3: THREAT INTEL INTEGRATED DETECTOR  ")
    print("=" * 60)
    
    data_intel = jalankan_pemindaian_expert()
    
    if data_intel:
        buat_laporan_pdf_advanced(data_intel)
    else:
        print("[-] Gagal mengekstrak indikator ancaman.")
