from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.colors import HexColor
from fastapi.responses import FileResponse
from dotenv import load_dotenv

import tempfile
import os

from fastapi import FastAPI, UploadFile, File
import xml.etree.ElementTree as ET
import google.generativeai as genai

app = FastAPI()

# Gemini client
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")


@app.get("/")
def root():
    return {"mesaj": "PentReport AI çalışıyor"}


@app.post("/upload")
async def upload_scan(file: UploadFile = File(...)):
    # XML oku ve parse et
    content = await file.read()
    root = ET.fromstring(content)

    portlar = []
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            servis = port.find("service")
            servis_adı = servis.get("name", "bilinmiyor") if servis is not None else "bilinmiyor"
            versiyon = servis.get("version", "") if servis is not None else ""
            portlar.append(f"Port {port_id} - {servis_adı} {versiyon}")

    # AI'ya gönder
    tarama_metni = "\n".join(portlar)

    prompt = f"""Sen bir siber güvenlik uzmanısın. 
    Nmap tarama sonuçlarını analiz et, her port için risk seviyesi belirt (Düşük/Orta/Yüksek), 
    sade ve anlaşılır Türkçe yaz.

    Tarama sonuçları:
    {tarama_metni}"""

    response = model.generate_content(prompt)
    analiz = response.text

    return {
        "bulunan_portlar": portlar,
        "ai_analizi": analiz
    }


@app.post("/rapor")
async def rapor_olustur(file: UploadFile = File(...)):
    # XML parse et
    content = await file.read()
    root = ET.fromstring(content)

    portlar = []
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            servis = port.find("service")
            servis_adı = servis.get("name", "bilinmiyor") if servis is not None else "bilinmiyor"
            versiyon = servis.get("version", "") if servis is not None else ""
            portlar.append(f"Port {port_id} - {servis_adı} {versiyon}")

    # AI analizi al
    tarama_metni = "\n".join(portlar)
    prompt = f"""Sen bir siber güvenlik uzmanısın. 
    Nmap tarama sonuçlarını analiz et, her port için risk seviyesi belirt (Düşük/Orta/Yüksek), 
    sade ve anlaşılır Türkçe yaz.
    Tarama sonuçları:
    {tarama_metni}"""

    response = model.generate_content(prompt)
    analiz = response.text

    # PDF oluştur
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdfmetrics.registerFont(TTFont('DejaVu', r'C:\Users\akkuv\OneDrive\Masaüstü\Poppins\Fonts\ttf\DejaVuSans.ttf'))
    doc = SimpleDocTemplate(tmp.name, pagesize=A4,
                            rightMargin=2 * cm, leftMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)

    styles = getSampleStyleSheet()

    # Özel stiller
    baslik_stili = ParagraphStyle('baslik', fontName='DejaVu', fontSize=20,
                                  textColor=HexColor('#1a1a2e'), spaceAfter=20)
    normal_stili = ParagraphStyle('normal', fontName='DejaVu', fontSize=10,
                                  leading=16, spaceAfter=8)
    baslik2_stili = ParagraphStyle('baslik2', fontName='DejaVu', fontSize=14, spaceAfter=10)
    elemanlar = []

    # Başlık
    elemanlar.append(Paragraph("PentReport AI - Güvenlik Tarama Raporu", baslik_stili))
    elemanlar.append(Spacer(1, 0.5 * cm))

    # Bulunan portlar
    elemanlar.append(Paragraph("Bulunan Portlar:", baslik2_stili))
    for port in portlar:
        elemanlar.append(Paragraph(f"• {port}", normal_stili))

    elemanlar.append(Spacer(1, 0.5 * cm))

    # AI Analizi
    elemanlar.append(Paragraph("AI Güvenlik Analizi:", baslik2_stili ))
    for satir in analiz.split('\n'):
        if satir.strip():
            temiz = satir.replace('**', '').replace('###', '').replace('##', '')
            elemanlar.append(Paragraph(temiz, normal_stili))

    doc.build(elemanlar)

    return FileResponse(tmp.name,
                        media_type="application/pdf",
                        filename="guvenlik_raporu.pdf")