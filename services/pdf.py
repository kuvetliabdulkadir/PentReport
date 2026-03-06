from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.colors import HexColor
import tempfile


def pdf_olustur(baslik: str, portlar: list, analiz: str, cve_verileri: dict,
                http_basliklar: dict = None, ssl_bilgi: dict = None, dns_bilgi: dict = None) -> str:
    pdfmetrics.registerFont(TTFont('DejaVu', 'fonts/DejaVuSans.ttf'))

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    doc = SimpleDocTemplate(tmp.name, pagesize=A4,
                            rightMargin=2 * cm, leftMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)

    baslik_stili = ParagraphStyle('baslik', fontName='DejaVu', fontSize=20,
                                  textColor=HexColor('#1a1a2e'), spaceAfter=20)
    baslik2_stili = ParagraphStyle('baslik2', fontName='DejaVu', fontSize=14, spaceAfter=10)
    normal_stili = ParagraphStyle('normal', fontName='DejaVu', fontSize=10,
                                  leading=16, spaceAfter=8)
    cve_stili = ParagraphStyle('cve', fontName='DejaVu', fontSize=9,
                               textColor=HexColor('#cc0000'), spaceAfter=4)
    uyari_stili = ParagraphStyle('uyari', fontName='DejaVu', fontSize=9,
                                 textColor=HexColor('#ff8800'), spaceAfter=4)

    elemanlar = []

    # Başlık
    elemanlar.append(Paragraph(baslik, baslik_stili))
    elemanlar.append(Spacer(1, 0.5 * cm))

    # Bulunan portlar + CVE
    elemanlar.append(Paragraph("Bulunan Portlar:", baslik2_stili))
    for port in portlar:
        elemanlar.append(Paragraph(f"• {port}", normal_stili))
        port_no = port.split(" ")[1]
        if port_no in cve_verileri:
            for cve in cve_verileri[port_no]:
                elemanlar.append(Paragraph(
                    f"  ⚠ {cve['cve']} — CVSS: {cve['skor']} ({cve.get('seviye', 'N/A')})", cve_stili))

    elemanlar.append(Spacer(1, 0.5 * cm))

    # HTTP Başlıklar
    if http_basliklar:
        elemanlar.append(Paragraph("HTTP Güvenlik Başlıkları:", baslik2_stili))
        for baslik_adi, deger in http_basliklar.items():
            renk = '#cc0000' if '❌' in str(deger) else '#00aa44'
            stili = ParagraphStyle(f's_{baslik_adi}', fontName='DejaVu', fontSize=9,
                                   textColor=HexColor(renk), spaceAfter=4)
            elemanlar.append(Paragraph(f"• {baslik_adi}: {deger}", stili))
        elemanlar.append(Spacer(1, 0.5 * cm))

    # SSL Bilgisi
    if ssl_bilgi:
        elemanlar.append(Paragraph("SSL/TLS Durumu:", baslik2_stili))
        if ssl_bilgi.get("gecerli"):
            elemanlar.append(Paragraph(f"• Sertifika Geçerli ✅", normal_stili))
            elemanlar.append(Paragraph(f"• Bitiş Tarihi: {ssl_bilgi.get('bitis_tarihi', 'N/A')}", normal_stili))
        else:
            elemanlar.append(Paragraph(f"• Sertifika Geçersiz ❌ — {ssl_bilgi.get('hata', '')}", uyari_stili))
        elemanlar.append(Spacer(1, 0.5 * cm))

    # DNS Bilgisi
    if dns_bilgi:
        elemanlar.append(Paragraph("DNS Kayıtları:", baslik2_stili))
        for kayit, deger in dns_bilgi.items():
            if isinstance(deger, list):
                elemanlar.append(Paragraph(f"• {kayit}: {', '.join(deger[:2])}", normal_stili))
            else:
                elemanlar.append(Paragraph(f"• {kayit}: {deger}", normal_stili))
        elemanlar.append(Spacer(1, 0.5 * cm))

    # AI Analizi
    elemanlar.append(Paragraph("AI Güvenlik Analizi:", baslik2_stili))
    for satir in analiz.split('\n'):
        if satir.strip():
            temiz = satir.replace('**', '').replace('###', '').replace('##', '')
            elemanlar.append(Paragraph(temiz, normal_stili))

    doc.build(elemanlar)
    return tmp.name