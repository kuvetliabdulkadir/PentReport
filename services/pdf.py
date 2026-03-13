import re
import html
import tempfile
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.colors import HexColor


def alt_bilgi_ekle(canvas, doc):
    canvas.saveState()
    canvas.setFont('DejaVu' if 'DejaVu' in pdfmetrics.getRegisteredFontNames() else 'Helvetica', 9)
    canvas.setStrokeColor(HexColor('#cbd5e1'))
    canvas.line(1.5 * cm, 1.5 * cm, A4[0] - 1.5 * cm, 1.5 * cm)
    sayfa_no = f"Sayfa {doc.page}"
    canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, sayfa_no)
    canvas.drawString(1.5 * cm, 1 * cm, "Gizli - Güvenlik Analiz Raporu")
    canvas.restoreState()


def _baslik_temizle(baslik: str) -> str:
    """'PentReport AI - example.com Güvenlik Raporu' → 'example.com' """
    temiz = re.sub(r'(?i)pentreport\s*ai\s*[-–]?\s*', '', baslik)
    temiz = re.sub(r'(?i)\s*güvenlik\s*raporu', '', temiz)
    return temiz.strip()


def pdf_olustur(baslik, portlar, analiz, cve_verileri, http_basliklar=None, ssl_bilgi=None, dns_bilgi=None, ip_uyarisi=False):
    try:
        pdfmetrics.registerFont(TTFont('DejaVu', 'fonts/DejaVuSans.ttf'))
        font_name = 'DejaVu'
    except:
        font_name = 'Helvetica'

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")

    PRIMARY = HexColor('#1e293b')
    ACCENT = HexColor('#4f46e5')
    BG_LIGHT = HexColor('#f8fafc')

    doc = SimpleDocTemplate(tmp.name, pagesize=A4,
                            rightMargin=1.5 * cm, leftMargin=1.5 * cm,
                            topMargin=2 * cm, bottomMargin=2.5 * cm)

    styles = {
        'H1': ParagraphStyle('H1', fontName=font_name, fontSize=22, textColor=PRIMARY, alignment=1, spaceAfter=6),
        'H1Sub': ParagraphStyle('H1Sub', fontName=font_name, fontSize=14, textColor=ACCENT, alignment=1, spaceAfter=20),
        'H2': ParagraphStyle('H2', fontName=font_name, fontSize=13, textColor=ACCENT, spaceBefore=15, spaceAfter=10),
        'Normal': ParagraphStyle('Normal', fontName=font_name, fontSize=10, leading=14, textColor=HexColor('#334155'), spaceAfter=8),
        'Bullet': ParagraphStyle('Bullet', fontName=font_name, fontSize=10, leading=14, leftIndent=20, firstLineIndent=-10, spaceAfter=5),
        'TableText': ParagraphStyle('TableText', fontName=font_name, fontSize=9, leading=12),
        'Warning': ParagraphStyle('Warning', fontName=font_name, fontSize=10, textColor=HexColor('#9a3412'), backColor=HexColor('#ffedd5'), borderPadding=10)
    }

    hedef_adi = _baslik_temizle(baslik)

    elemanlar = []
    elemanlar.append(Spacer(1, 2 * cm))
    elemanlar.append(Paragraph("<b>GÜVENLİK ANALİZ RAPORU</b>", styles['H1']))
    elemanlar.append(Paragraph(f"<b>{hedef_adi.upper()}</b>", styles['H1Sub']))
    elemanlar.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=30))

    if ip_uyarisi:
        elemanlar.append(Paragraph(
            "<b>UYARI:</b> IP tabanlı tarama yapıldı. Paylaşımlı sunucu tespiti halinde sonuçlar kısıtlı olabilir.",
            styles['Warning']))
        elemanlar.append(Spacer(1, 0.5 * cm))

    elemanlar.append(Paragraph("Açık Portlar ve Zafiyetler", styles['H2']))
    for port in portlar:
        elemanlar.append(Paragraph(f"• <b>{port}</b>", styles['Normal']))
        p_no = port.split(" ")[1] if " " in port else port
        if p_no in cve_verileri:
            for cve in cve_verileri[p_no]:
                txt = f"<font color='#b91c1c'><b>{cve['cve']}</b></font> - CVSS: {cve['skor']}"
                elemanlar.append(Paragraph(txt, styles['Bullet']))

    def tablo_ciz(baslik_mt, veri, widths):
        if not veri:
            return
        elemanlar.append(Paragraph(baslik_mt, styles['H2']))
        t_data = [[Paragraph("<b>Kriter</b>", styles['TableText']), Paragraph("<b>Değer</b>", styles['TableText'])]]
        for k, v in veri.items():
            val = ", ".join(v[:3]) if isinstance(v, list) else str(v)
            t_data.append([Paragraph(str(k), styles['TableText']), Paragraph(html.escape(val), styles['TableText'])])
        t = Table(t_data, colWidths=widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elemanlar.append(t)
        elemanlar.append(Spacer(1, 0.5 * cm))

    tablo_ciz("HTTP Güvenlik Başlıkları", http_basliklar, [6 * cm, 12 * cm])
    tablo_ciz("DNS Analiz Bilgileri", dns_bilgi, [4 * cm, 14 * cm])

    if ssl_bilgi and isinstance(ssl_bilgi, dict) and ssl_bilgi.get("gecerli") is not None:
        ssl_veri = {}
        if ssl_bilgi.get("gecerli") is True:
            ssl_veri["Durum"] = "Geçerli"
            ssl_veri["Bitiş Tarihi"] = ssl_bilgi.get("bitis_tarihi", "Bilinmiyor")
            konu = ssl_bilgi.get("konu", {})
            if konu:
                ssl_veri["Konu"] = str(konu.get("commonName", ""))
        elif ssl_bilgi.get("gecerli") is False:
            ssl_veri["Durum"] = "Geçersiz"
            ssl_veri["Hata"] = ssl_bilgi.get("hata", "Bilinmiyor")
        else:
            ssl_veri["Durum"] = ssl_bilgi.get("bilgi", "Kontrol edilemedi")
        if ssl_veri:
            tablo_ciz("SSL Sertifika Bilgisi", ssl_veri, [5 * cm, 13 * cm])

    elemanlar.append(PageBreak())
    elemanlar.append(Paragraph("Yapay Zeka Analiz Raporu", styles['H2']))

    for satir in analiz.split('\n'):
        satir = satir.strip()
        if not satir or satir.startswith('```'):
            continue

        # ---BÖLÜM X: ...--- formatını başlık olarak yakala
        bolum_match = re.match(r'^-{2,}(.+?)-{2,}$', satir)
        if bolum_match:
            baslik_ic = bolum_match.group(1).strip()
            elemanlar.append(Spacer(1, 0.3 * cm))
            elemanlar.append(Paragraph(f"<b>{baslik_ic}</b>", styles['H2']))
            continue

        satir = html.escape(satir)
        satir = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', satir)

        if satir.startswith('#'):
            h_clean = re.sub(r'^#+\s*', '', satir)
            elemanlar.append(Paragraph(f"<b>{h_clean}</b>", styles['H2']))
        elif re.match(r'^\d+\.\s+\[', satir):
            elemanlar.append(Paragraph(satir, styles['Bullet']))
        elif satir.startswith(('*', '•')):
            b_clean = re.sub(r'^[*•]\s*', '', satir)
            elemanlar.append(Paragraph(f"• {b_clean}", styles['Bullet']))
        elif satir.startswith('-') and not satir.startswith('--'):
            b_clean = re.sub(r'^-\s*', '', satir)
            elemanlar.append(Paragraph(f"• {b_clean}", styles['Bullet']))
        else:
            elemanlar.append(Paragraph(satir, styles['Normal']))

    doc.build(elemanlar, onFirstPage=alt_bilgi_ekle, onLaterPages=alt_bilgi_ekle)
    return tmp.name