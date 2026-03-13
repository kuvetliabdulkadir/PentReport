from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
import xml.etree.ElementTree as ET
import re
from services.ai import ai_analiz
from services.nvd import cvss_getir
from services.pdf import pdf_olustur
from services.veritabani import rapor_kaydet

router = APIRouter()

@router.post("/rapor")
async def rapor_olustur(file: UploadFile = File(...)):
    content = await file.read()

    # DOCTYPE temizle
    xml_text = content.decode("utf-8", errors="ignore")
    xml_text = re.sub(r'<!DOCTYPE[^>]+>', '', xml_text)
    root = ET.fromstring(xml_text)

    portlar = []
    cve_verileri = {}
    hedef_ip = "Bilinmiyor"

    for host in root.findall("host"):
        # Hedef IP'yi XML'den çek
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                hedef_ip = addr.get("addr", "Bilinmiyor")
                break
        # Hostname varsa onu kullan
        for hn in host.findall(".//hostname"):
            if hn.get("type") == "user":
                hedef_ip = hn.get("name", hedef_ip)
                break

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue

            port_id = port.get("portid")
            servis = port.find("service")
            servis_adi = servis.get("name", "bilinmiyor") if servis is not None else "bilinmiyor"

            # SSL port isim düzeltmesi
            SSL_SERVIS_MAP = {
                "443": "https", "465": "smtps",
                "993": "imaps", "995": "pop3s", "587": "submission"
            }
            if port_id in SSL_SERVIS_MAP and servis_adi in ("http", "smtp", "imap", "pop3"):
                servis_adi = SSL_SERVIS_MAP[port_id]

            product = servis.get("product", "") if servis is not None else ""
            version = servis.get("version", "") if servis is not None else ""

            # Versiyon temizle
            versiyon_temiz = re.sub(r'[^0-9.]', '', version).strip('.')
            version_gecerli = bool(re.match(r'^\d+\.\d+', versiyon_temiz))

            if product and version_gecerli:
                versiyon = f"{product} {versiyon_temiz}"
            elif product:
                versiyon = product
            elif version_gecerli:
                versiyon = versiyon_temiz
            else:
                versiyon = ""

            cpe = ""
            for cpe_elem in port.findall(".//cpe"):
                cpe = cpe_elem.text or ""
                break

            portlar.append(f"Port {port_id} - {servis_adi} {versiyon}".strip())

            if version_gecerli or cpe:
                cve_sonuc = cvss_getir(servis_adi, versiyon, cpe_bilgisi=cpe if cpe else None)
                if cve_sonuc["cve_listesi"]:
                    cve_verileri[port_id] = cve_sonuc["cve_listesi"]

    if not portlar:
        raise HTTPException(status_code=400, detail="XML dosyasında açık port bulunamadı.")

    tarama_metni = "\n".join(portlar)

    try:
        analiz = ai_analiz(tarama_metni)
    except ValueError:
        raise HTTPException(status_code=429, detail="Yapay Zeka günlük analiz limiti aşıldı. Lütfen bekleyip tekrar deneyin.")

    pdf_yolu = pdf_olustur(
        baslik=hedef_ip,
        portlar=portlar,
        analiz=analiz,
        cve_verileri=cve_verileri
    )

    rapor_kaydet(hedef=hedef_ip, pdf_yolu=pdf_yolu)

    return FileResponse(pdf_yolu,
                        media_type="application/pdf",
                        filename="guvenlik_raporu.pdf")