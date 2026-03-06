from fastapi import APIRouter, UploadFile, File
from fastapi.responses import FileResponse
import xml.etree.ElementTree as ET
from services.ai import ai_analiz
from services.nvd import cvss_getir
from services.pdf import pdf_olustur
from services.veritabani import rapor_kaydet

router = APIRouter()

@router.post("/rapor")
async def rapor_olustur(file: UploadFile = File(...)):
    content = await file.read()
    root = ET.fromstring(content)

    portlar = []
    cve_verileri = {}

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            servis = port.find("service")
            servis_adi = servis.get("name", "bilinmiyor") if servis is not None else "bilinmiyor"
            versiyon = servis.get("version", "") if servis is not None else ""
            portlar.append(f"Port {port_id} - {servis_adi} {versiyon}")

            cve_sonuc = cvss_getir(servis_adi, versiyon)
            if cve_sonuc["cve_listesi"]:
                cve_verileri[port_id] = cve_sonuc["cve_listesi"]

    tarama_metni = "\n".join(portlar)
    analiz = ai_analiz(tarama_metni)

    pdf_yolu = pdf_olustur(
        baslik="PentReport AI - Güvenlik Tarama Raporu",
        portlar=portlar,
        analiz=analiz,
        cve_verileri=cve_verileri
    )

    # Raporu veritabanına kaydet
    rapor_kaydet(hedef="XML Yükleme", pdf_yolu=pdf_yolu)

    return FileResponse(pdf_yolu,
                       media_type="application/pdf",
                       filename="guvenlik_raporu.pdf")