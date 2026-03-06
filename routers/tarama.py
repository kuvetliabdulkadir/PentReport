import nmap
from fastapi import APIRouter
from fastapi.responses import FileResponse
from services.ai import ai_analiz
from services.nvd import cvss_getir
from services.pdf import pdf_olustur
from services.veritabani import rapor_kaydet
from services.pasif_tarama import http_baslik_kontrol, ssl_kontrol, dns_kontrol

router = APIRouter()

@router.post("/tara-ve-raporla")
async def tara_ve_raporla(hedef: str):
    nm = nmap.PortScanner()
    nm.scan(hedef, arguments='-sV')

    portlar = []
    cve_verileri = {}

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                servis = nm[host][proto][port]
                servis_adi = servis['name']
                versiyon = servis.get('version', '')
                portlar.append(f"Port {port} - {servis_adi} {versiyon}")

                cve_sonuc = cvss_getir(servis_adi, versiyon)
                if cve_sonuc["cve_listesi"]:
                    cve_verileri[str(port)] = cve_sonuc["cve_listesi"]

    if not portlar:
        return {"hata": "Hiç açık port bulunamadı"}

    # Pasif tarama
    http_basliklar = http_baslik_kontrol(hedef)
    ssl_bilgi = ssl_kontrol(hedef)
    dns_bilgi = dns_kontrol(hedef)

    tarama_metni = "\n".join(portlar)
    analiz = ai_analiz(tarama_metni)

    pdf_yolu = pdf_olustur(
        baslik=f"PentReport AI - {hedef} Güvenlik Raporu",
        portlar=portlar,
        analiz=analiz,
        cve_verileri=cve_verileri,
        http_basliklar=http_basliklar,
        ssl_bilgi=ssl_bilgi,
        dns_bilgi=dns_bilgi
    )

    rapor_kaydet(hedef=hedef, pdf_yolu=pdf_yolu)

    return FileResponse(pdf_yolu,
                       media_type="application/pdf",
                       filename=f"{hedef}_rapor.pdf")