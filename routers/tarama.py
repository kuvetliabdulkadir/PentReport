import socket
import re
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from services.ai import ai_analiz
from services.nvd import cvss_getir
from services.pdf import pdf_olustur
from services.veritabani import rapor_kaydet
from services.pasif_tarama import http_baslik_kontrol, ssl_kontrol, dns_kontrol
from services.nmap_tarama import nmap_tara, nmap_ssl_tara

router = APIRouter()

def is_ip(hedef: str) -> bool:
    return bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hedef))

@router.post("/tara-ve-raporla")
async def tara_ve_raporla(hedef: str):
    if not hedef:
        raise HTTPException(status_code=400, detail="Hedef belirtilmedi")

    ip_uyarisi = is_ip(hedef)

    if ip_uyarisi:
        ip = hedef
        domain = None
    else:
        domain = hedef
        try:
            ip = socket.gethostbyname(hedef)
        except:
            ip = hedef

    # Nmap subprocess ile tara
    port_listesi = nmap_tara(ip)

    if not port_listesi:
        raise HTTPException(status_code=404, detail=f"{hedef} adresine ulaşılamadı veya açık port bulunamadı.")

    portlar = []
    cve_verileri = {}

    for p in port_listesi:
        durum_etiketi = "" if p['durum'] == "open" else f" [{p['durum'].upper()}]"
        versiyon_goster = p['versiyon'] if p['versiyon'] else ""
        port_str = f"Port {p['port']} - {p['servis']} {versiyon_goster}{durum_etiketi}".strip()
        portlar.append(port_str)

        if p['durum'] == "open":
            # Versiyon temiz ve anlamlıysa CVE ara
            versiyon = p['versiyon'].strip()
            import re
            versiyon_temiz = re.sub(r'[^0-9.]', '', versiyon).strip('.')
            if versiyon_temiz and len(versiyon_temiz) >= 3:  # En az "1.0" gibi bir versiyon
                cve_sonuc = cvss_getir(p['servis'], versiyon, cpe_bilgisi=p['cpe'] if p['cpe'] else None)
                if cve_sonuc.get("cve_listesi"):
                    cve_verileri[p['port']] = cve_sonuc["cve_listesi"]

    pasif_hedef = domain if domain else ip
    http_basliklar = http_baslik_kontrol(pasif_hedef)
    ssl_bilgi = ssl_kontrol(pasif_hedef)
    dns_bilgi = dns_kontrol(pasif_hedef) if domain else {}
    ssl_analiz = nmap_ssl_tara(ip)

    tarama_metni = "\n".join(portlar)
    try:
        analiz = ai_analiz(tarama_metni=tarama_metni, ssl_analizi=ssl_analiz)
    except ValueError:
        raise HTTPException(status_code=429, detail="Yapay Zeka günlük analiz limiti aşıldı. Lütfen bekleyip tekrar deneyin.")

    pdf_yolu = pdf_olustur(
        baslik=f"PentReport AI - {hedef} Güvenlik Raporu",
        portlar=portlar,
        analiz=analiz,
        cve_verileri=cve_verileri,
        http_basliklar=http_basliklar,
        ssl_bilgi=ssl_bilgi,
        dns_bilgi=dns_bilgi,
        ip_uyarisi=ip_uyarisi
    )

    rapor_kaydet(hedef=hedef, pdf_yolu=pdf_yolu)

    return FileResponse(
        path=pdf_yolu,
        media_type="application/pdf",
        filename=f"{hedef}_rapor.pdf",
        content_disposition_type="attachment"
    )