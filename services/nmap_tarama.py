import subprocess
import xml.etree.ElementTree as ET
import re
import sys

# Platform bağımsız Nmap path
def _nmap_path() -> str:
    if sys.platform != "win32":
        return "nmap"  # Railway/Linux: PATH'de
    return r"C:\Program Files (x86)\Nmap\nmap.exe"  # Windows

NMAP_PATH = _nmap_path()


def _parse_nmap_xml(xml_text: str) -> ET.Element:
    xml_text = re.sub(r'<!DOCTYPE[^>]+>', '', xml_text)
    return ET.fromstring(xml_text)


def nmap_tara(hedef: str) -> list:
    try:
        cmd = [
            NMAP_PATH, "-sT", "-sV",
            "--version-intensity", "2",
            "-p", "21,22,25,53,80,110,143,443,465,587,993,995,1433,1434,1720,3306,3389,8080,8443",
            "--host-timeout", "300s",
            "--max-rtt-timeout", "2000ms",
            "--initial-rtt-timeout", "500ms",
            "-oX", "-",
            hedef
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)

        if result.returncode != 0:
            print(f"[NMAP HATA] {result.stderr}")
            return []

        root = _parse_nmap_xml(result.stdout)
        portlar = []

        for host in root.findall("host"):
            for ports_elem in host.findall("ports"):
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    port_id = port.get("portid")
                    servis = port.find("service")

                    SSL_SERVIS_MAP = {
                        "443": "https", "465": "smtps",
                        "993": "imaps", "995": "pop3s", "587": "submission",
                        "1433": "ms-sql-s", "1434": "ms-sql-m", "1720": "h323q931"
                    }

                    if servis is not None:
                        servis_adi = servis.get("name", "unknown")
                        if port_id in SSL_SERVIS_MAP and servis_adi in ("http", "smtp", "imap", "pop3"):
                            servis_adi = SSL_SERVIS_MAP[port_id]
                        product = servis.get("product", "")
                        version = servis.get("version", "")

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
                    else:
                        servis_adi = "unknown"
                        versiyon = ""

                    cpe = ""
                    for cpe_elem in port.findall(".//cpe"):
                        cpe = cpe_elem.text or ""
                        break

                    portlar.append({
                        "port": port_id,
                        "servis": servis_adi,
                        "versiyon": versiyon,
                        "cpe": cpe,
                        "durum": "open"
                    })

        print(f"[NMAP] {len(portlar)} port bulundu")
        return portlar

    except subprocess.TimeoutExpired:
        print("[NMAP] Timeout aşıldı")
        return []
    except Exception as e:
        print(f"[NMAP HATA] {str(e)}")
        return []


def nmap_ssl_tara(hedef: str) -> str:
    try:
        cmd = [
            NMAP_PATH, "-sT",
            "-p", "443,465,587",
            "--script", "ssl-enum-ciphers",
            "--host-timeout", "300s",
            "--max-rtt-timeout", "2000ms",
            "-oX", "-",
            hedef
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)

        if result.returncode != 0:
            return "SSL analizi yapılamadı."

        root = _parse_nmap_xml(result.stdout)
        analiz_metni = ""

        for host in root.findall("host"):
            for ports_elem in host.findall("ports"):
                for port in ports_elem.findall("port"):
                    port_id = port.get("portid")
                    for script in port.findall(".//script[@id='ssl-enum-ciphers']"):
                        analiz_metni += f"\n[Port {port_id} SSL/TLS Analizi]:\n"
                        analiz_metni += script.get("output", "") + "\n"

        return analiz_metni if analiz_metni else "SSL/TLS Cipher verisi bulunamadı."

    except Exception as e:
        return f"SSL Analiz Hatası: {str(e)}"