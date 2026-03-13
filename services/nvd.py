import requests
import re
import time


def cvss_getir(servis_adi: str, versiyon: str, cpe_bilgisi: str = None) -> dict:
    cve_listesi = []
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    versiyon_temiz = re.sub(r'[^0-9.]', '', versiyon).strip('.') if versiyon else ""

    params = {"resultsPerPage": 5}

    if cpe_bilgisi:
        params["cpeName"] = cpe_bilgisi
    elif servis_adi and versiyon_temiz:
        params["keywordSearch"] = f"{servis_adi} {versiyon_temiz}"
    else:
        return {"cve_listesi": []}

    try:
        # NVD API key olmadan max 5 istek/30 saniye — güvenli taraf 6sn/istek
        time.sleep(6)

        res = requests.get(base_url, params=params, timeout=15)

        if res.status_code in [403, 429]:
            print(f"[NVD] Rate limit, bekleniyor...")
            time.sleep(30)
            return {"cve_listesi": []}

        # Boş yanıt kontrolü
        if not res.text.strip() or res.status_code != 200:
            return {"cve_listesi": []}

        data = res.json()

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]

            match = re.search(r'CVE-(\d{4})-', cve_id)
            if match and int(match.group(1)) < 2018 and versiyon_temiz:
                continue

            metrics = cve.get("metrics", {})
            skor, seviye = "N/A", "N/A"

            if "cvssMetricV40" in metrics:
                skor = metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
                seviye = metrics["cvssMetricV40"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV31" in metrics:
                skor = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                seviye = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV30" in metrics:
                skor = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                seviye = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                skor = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                seviye = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

            cve_listesi.append({
                "cve": cve_id,
                "skor": skor,
                "seviye": seviye
            })

        return {"cve_listesi": cve_listesi}

    except Exception as e:
        print(f"[NVD HATA] {str(e)}")
        return {"cve_listesi": []}