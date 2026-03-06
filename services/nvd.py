import requests
import re


def cvss_getir(servis_adi: str, versiyon: str) -> dict:
    if not versiyon or versiyon.strip() == "":
        return {"cve_listesi": []}

    # Versiyonu temizle — sadece sayısal kısım al
    versiyon_temiz = re.sub(r'[^0-9.]', '', versiyon).strip('.')
    if not versiyon_temiz:
        return {"cve_listesi": []}

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": f"{servis_adi} {versiyon_temiz}",
            "resultsPerPage": 3
        }
        res = requests.get(url, params=params, timeout=10)
        data = res.json()

        cve_listesi = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]

            skor = "N/A"
            seviye = "N/A"
            metrics = cve.get("metrics", {})

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
    except:
        return {"cve_listesi": []}