import google.generativeai as genai
import time


def ai_analiz(tarama_metni: str) -> str:
    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""Sen bir siber güvenlik uzmanısın. Nmap tarama sonuçlarını analiz et.
Her port için şunları yaz:
1. CVSS Skoru: 0.0 - 10.0 arası
2. Risk Seviyesi: Düşük (0-3.9) / Orta (4.0-6.9) / Yüksek (7.0-8.9) / Kritik (9.0-10.0)
3. Neden riskli: Kısa açıklama
4. Nasıl kapatılır: Adım adım teknik talimat (komutlar dahil)
Türkçe yaz.
Tarama sonuçları:
{tarama_metni}"""

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        if "RESOURCE_EXHAUSTED" in str(e):
            time.sleep(35)
            try:
                response = model.generate_content(prompt)
                return response.text
            except:
                return "AI analizi şu an kullanılamıyor. Lütfen birkaç dakika sonra tekrar deneyin."
        return f"AI analizi hatası: {str(e)}"