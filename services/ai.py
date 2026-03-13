import google.generativeai as genai
from datetime import datetime

MODELLER = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
]

def ai_analiz(tarama_metni: str, ssl_analizi: str = "") -> str:
    if not tarama_metni.strip():
        tarama_metni = "Yapılan Nmap taramasında hiçbir açık port bulunamadı."

    AYLAR = {
        1: 'Ocak', 2: 'Şubat', 3: 'Mart', 4: 'Nisan',
        5: 'Mayıs', 6: 'Haziran', 7: 'Temmuz', 8: 'Ağustos',
        9: 'Eylül', 10: 'Ekim', 11: 'Kasım', 12: 'Aralık'
    }
    now = datetime.now()
    tarih = f"{now.day} {AYLAR[now.month]} {now.year}"

    prompt = f"""Sen kıdemli bir siber güvenlik danışmanısın. Aşağıdaki tarama verilerini analiz ederek YALNIZCA aşağıdaki yapıda bir rapor üret. Yapının dışına KESINLIKLE çıkma.

TARAMA TARİHİ: {tarih}

=== TARAMA VERİLERİ ===
{tarama_metni}

=== SSL/TLS ANALİZİ ===
{ssl_analizi if ssl_analizi else "SSL/TLS verisi mevcut değil."}

=== RAPOR YAPISI ===

Aşağıdaki bölümleri SIRAYLA ve EKSİKSİZ üret:

---BÖLÜM 1: YÖNETİCİ ÖZETİ---
(Teknik bilgisi olmayan bir işletme sahibine hitap et. Maksimum 5 cümle.)
- Kaç port açık, genel güvenlik durumu nedir?
- En kritik 2-3 bulgu nedir? (Teknik terim kullanma, sade Türkçe)
- Bu açıklar kötüye kullanılırsa işletmeye ne olabilir? (veri çalınması, spam gönderimi, itibar kaybı gibi somut sonuçlar)
- Genel risk seviyesi: DÜŞÜK / ORTA / YÜKSEK / KRİTİK

---BÖLÜM 2: ACİL EYLEM LİSTESİ---
(Öncelik sırasına göre, en kritikten başla. Her madde max 2 satır.)
1. [BU HAFTA] ...
2. [BU HAFTA] ...
3. [BU AY] ...
4. [BU AY] ...
5. [3 AYDA BİR] ...

---BÖLÜM 3: TEKNİK PORT ANALİZİ---
(Her açık port için aşağıdaki formatı kullan. Sistem yöneticisine hitap et.)

PORT [numara] - [servis] - [versiyon]
Risk Puanı: [0.0-10.0] | Seviye: [Düşük/Orta/Yüksek/Kritik]
Neden Riskli: [1-2 cümle, kesin yargı değil ihtimal belirt]
Yapılması Gereken: [Madde madde, Windows/IIS/MailEnable'a özel komutlarla]

(Tüm portlar için tekrarla)

---BÖLÜM 4: RİSK ÖZETİ---
Kritik: [sayı] | Yüksek: [sayı] | Orta: [sayı] | Düşük: [sayı]
En Öncelikli Düzeltme: [tek cümle]

=== KURALLAR ===
- Sadece SSL/TLS analizinde gerçekten görülen zafiyetleri (SWEET32, RC4, vb.) belirt. Varsayım yapma.
- CVE verisi yoksa "CVE verisi bu taramada elde edilemedi, manuel doğrulama önerilir" yaz. Uydurma.
- Port 80 açıksa ve 443 de açıksa risk puanı 2.0'ı geçmesin (büyük ihtimalle yönlendirme yapıyordur).
- Risk puanı için CVSS v3 standardını baz al.
- Türkçe yaz. Kurumsal ama anlaşılır dil kullan.
- "Kesin hacklenirsiniz", "acil tehlike" gibi panikletici ifadeler kullanma.
- Her bölümü --- ile ayır, bölüm başlıklarını koru.
"""

    for model_adi in MODELLER:
        try:
            model = genai.GenerativeModel(model_adi)
            response = model.generate_content(prompt)
            print(f"[AI] {model_adi} modeli kullanıldı.")
            return response.text
        except Exception as e:
            hata = str(e).lower()
            if any(k in hata for k in ["resource_exhausted", "429", "quota", "limit"]):
                print(f"[AI] {model_adi} limiti doldu, sonraki modele geçiliyor...")
                continue
            else:
                print(f"[AI] {model_adi} hatası: {e}")
                continue

    raise ValueError("LIMIT_ASILDI")