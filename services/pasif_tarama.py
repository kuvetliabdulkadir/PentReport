import requests
import ssl
import socket
import ipaddress
import dns.resolver


def http_baslik_kontrol(hedef: str) -> dict:
    try:
        url = f"http://{hedef}" if not hedef.startswith("http") else hedef
        res = requests.get(url, timeout=10, allow_redirects=True)
        basliklar = res.headers

        kontroller = {
            "X-Frame-Options": basliklar.get("X-Frame-Options", "❌ Eksik"),
            "X-Content-Type-Options": basliklar.get("X-Content-Type-Options", "❌ Eksik"),
            "Strict-Transport-Security": basliklar.get("Strict-Transport-Security", "❌ Eksik"),
            "Content-Security-Policy": basliklar.get("Content-Security-Policy", "❌ Eksik"),
            "Referrer-Policy": basliklar.get("Referrer-Policy", "❌ Eksik"),
        }
        return kontroller
    except:
        return {}


def ssl_kontrol(hedef: str) -> dict:
    try:
        try:
            ipaddress.ip_address(hedef)
            return {"gecerli": None, "bilgi": "IP adresi için SSL kontrolü yapılamaz, domain girin"}
        except ValueError:
            pass

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hedef) as s:
            s.connect((hedef, 443))
            sert = s.getpeercert()
            return {
                "gecerli": True,
                "bitis_tarihi": sert["notAfter"],
                "konu": dict(x[0] for x in sert["subject"])
            }
    except Exception as e:
        return {"gecerli": False, "hata": str(e)}


def dns_kontrol(hedef: str) -> dict:
    # IP adresi girilmişse DNS sorgusu yapma
    try:
        ipaddress.ip_address(hedef)
        return {
            "Bilgi": "IP adresi tarandı — DNS kayıtları için domain adı giriniz"
        }
    except ValueError:
        pass

    sonuclar = {}
    try:
        cozucu = dns.resolver.Resolver()
        cozucu.nameservers = ['8.8.8.8', '1.1.1.1']
        cozucu.timeout = 5
        cozucu.lifetime = 10
        for kayit in ["A", "MX", "TXT", "NS"]:
            try:
                cevap = cozucu.resolve(hedef, kayit)
                sonuclar[kayit] = [str(r) for r in cevap]
            except dns.resolver.NXDOMAIN:
                sonuclar[kayit] = "Alan adı bulunamadı"
            except dns.resolver.NoAnswer:
                sonuclar[kayit] = "Kayıt yok"
            except dns.resolver.Timeout:
                sonuclar[kayit] = "Sorgu zaman aşımına uğradı"
            except Exception:
                sonuclar[kayit] = "Sorgulanamadı"

        # DNSSEC kontrolü - DS kaydı var mı?
        try:
            cozucu.resolve(hedef, "DS")
            sonuclar["DNSSEC"] = "✅ İmzalı (DS kaydı mevcut)"
        except dns.resolver.NoAnswer:
            sonuclar["DNSSEC"] = "⚠️ İmzasız - DNS önbellek zehirlenmesi riski"
        except dns.resolver.NXDOMAIN:
            sonuclar["DNSSEC"] = "⚠️ İmzasız - DNS önbellek zehirlenmesi riski"
        except Exception:
            sonuclar["DNSSEC"] = "Sorgulanamadı"

    except Exception:
        return {"Hata": "DNS sorgusu başlatılamadı"}
    return sonuclar