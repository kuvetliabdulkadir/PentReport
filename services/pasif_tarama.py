import requests
import ssl
import socket
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
        # IP ise SSL kontrolü yapma
        import ipaddress
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
    sonuclar = {}
    try:
        for kayit in ["A", "MX", "TXT"]:
            try:
                cevap = dns.resolver.resolve(hedef, kayit)
                sonuclar[kayit] = [str(r) for r in cevap]
            except:
                sonuclar[kayit] = "Bulunamadı"
    except:
        pass
    return sonuclar