from fastapi import APIRouter
from fastapi.responses import FileResponse
from services.veritabani import raporlari_getir
import os

router = APIRouter()


@router.get("/gecmis")
async def gecmis_getir():
    raporlar = raporlari_getir()
    return [
        {
            "id": r.id,
            "hedef": r.hedef,
            "tarih": r.tarih.strftime("%d.%m.%Y %H:%M"),
            "pdf_yolu": r.pdf_yolu
        }
        for r in raporlar
    ]


@router.get("/gecmis/{rapor_id}/indir")
async def rapor_indir(rapor_id: int):
    raporlar = raporlari_getir()
    rapor = next((r for r in raporlar if r.id == rapor_id), None)

    if not rapor:
        return {"hata": "Rapor bulunamadı"}

    if not os.path.exists(rapor.pdf_yolu):
        return {"hata": "PDF dosyası bulunamadı"}

    return FileResponse(rapor.pdf_yolu,
                        media_type="application/pdf",
                        filename=f"rapor_{rapor_id}.pdf")