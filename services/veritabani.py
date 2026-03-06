from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# SQLite veritabanı
engine = create_engine("sqlite:///raporlar.db")
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)


class Rapor(Base):
    __tablename__ = "raporlar"

    id = Column(Integer, primary_key=True)
    hedef = Column(String)
    pdf_yolu = Column(String)
    tarih = Column(DateTime, default=datetime.now)


# Tabloyu oluştur
Base.metadata.create_all(engine)


def rapor_kaydet(hedef: str, pdf_yolu: str):
    db = SessionLocal()
    yeni = Rapor(hedef=hedef, pdf_yolu=pdf_yolu)
    db.add(yeni)
    db.commit()
    db.close()


def raporlari_getir():
    db = SessionLocal()
    raporlar = db.query(Rapor).order_by(Rapor.tarih.desc()).all()
    db.close()
    return raporlar