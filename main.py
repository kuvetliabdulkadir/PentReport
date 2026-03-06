from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import google.generativeai as genai
import os
from routers import rapor, tarama, gecmis


from routers import rapor, tarama

# Env yükle
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

app = FastAPI()

# Static dosyalar
app.mount("/static", StaticFiles(directory="static"), name="static")

# Router'ları bağla
app.include_router(rapor.router)
app.include_router(tarama.router)

@app.get("/")
def root():
    return {"mesaj": "PentReport AI çalışıyor"}

app.include_router(gecmis.router)