from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
import google.generativeai as genai
import os
from routers import rapor, tarama, gecmis

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(rapor.router)
app.include_router(tarama.router)
app.include_router(gecmis.router)

@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")