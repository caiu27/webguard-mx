import os
import time
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx

app = FastAPI(title="WebGuard MX Security Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VulnDetail(BaseModel):
    header: str
    status: str
    message: str
    fix: str

class AuditResponse(BaseModel):
    url: str
    security_score: int
    ssl_status: str
    server_info: str
    response_time_ms: int
    vulnerabilities: list[VulnDetail]

# --- Rutas de API ---
@app.get("/api/health")
def health_check():
    return {"status": "ok"}

@app.get("/scan", response_model=AuditResponse)
async def scan_headers(url: str = Query(...)):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings = []
    score = 100
    server_header = "Oculto / Desconocido"
    ssl_status = "Seguro (SSL Activo)" if url.startswith("https://") else "Inseguro (HTTP sin cifrar)"
    
    if not url.startswith("https://"):
        score -= 30

    start_time = time.time()

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            elapsed_time = int((time.time() - start_time) * 1000)
            headers = {k.lower(): v for k, v in response.headers.items()}

            if "server" in headers:
                server_header = headers["server"]
                score -= 10
                findings.append(VulnDetail(
                    header="Server Banner Exposición",
                    status="warning",
                    message=f"El servidor revela su versión ({server_header}), lo que expone vectores de ataque.",
                    fix="Desactivar ServerTokens en Apache/Nginx"
                ))

            if "x-frame-options" not in headers:
                score -= 20
                findings.append(VulnDetail(
                    header="X-Frame-Options",
                    status="critical",
                    message="Falta protección contra Clickjacking. Su sitio puede ser incrustado en marcos maliciosos.",
                    fix="X-Frame-Options: DENY"
                ))

            if "content-security-policy" not in headers:
                score -= 20
                findings.append(VulnDetail(
                    header="Content-Security-Policy (CSP)",
                    status="critical",
                    message="Sin política CSP. Riesgo alto de inyección de scripts no autorizados (XSS).",
                    fix="Content-Security-Policy: default-src 'self';"
                ))

            if "strict-transport-security" not in headers:
                score -= 15
                findings.append(VulnDetail(
                    header="Strict-Transport-Security (HSTS)",
                    status="warning",
                    message="No se fuerza el tráfico HTTPS en conexiones subsecuentes.",
                    fix="Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ))

            if "referrer-policy" not in headers:
                score -= 10
                findings.append(VulnDetail(
                    header="Referrer-Policy",
                    status="warning",
                    message="No se controla la fuga de información de origen al hacer clic en enlaces externos.",
                    fix="Referrer-Policy: strict-origin-when-cross-origin"
                ))

            set_cookie = response.headers.get("set-cookie", "").lower()
            if set_cookie:
                missing_flags = []
                if "secure" not in set_cookie:
                    missing_flags.append("Secure")
                if "httponly" not in set_cookie:
                    missing_flags.append("HttpOnly")
                if "samesite" not in set_cookie:
                    missing_flags.append("SameSite")

                if missing_flags:
                    score -= 15
                    findings.append(VulnDetail(
                        header="Galletas / Cookies Inseguras",
                        status="critical",
                        message=f"Las cookies emitidas carecen de atributos de seguridad: {', '.join(missing_flags)}.",
                        fix="Set-Cookie: clave=valor; Secure; HttpOnly; SameSite=Strict"
                    ))

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error de conexión con el destino: {str(e)}")

    return AuditResponse(
        url=url,
        security_score=max(0, score),
        ssl_status=ssl_status,
        server_info=server_header,
        response_time_ms=elapsed_time,
        vulnerabilities=findings
    )

# --- Servir Frontend ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BASE_DIR, "frontend", "dist")

if os.path.exists(DIST_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST_DIR, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_react(full_path: str):
        file_path = os.path.join(DIST_DIR, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(DIST_DIR, "index.html"))
else:
    @app.get("/")
    def index():
        return {"error": "Carpeta frontend/dist no encontrada en el servidor."}
