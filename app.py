import time
from pathlib import Path
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
    status: str  # "critical", "warning", "pass"
    message: str
    fix: str

class AuditResponse(BaseModel):
    url: str
    security_score: int
    ssl_status: str
    server_info: str
    response_time_ms: int
    vulnerabilities: list[VulnDetail]

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

            # 1. Server Leak Detection
            if "server" in headers:
                server_header = headers["server"]
                score -= 10
                findings.append(VulnDetail(
                    header="Server Banner Exposición",
                    status="warning",
                    message=f"El servidor revela su versión ({server_header}), lo que expone vectores de ataque.",
                    fix="Desactivar ServerTokens en Apache/Nginx"
                ))

            # 2. X-Frame-Options (Clickjacking)
            if "x-frame-options" not in headers:
                score -= 20
                findings.append(VulnDetail(
                    header="X-Frame-Options",
                    status="critical",
                    message="Falta protección contra Clickjacking. Su sitio puede ser incrustado en marcos maliciosos.",
                    fix="X-Frame-Options: DENY"
                ))

            # 3. Content-Security-Policy (XSS)
            if "content-security-policy" not in headers:
                score -= 20
                findings.append(VulnDetail(
                    header="Content-Security-Policy (CSP)",
                    status="critical",
                    message="Sin política CSP. Riesgo alto de inyección de scripts no autorizados (XSS).",
                    fix="Content-Security-Policy: default-src 'self';"
                ))

            # 4. Strict-Transport-Security (HSTS)
            if "strict-transport-security" not in headers:
                score -= 15
                findings.append(VulnDetail(
                    header="Strict-Transport-Security (HSTS)",
                    status="warning",
                    message="No se fuerza el tráfico HTTPS en conexiones subsecuentes.",
                    fix="Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ))

            # 5. Referrer-Policy
            if "referrer-policy" not in headers:
                score -= 10
                findings.append(VulnDetail(
                    header="Referrer-Policy",
                    status="warning",
                    message="No se controla la fuga de información de origen al hacer clic en enlaces externos.",
                    fix="Referrer-Policy: strict-origin-when-cross-origin"
                ))

            # 6. Cookies inseguras (Set-Cookie)
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
                        message=f"Las cookies emitidas carecen de los atributos de seguridad: {', '.join(missing_flags)}.",
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

# Estáticos de React
BASE_DIR = Path(__file__).resolve().parent
frontend_dist = BASE_DIR / "frontend" / "dist"

if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}")
    def serve_react_app(full_path: str):
        if full_path.startswith("api/") or full_path == "scan":
            raise HTTPException(status_code=404, detail="Not Found")
        file_path = frontend_dist / full_path
        if file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(frontend_dist / "index.html"))