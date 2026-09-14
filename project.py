import os
import requests


class EscanerSeguridadWeb:

  def __init__(self, archivo_urls="urls.txt", archivo_salida="reporte.txt"):
    self.archivo_urls = archivo_urls
    self.archivo_salida = archivo_salida
    self.cabeceras_criticas = {
        "Strict-Transport-Security": (
            "Fuerza el uso de HTTPS (Protege contra ataques de interceptación)"
        ),
        "Content-Security-Policy": (
            "Controla qué recursos se pueden cargar (Previene XSS)"
        ),
        "X-Frame-Options": (
            "Evita que la web sea clonada dentro de un iframe (Clickjacking)"
        ),
        "X-Content-Type-Options": (
            "Evita que el navegador interprete archivos maliciosos"
        ),
    }

  def analizar_sitio(self, url):
    url = url.strip()
    if not url:
      return ""

    reporte_sitio = []
    reporte_sitio.append(f"\n[+] Analizando postura de seguridad para: {url}")
    print(reporte_sitio[-1])

    try:
      # Petición HTTP con un timeout de 5 segundos por seguridad
      response = requests.get(
          url, timeout=5, headers={"User-Agent": "SecurityScannerBot/1.0"}
      )
      headers = response.headers
      hallazgos_positivos = 0

      for cabecera, descripcion in self.cabeceras_criticas.items():
        if cabecera in headers:
          mensaje = f"  [OK] {cabecera} -> Configurada correctamente."
          hallazgos_positivos += 1
        else:
          mensaje = (
              f"  [!] ALERTA: Falta '{cabecera}'\n      ->"
              f" Impacto: {descripcion}"
          )
        print(mensaje)
        reporte_sitio.append(mensaje)

      resumen = (
          f"  -> Resumen: {hallazgos_positivos} de"
          f" {len(self.cabeceras_criticas)} cabeceras implementadas.\n"
      )
      print(resumen)
      reporte_sitio.append(resumen)

    except requests.exceptions.RequestException as e:
      error_msg = f"  [-] Error de conexión con el sitio web: {e}\n"
      print(error_msg)
      reporte_sitio.append(error_msg)

    return "\n".join(reporte_sitio)

  def ejecutar_escaneo_masivo(self):
    if not os.path.exists(self.archivo_urls):
      print(
          f"[-] No se encontró el archivo '{self.archivo_urls}'. Créalo en la"
          " misma carpeta."
      )
      return

    with open(self.archivo_urls, "r", encoding="utf-8") as f:
      urls = f.readlines()

    print(
        f"--- INICIANDO AUDITORÍA EN LOTE ---\nSe evaluarán {len(urls)}"
        f" sitios.\n"
    )

    resultados_totales = []
    for url in urls:
      resultado = self.analizar_sitio(url)
      if resultado:
        resultados_totales.append(resultado)

    # Guardar reporte profesional en un archivo .txt
    with open(self.archivo_salida, "w", encoding="utf-8") as f:
      f.write(
          "=== REPORTE DE AUDITORÍA DE CABECERAS HTTP ===\n"
          + "\n".join(resultados_totales)
      )

    print(
        f"[í] Auditoría finalizada. Reporte guardado exitosamente en:"
        f" '{self.archivo_salida}'"
    )


if __name__ == "__main__":
  # Instanciamos la clase y ejecutamos
  escaner = EscanerSeguridadWeb()
  escaner.ejecutar_escaneo_masivo()