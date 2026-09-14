import React, { useState, useRef } from 'react';
import { Shield, AlertTriangle, Server, Lock, Download, MessageSquare, Clock, Zap } from 'lucide-react';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

export default function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const reportRef = useRef(null);

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`/scan?url=${encodeURIComponent(url)}`);
      if (!res.ok) throw new Error();
      const data = await res.json();
      setReport(data);
    } catch (err) {
      alert("No se pudo completar el análisis del sitio web.");
    } finally {
      setLoading(false);
    }
  };

  const downloadPDF = async () => {
    if (!reportRef.current) return;
    const canvas = await html2canvas(reportRef.current, { scale: 2, backgroundColor: '#020617' });
    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF('p', 'mm', 'a4');
    const imgWidth = 210;
    const pageHeight = 295;
    const imgHeight = (canvas.height * imgWidth) / canvas.width;
    let heightLeft = imgHeight;
    let position = 0;

    pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
    heightLeft -= pageHeight;

    while (heightLeft >= 0) {
      position = heightLeft - imgHeight;
      pdf.addPage();
      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;
    }

    pdf.save(`Auditoria_Seguridad_${report.url.replace(/https?:\/\//, '')}.pdf`);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 md:p-8 font-sans">
      <div className="max-w-5xl mx-auto space-y-6">
        
        {/* HEADER */}
        <header className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-600/20 border border-indigo-500/30 rounded-xl">
              <Shield className="w-7 h-7 text-indigo-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">WebGuard MX</h1>
              <p className="text-xs text-slate-400">Auditoría Técnica de Ciberseguridad & Diagnóstico Web</p>
            </div>
          </div>
        </header>

        {/* ESPACIO PARA ADSENSE: BANNER SUPERIOR */}
        <div className="w-full bg-slate-900/50 border border-slate-800/80 rounded-xl p-3 text-center text-xs text-slate-500 font-mono">
          [ Espacio Publicitario / Google AdSense ]
        </div>

        {/* FORMULARIO DE BUSQUEDA */}
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-3">
          <label className="text-sm font-medium text-slate-300">Sitio Web a Analizar</label>
          <form onSubmit={handleScan} className="flex gap-3">
            <input
              type="text"
              placeholder="https://ejemplo.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
              className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono text-sm"
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-900 text-white font-semibold px-6 py-3 rounded-xl transition-all shrink-0 text-sm"
            >
              {loading ? 'Escaneando...' : 'Iniciar Auditoría'}
            </button>
          </form>
        </div>

        {/* RESULTADOS Y PANEL REPORTE */}
        {report && (
          <div className="space-y-6">
            <div className="flex justify-end">
              <button
                onClick={downloadPDF}
                className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs px-4 py-2.5 rounded-xl flex items-center gap-2 transition-all"
              >
                <Download className="w-4 h-4 text-indigo-400" /> Descargar Reporte PDF
              </button>
            </div>

            {/* CONTENEDOR CAPTURADO PARA PDF */}
            <div ref={reportRef} className="space-y-6 bg-slate-950 p-2 rounded-2xl">
              
              {/* METRICAS Y METADATOS */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                  <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Puntuación</span>
                  <div className="text-3xl font-black font-mono mt-1 text-emerald-400">
                    {report.security_score}%
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                  <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Servidor Detectado</span>
                  <div className="text-xs font-mono mt-2 text-slate-200 truncate">
                    {report.server_info}
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                  <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Estado SSL/TLS</span>
                  <div className="text-xs font-medium mt-2 text-emerald-400">
                    {report.ssl_status}
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                  <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Latencia</span>
                  <div className="text-xs font-mono mt-2 text-indigo-400 flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" /> {report.response_time_ms} ms
                  </div>
                </div>
              </div>

              {/* LISTA DE VULNERABILIDADES */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Zap className="w-4 h-4 text-amber-400" /> Vectores de Seguridad Evaluados ({report.vulnerabilities.length})
                </h3>

                <div className="space-y-3">
                  {report.vulnerabilities.map((vuln, idx) => (
                    <div key={idx} className="p-4 bg-slate-950 border border-slate-800/80 rounded-xl space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm text-slate-200">{vuln.header}</span>
                        <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                          vuln.status === 'critical' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        }`}>
                          {vuln.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{vuln.message}</p>
                      <div className="bg-slate-900 px-3 py-2 rounded-lg font-mono text-xs text-indigo-300 border border-slate-800/80">
                        {vuln.fix}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* ESPACIO PARA ADSENSE: BANNER INFERIOR / CONVERSIÓN */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between space-y-4">
                <div>
                  <h4 className="text-sm font-bold text-white">¿Quieres asegurar tu servidor?</h4>
                  <p className="text-xs text-slate-400 mt-1">Implementamos las cabeceras faltantes y la configuración SSL sin interferir con tu sitio activo.</p>
                </div>
                <a
                  href={`https://wa.me/521234567890?text=Hola,%20requiero%20asistencia%20profesional%20para%20las%20vulnerabilidades%20de%20mi%20sitio%20${encodeURIComponent(report.url)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs px-4 py-2.5 rounded-xl flex items-center justify-center gap-2 transition-all w-fit"
                >
                  <MessageSquare className="w-4 h-4" /> Solicitar Corrección vía WhatsApp
                </a>
              </div>

              <div className="bg-slate-900/50 border border-slate-800/80 rounded-2xl p-4 flex items-center justify-center text-center text-xs text-slate-500 font-mono">
                [ Anuncio AdSense 300x250 ]
              </div>
            </div>

          </div>
        )}

        {/* PIE DE PÁGINA (REQUISITO ADSENSE) */}
        <footer className="border-t border-slate-800/80 pt-4 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <span>© 2026 WebGuard MX - Auditorías Automatizadas</span>
          <div className="flex gap-4">
            <a href="#" className="hover:text-slate-400">Privacidad</a>
            <a href="#" className="hover:text-slate-400">Términos</a>
          </div>
        </footer>

      </div>
    </div>
  );
}