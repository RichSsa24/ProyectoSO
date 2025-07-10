#!/bin/bash
set -euo pipefail

# Script: parse_traffic.sh
# Descripción: Analiza archivos pcap y genera reportes en Markdown
# Uso: ./parse_traffic.sh <pcap_file> [--help]

show_help() {
    echo "Uso: ${0##*/} <pcap_file>"
    echo "Analiza un archivo pcap y genera un reporte en Markdown."
    echo "  <pcap_file>   Archivo de captura (.pcap o .pcap.gz)"
    echo "  --help        Muestra esta ayuda"
    exit 0
}

if [[ "$#" -ne 1 ]]; then
    show_help
    exit 1
fi

if [[ "$1" == "--help" ]]; then
    show_help
fi

PCAP_INPUT="$1"
REPORTS_DIR="reports/traffic"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Verificar si el archivo existe
if [ ! -f "$PCAP_INPUT" ]; then
    echo "[!] Error: El archivo $PCAP_INPUT no existe."
    exit 1
fi

# Crear directorio de reportes
mkdir -p "$REPORTS_DIR"

# Obtener nombre base del archivo
BASENAME=$(basename "$PCAP_INPUT" .gz)
BASENAME=$(basename "$BASENAME" .pcap)
REPORT_FILE="${REPORTS_DIR}/${BASENAME}_${TIMESTAMP}_report.md"

# Verificar si tshark está instalado
if ! command -v tshark >/dev/null 2>&1; then
    echo "[!] Error: tshark no está instalado. Instálelo con 'apt install wireshark'"
    exit 1
fi

echo "[*] Analizando $PCAP_INPUT..."

# Crear reporte Markdown
{
    echo "# Análisis de Tráfico: $BASENAME"
    echo "**Fecha:** $(date)"
    echo "**Archivo original:** $PCAP_INPUT"
    echo ""
    
    # Resumen general
    echo "## Resumen General"
    echo '```'
    if [[ "$PCAP_INPUT" == *.gz ]]; then
        zcat "$PCAP_INPUT" | tshark -r - -q -z io,phs 2>/dev/null || true
    else
        tshark -r "$PCAP_INPUT" -q -z io,phs 2>/dev/null || true
    fi
    echo '```'
    echo ""
    
    # Protocolos más utilizados
    echo "## Estadísticas por Protocolo"
    echo '```'
    if [[ "$PCAP_INPUT" == *.gz ]]; then
        zcat "$PCAP_INPUT" | tshark -r - -q -z io,stat,0,"frame.protocols" 2>/dev/null || true
    else
        tshark -r "$PCAP_INPUT" -q -z io,stat,0,"frame.protocols" 2>/dev/null || true
    fi
    echo '```'
    echo ""
    
    # Conversaciones TCP
    echo "## Conversaciones TCP"
    echo '```'
    if [[ "$PCAP_INPUT" == *.gz ]]; then
        zcat "$PCAP_INPUT" | tshark -r - -q -z conv,tcp 2>/dev/null || true
    else
        tshark -r "$PCAP_INPUT" -q -z conv,tcp 2>/dev/null || true
    fi
    echo '```'
    echo ""
    
    # Conversaciones UDP
    echo "## Conversaciones UDP"
    echo '```'
    if [[ "$PCAP_INPUT" == *.gz ]]; then
        zcat "$PCAP_INPUT" | tshark -r - -q -z conv,udp 2>/dev/null || true
    else
        tshark -r "$PCAP_INPUT" -q -z conv,udp 2>/dev/null || true
    fi
    echo '```'
    echo ""
    
    # HTTP Requests
    echo "## Peticiones HTTP"
    echo '```'
    if [[ "$PCAP_INPUT" == *.gz ]]; then
        zcat "$PCAP_INPUT" | tshark -r - -Y "http.request" -T fields \
            -e frame.time -e ip.src -e http.host -e http.request.method -e http.request.uri 2>/dev/null || true
    else
        tshark -r "$PCAP_INPUT" -Y "http.request" -T fields \
            -e frame.time -e ip.src -e http.host -e http.request.method -e http.request.uri 2>/dev/null || true
    fi
    echo '```'
    
} > "$REPORT_FILE"

echo "[+] Análisis completado. Reporte generado en: $REPORT_FILE"

exit 0