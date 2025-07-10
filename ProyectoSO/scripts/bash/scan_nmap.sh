#!/bin/bash
set -euo pipefail

# Script: scan_nmap.sh
# Descripción: Realiza escaneos TCP SYN, UDP y detección de versiones con Nmap
# Uso: ./scan_nmap.sh <objetivo> [--help]

# Función para mostrar ayuda
show_help() {
    echo "Uso: ${0##*/} <objetivo>"
    echo "Realiza escaneos TCP SYN, UDP y detección de versiones con Nmap."
    echo "  <objetivo>  IP, rango o dominio a escanear"
    echo "  --help      Muestra esta ayuda"
    exit 0
}

# Procesar argumentos
if [[ "$#" -ne 1 ]]; then
    show_help
    exit 1
fi

if [[ "$1" == "--help" ]]; then
    show_help
fi

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="reports/nmap"
XML_OUTPUT="${OUTPUT_DIR}/${TARGET}_${TIMESTAMP}.xml"
SUMMARY_OUTPUT="${OUTPUT_DIR}/${TARGET}_summary.txt"

# Crear directorios si no existen
mkdir -p "$OUTPUT_DIR"

echo "[*] Iniciando escaneo de ${TARGET} a las $(date)"

# Escaneo TCP SYN (Puertos más comunes)
echo "[*] Ejecutando escaneo TCP SYN..."
nmap -sS -T4 --top-ports 1000 -v "$TARGET" -oX "${XML_OUTPUT}.syn" >/dev/null

# Escaneo UDP (Puertos más comunes)
echo "[*] Ejecutando escaneo UDP..."
nmap -sU -T4 --top-ports 100 -v "$TARGET" -oX "${XML_OUTPUT}.udp" >>/dev/null 2>&1

# Detección de versiones y sistema operativo
echo "[*] Ejecutando detección de versiones..."
nmap -sV -O -T4 -v "$TARGET" -oX "${XML_OUTPUT}.versions" >/dev/null

# Combinar resultados XML
echo "[*] Combinando resultados..."
xsltproc "${XML_OUTPUT}.syn" "${XML_OUTPUT}.udp" "${XML_OUTPUT}.versions" > "$XML_OUTPUT" 2>/dev/null || {
    echo "[!] Error al combinar resultados XML. Usando solo escaneo SYN como fallback."
    cp "${XML_OUTPUT}.syn" "$XML_OUTPUT"
}

# Limpiar archivos temporales
rm -f "${XML_OUTPUT}.syn" "${XML_OUTPUT}.udp" "${XML_OUTPUT}.versions"

# Generar resumen de puertos abiertos
echo "[*] Generando resumen..."
echo "Resumen de escaneo para ${TARGET} - $(date)" > "$SUMMARY_OUTPUT"
echo "======================================" >> "$SUMMARY_OUTPUT"

# Extraer puertos TCP abiertos
echo -e "\nPuertos TCP abiertos:" >> "$SUMMARY_OUTPUT"
xmlstarlet sel -t -m "//port[state/@state='open' and @protocol='tcp']" \
    -v "concat(@portid, '/', @protocol, ' - ', service/@name, ' (', service/@product, ' ', service/@version, ')')" \
    -n "$XML_OUTPUT" 2>/dev/null | sort -n >> "$SUMMARY_OUTPUT"

# Extraer puertos UDP abiertos
echo -e "\nPuertos UDP abiertos:" >> "$SUMMARY_OUTPUT"
xmlstarlet sel -t -m "//port[state/@state='open' and @protocol='udp']" \
    -v "concat(@portid, '/', @protocol, ' - ', service/@name, ' (', service/@product, ' ', service/@version, ')')" \
    -n "$XML_OUTPUT" 2>/dev/null | sort -n >> "$SUMMARY_OUTPUT"

# Información del sistema operativo
echo -e "\nInformación del sistema operativo:" >> "$SUMMARY_OUTPUT"
xmlstarlet sel -t -v "//osmatch/@name" -n "$XML_OUTPUT" 2>/dev/null | head -1 >> "$SUMMARY_OUTPUT"

echo "[+] Escaneo completado. Resultados guardados en:"
echo "  - XML: $XML_OUTPUT"
echo "  - Resumen: $SUMMARY_OUTPUT"

exit 0