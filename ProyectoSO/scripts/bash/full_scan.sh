#!/bin/bash
set -euo pipefail

# Directorio y archivo de log
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/full_scan_${TIMESTAMP}.txt"
# Redirigir todo stdout y stderr al archivo de log
exec >"$LOG_FILE" 2>&1

# Script: full_scan.sh
# Descripción: Ejecuta escaneo Nmap y captura de tráfico en paralelo
# Uso: ./full_scan.sh <objetivo> <interfaz> <duración> [--help]

show_help() {
    echo "Uso: ${0##*/} <objetivo> <interfaz> <duración>"
    echo "Ejecuta escaneo Nmap y captura de tráfico simultáneamente."
    echo "  <objetivo>    IP, rango o dominio a escanear"
    echo "  <interfaz>    Interfaz de red para capturar tráfico"
    echo "  <duración>    Duración de la captura en segundos"
    echo "  --help        Muestra esta ayuda"
    exit 0
}

# Validación de argumentos
if [[ "$#" -ne 3 ]]; then
    show_help
    exit 1
fi

if [[ "$1" == "--help" ]]; then
    show_help
fi

TARGET="$1"
INTERFACE="$2"
DURATION="$3"

# Directorio base (ruta absoluta del script)
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Iniciando full_scan.sh en $(date)"
echo "[*] Objetivo: $TARGET"
echo "[*] Interfaz: $INTERFACE"
echo "[*] Duración: $DURATION segundos"

# Ejecutar escaneo Nmap en segundo plano
echo "[*] Iniciando escaneo Nmap sobre $TARGET..."
"$BASE_DIR/scan_nmap.sh" "$TARGET" &
NMAP_PID=$!

# Ejecutar captura de tráfico
echo "[*] Iniciando captura de tráfico en $INTERFACE por $DURATION segundos..."
"$BASE_DIR/capture_logs.sh" "$INTERFACE" "$DURATION"

# Esperar finalización de escaneo Nmap
echo "[*] Esperando finalización de escaneo Nmap (PID $NMAP_PID)..."
wait "$NMAP_PID"
echo "[*] Escaneo Nmap completado."

# Procesar la última captura PCAP
LAST_PCAP=$(ls -t captures/*.pcap.gz 2>/dev/null | head -1 || true)
if [[ -n "$LAST_PCAP" ]]; then
    echo "[*] Analizando captura de tráfico: $LAST_PCAP"
    "${BASE_DIR}/parse_traffic.sh" "$LAST_PCAP"
else
    echo "[!] No se encontraron archivos de captura para analizar."
fi

echo "[+] Escaneo completo finalizado."
echo "[+] Log de ejecución guardado en: $LOG_FILE"

exit 0

