#!/bin/bash
set -euo pipefail

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

# Directorio base
BASE_DIR=$(dirname "$0")

# Ejecutar escaneo Nmap en segundo plano
echo "[*] Iniciando escaneo Nmap..."
"$BASE_DIR/scan_nmap.sh" "$TARGET" &

# Ejecutar captura de tráfico
echo "[*] Iniciando captura de tráfico en $INTERFACE por $DURATION segundos..."
"$BASE_DIR/capture_logs.sh" "$INTERFACE" "$DURATION"

# Esperar a que finalice el escaneo Nmap si aún está en curso
wait

# Procesar la última captura PCAP
LAST_PCAP=$(ls -t captures/*.pcap.gz | head -1)
if [ -n "$LAST_PCAP" ]; then
    echo "[*] Analizando captura de tráfico..."
    "$BASE_DIR/parse_traffic.sh" "$LAST_PCAP"
else
    echo "[!] No se encontraron archivos de captura para analizar."
fi

echo "[+] Escaneo completo finalizado."

exit 0