#!/bin/bash
set -euo pipefail

# Script: capture_logs.sh
# Descripción: Captura tráfico de red usando tcpdump
# Uso: ./capture_logs.sh <interfaz> <duración_en_segundos> [--help]

show_help() {
    echo "Uso: ${0##*/} <interfaz> <duración_en_segundos>"
    echo "Captura tráfico de red en la interfaz especificada."
    echo "  <interfaz>            Interfaz de red (ej: eth0, wlan0)"
    echo "  <duración_en_segundos> Tiempo de captura en segundos"
    echo "  --help                Muestra esta ayuda"
    exit 0
}

# Validar argumentos
if [[ "$#" -ne 2 ]]; then
    show_help
    exit 1
fi

if [[ "$1" == "--help" ]]; then
    show_help
fi

INTERFACE="$1"
DURATION="$2"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_DIR="captures"
PCAP_FILE="${CAPTURE_DIR}/${INTERFACE}_${TIMESTAMP}.pcap"

# Verificar si la interfaz existe
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "[!] Error: La interfaz $INTERFACE no existe."
    ip link show | grep -E '^[0-9]+:' | cut -d ' ' -f 2 | tr -d ':'
    exit 1
fi

# Verificar permisos
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Se necesitan privilegios de root para capturar tráfico."
    exit 1
fi

# Crear directorio de capturas
mkdir -p "$CAPTURE_DIR"

echo "[*] Iniciando captura en $INTERFACE por $DURATION segundos..."

# Capturar tráfico con tcpdump
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
    -n -s 0 -v \
    'not arp and not stp and not port 5353' &>/dev/null &

# Obtener PID del proceso
TCPDUMP_PID=$!

# Configurar temporizador
sleep "$DURATION"

# Detener captura
kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID"

# Comprimir captura
echo "[*] Comprimiendo captura..."
gzip -f "$PCAP_FILE"
COMPRESSED_FILE="${PCAP_FILE}.gz"

echo "[+] Captura completada. Archivo guardado en: $COMPRESSED_FILE"

exit 0