#!/bin/bash
set -euo pipefail



# Directorio y archivo de log
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/capture_${TIMESTAMP}.txt"
# Redirigir todo stdout y stderr al archivo de log
exec >"$LOG_FILE" 2>&1

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
echo "[*] Creando directorio de capturas: $CAPTURE_DIR"
mkdir -p "$CAPTURE_DIR"

echo "[*] Iniciando captura en $INTERFACE por $DURATION segundos..."

# Capturar tráfico con tcpdump
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
    -n -s 0 -v \
    'not arp and not stp and not port 5353' &

# Obtener PID del proceso
tcpdump_pid=$!

# Esperar duración especificada
sleep "$DURATION"

# Detener captura
echo "[*] Deteniendo tcpdump (PID $tcpdump_pid)..."
kill -INT "$tcpdump_pid"
wait "$tcpdump_pid"

echo "[*] Captura guardada en: $PCAP_FILE"

echo "[*] Comprimiendo captura..."
gzip -f "$PCAP_FILE"
COMPRESSED_FILE="${PCAP_FILE}.gz"

echo "[+] Captura completada. Archivo comprimido en: $COMPRESSED_FILE"

echo "[+] Log de ejecución: $LOG_FILE"

exit 0
