#!/bin/bash
set -euo pipefail

# Directorio y archivo de log
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Procesar argumentos y ayuda
def show_help() {
    echo "Uso: ${0##*/} <objetivo>"
    echo "Realiza escaneos TCP SYN, UDP y detección de versiones con Nmap, redirigiendo todo a un .txt"
    echo "  <objetivo>  IP, rango o dominio a escanear"
    echo "  --help      Muestra esta ayuda"
    exit 0
}

if [[ "$#" -ne 1 || "$1" == "--help" ]]; then
    show_help
fi

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/scan_nmap_${TARGET}_${TIMESTAMP}.txt"

# Redirigir stdout y stderr al log
exec >"$LOG_FILE" 2>&1

# Inicio del escaneo
echo "[*] Iniciando escaneo de ${TARGET} a las $(date)"

echo "[*] Escaneo TCP SYN (top 1000 puertos)"
nmap -sS -T4 --top-ports 1000 -v "$TARGET"

echo "[*] Escaneo UDP (top 100 puertos)"
nmap -sU -T4 --top-ports 100 -v "$TARGET"

echo "[*] Detección de versiones y sistema operativo"
nmap -sV -O -T4 -v "$TARGET"

echo "[+] Escaneo completado a las $(date)"
echo "[+] Log de ejecución guardado en: $LOG_FILE"

exit 0
