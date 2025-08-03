#!/bin/bash

# Script de escaneo de seguridad con Nmap
# Autor: [Tu Nombre]
# Fecha: $(date)

# Función para validar IP/Dominio
validar_target() {
    local target=$1
    # Expresión regular para validar IP o dominio
    if [[ $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ $target =~ ^([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Verificar si nmap está instalado
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap no está instalado. Por favor instálalo primero."
    exit 1
fi

# Solicitar objetivo
read -p "Introduce la IP o dominio objetivo: " target

# Validar objetivo
if ! validar_target "$target"; then
    echo "Error: El objetivo no es una IP o dominio válido."
    exit 1
fi

# Crear nombre de archivo con marca de tiempo
timestamp=$(date +"%Y%m%d_%H%M%S")
output_file="scan_results_${timestamp}.txt"

echo "Iniciando escaneo de $target..."
echo "Los resultados se guardarán en $output_file"
echo "==========================================" > "$output_file"
echo "Escaneo de seguridad - $timestamp" >> "$output_file"
echo "Objetivo: $target" >> "$output_file"
echo "==========================================" >> "$output_file"

# 1. Escaneo completo de puertos abiertos
echo -e "\n[+] Realizando escaneo de puertos abiertos..."
echo -e "\n=== PUERTOS ABIERTOS ===" >> "$output_file"
nmap -p- --open -T4 "$target" | tee -a "$output_file"

# 2. Detección de sistema operativo
echo -e "\n[+] Detectando sistema operativo..."
echo -e "\n=== SISTEMA OPERATIVO ===" >> "$output_file"
nmap -O "$target" | tee -a "$output_file"

# 3. Detección de vulnerabilidades con scripts NSE
echo -e "\n[+] Escaneando vulnerabilidades comunes..."
echo -e "\n=== VULNERABILIDADES ===" >> "$output_file"
nmap --script vuln "$target" | tee -a "$output_file"

echo -e "\nEscaneo completado. Resultados guardados en $output_file"