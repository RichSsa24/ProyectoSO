#!/usr/bin/env python3

"""
Analizador de tráfico de red con tcpdump y scapy
Autor: [Tu Nombre]
"""

import subprocess
import time
import sys
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP
import os

def listar_interfaces():
    """Lista las interfaces de red disponibles"""
    try:
        interfaces = os.listdir('/sys/class/net/')
        print("\nInterfaces disponibles:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        return interfaces
    except:
        print("No se pudieron listar las interfaces. Usando 'eth0' por defecto.")
        return ['eth0']

def capturar_trafico(interface, duracion, archivo_salida):
    """Captura tráfico de red con tcpdump"""
    print(f"\n[+] Capturando tráfico en {interface} durante {duracion} segundos...")
    try:
        proceso = subprocess.Popen(
            ['tcpdump', '-i', interface, '-w', archivo_salida],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(duracion)
        proceso.terminate()
        print(f"[+] Captura completada. Guardada en {archivo_salida}")
    except Exception as e:
        print(f"Error en la captura: {e}")
        sys.exit(1)

def analizar_captura(archivo_pcap):
    """Analiza el archivo pcap y muestra estadísticas"""
    print("\n[+] Analizando captura...")
    
    try:
        paquetes = rdpcap(archivo_pcap)
    except Exception as e:
        print(f"Error al leer el archivo pcap: {e}")
        return

    if not paquetes:
        print("No se encontraron paquetes en la captura.")
        return

    # Estadísticas
    protocolos = []
    destinos = []
    
    for pkt in paquetes:
        if IP in pkt:
            destinos.append(pkt[IP].dst)
            
            if TCP in pkt:
                protocolos.append("TCP")
            elif UDP in pkt:
                protocolos.append("UDP")
            else:
                protocolos.append("Otro")

    # Mostrar resultados
    print("\n=== RESULTADOS DEL ANÁLISIS ===")
    print(f"Total de paquetes: {len(paquetes)}")
    
    if protocolos:
        contador_protocolos = Counter(protocolos)
        print("\nProtocolos más usados:")
        for proto, count in contador_protocolos.most_common():
            print(f"- {proto}: {count} paquetes ({count/len(paquetes)*100:.1f}%)")
    
    if destinos:
        contador_destinos = Counter(destinos)
        print("\nTop 5 direcciones IP destino:")
        for ip, count in contador_destinos.most_common(5):
            print(f"- {ip}: {count} paquetes")

def main():
    print("\n=== ANALIZADOR DE TRÁFICO DE RED ===")
    
    # Seleccionar interfaz
    interfaces = listar_interfaces()
    try:
        seleccion = int(input("\nSelecciona interfaz (número) o presiona Enter para usar la primera: ") or 1)
        interface = interfaces[seleccion-1]
    except:
        interface = interfaces[0]
    
    # Configurar duración
    try:
        duracion = int(input("Duración de la captura (segundos): "))
    except:
        print("Usando duración por defecto de 10 segundos")
        duracion = 10
    
    # Nombre del archivo de salida
    archivo_pcap = f"captura_{interface}_{int(time.time())}.pcap"
    
    # Capturar y analizar
    capturar_trafico(interface, duracion, archivo_pcap)
    analizar_captura(archivo_pcap)

if __name__ == "__main__":
    # Verificar si se ejecuta como root
    if os.geteuid() != 0:
        print("Error: Este script requiere privilegios de root para capturar tráfico.")
        sys.exit(1)
    
    # Verificar dependencias
    try:
        subprocess.run(['tcpdump', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("Error: tcpdump no está instalado. Por favor instálalo primero.")
        sys.exit(1)
    
    try:
        from scapy.all import rdpcap
    except ImportError:
        print("Error: scapy no está instalado. Instálalo con: pip install scapy")
        sys.exit(1)
    
    main()