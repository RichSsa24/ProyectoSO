#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sniff_and_fingerprint.py - Herramienta integrada de captura de tráfico y fingerprinting
Autor: [Tu Nombre]
Fecha: $(date +%Y-%m-%d)

Uso:
    python3 sniff_and_fingerprint.py --iface eth0 --target 10.0.0.5 --duration 60
"""

import argparse
import json
import logging
import os
import pyshark
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sniff_and_fingerprint.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    """Clase para captura y análisis de tráfico en tiempo real"""
    
    def __init__(self, interface: str, output_pcap: str, output_creds: str):
        self.interface = interface
        self.output_pcap = output_pcap
        self.output_creds = output_creds
        self.credentials_found = []
        self.handshakes_found = 0
        self.sensitive_headers = []
        
        # Filtros Wireshark optimizados
        self.capture_filters = (
            'tcp.port == 80 or tcp.port == 8080 or '  # HTTP
            'tcp.port == 21 or '                      # FTP
            'tcp.port == 23 or '                      # Telnet
            'tcp.port == 143 or '                     # IMAP
            'tcp.port == 110 or '                     # POP3
            'tcp.port == 25 or '                      # SMTP
            'eapol or '                               # WPA Handshake
            'http.authorization or '                   # Auth headers
            'http.cookie or '                         # Cookies
            'http.request.uri contains "token" or '    # Tokens en URLs
            'http.request.uri contains "session"'
        )
        
    def _packet_handler(self, pkt):
        """Callback para procesamiento de cada paquete"""
        try:
            # Detección de credenciales HTTP Basic Auth
            if 'HTTP' in pkt and hasattr(pkt.http, 'authorization'):
                auth = pkt.http.authorization
                if 'Basic' in auth:
                    from base64 import b64decode
                    creds = b64decode(auth.split('Basic ')[1]).decode('utf-8')
                    logger.warning(f"Credenciales HTTP Basic encontradas: {creds}")
                    self.credentials_found.append({
                        'type': 'http_basic',
                        'credentials': creds,
                        'source': f"{pkt.ip.src}:{pkt.tcp.srcport}",
                        'destination': f"{pkt.ip.dst}:{pkt.tcp.dstport}",
                        'timestamp': pkt.sniff_time.isoformat()
                    })
            
            # Detección de handshakes WPA
            elif 'EAPOL' in pkt:
                self.handshakes_found += 1
                logger.info(f"Handshake WPA/WPA2 detectado (total: {self.handshakes_found})")
                
            # Detección de cabeceras sensibles
            elif 'HTTP' in pkt:
                sensitive_headers = [
                    'authorization', 'cookie', 'set-cookie',
                    'x-api-key', 'x-access-token', 'bearer'
                ]
                for header in sensitive_headers:
                    if hasattr(pkt.http, header):
                        value = getattr(pkt.http, header)
                        self.sensitive_headers.append({
                            'header': header,
                            'value': value[:100] + '...' if len(value) > 100 else value,
                            'source': f"{pkt.ip.src}:{pkt.tcp.srcport}",
                            'destination': f"{pkt.ip.dst}:{pkt.tcp.dstport}",
                            'timestamp': pkt.sniff_time.isoformat()
                        })
                        logger.warning(f"Header sensible detectado: {header}")
                        
        except Exception as e:
            logger.debug(f"Error procesando paquete: {e}")
    
    def run_capture(self, duration: int):
        """Ejecuta la captura de tráfico durante el tiempo especificado"""
        logger.info(f"Iniciando captura en {self.interface} por {duration} segundos...")
        
        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                output_file=self.output_pcap,
                display_filter=self.capture_filters
            )
            
            # Captura asíncrona con timeout
            capture.apply_on_packets(self._packet_handler, timeout=duration)
            
            # Guardar credenciales encontradas
            if self.credentials_found or self.sensitive_headers or self.handshakes_found:
                with open(self.output_creds, 'w') as f:
                    json.dump({
                        'credentials': self.credentials_found,
                        'sensitive_headers': self.sensitive_headers,
                        'wpa_handshakes': self.handshakes_found,
                        'pcap_file': self.output_pcap,
                        'timestamp': datetime.now().isoformat()
                    }, f, indent=2)
                
                logger.info(f"Resultados guardados en {self.output_creds}")
            
            logger.info(f"Captura completada. Paquetes guardados en {self.output_pcap}")
            return True
            
        except Exception as e:
            logger.error(f"Error en captura: {e}")
            return False


class NmapScanner:
    """Clase para ejecución y parseo de resultados de Nmap OS Detection"""
    
    def __init__(self, target: str):
        self.target = target
        self.results = None
    
    def run_os_scan(self):
        """Ejecuta escaneo de detección de SO con Nmap"""
        try:
            logger.info(f"Iniciando escaneo OS detection contra {self.target}")
            
            # Comando Nmap optimizado para fingerprinting
            cmd = [
                'nmap', '-O', '--osscan-limit',
                '--max-retries', '1',
                '--host-timeout', '2m',
                '-oX', '-',
                self.target
            ]
            
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self._parse_xml_output(result.stdout)
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error en Nmap: {e.stderr}")
            return False
    
    def _parse_xml_output(self, xml_data: str):
        """Parsea la salida XML de Nmap para extraer información del SO"""
        from xml.etree import ElementTree as ET
        
        try:
            root = ET.fromstring(xml_data)
            host = root.find('host')
            
            if host is not None:
                os_info = host.find('os')
                if os_info is not None:
                    os_match = os_info.find('osmatch')
                    if os_match is not None:
                        self.results = {
                            'target': self.target,
                            'os_guess': os_match.get('name'),
                            'accuracy': os_match.get('accuracy'),
                            'timestamp': datetime.now().isoformat()
                        }
            
            if not self.results:
                logger.warning("No se pudo determinar el sistema operativo")
                self.results = {
                    'target': self.target,
                    'os_guess': 'unknown',
                    'accuracy': '0',
                    'timestamp': datetime.now().isoformat()
                }
                
        except ET.ParseError as e:
            logger.error(f"Error parseando XML de Nmap: {e}")
            raise
    
    def save_results(self, output_file: str):
        """Guarda los resultados en formato JSON"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Resultados de fingerprinting guardados en {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error guardando resultados: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Herramienta integrada de captura de tráfico y fingerprinting de sistemas"
    )
    parser.add_argument('--iface', required=True, help="Interfaz de red para captura")
    parser.add_argument('--target', required=True, help="Objetivo para escaneo Nmap")
    parser.add_argument('--duration', type=int, default=60, 
                       help="Duración de captura en segundos (default: 60)")
    
    args = parser.parse_args()
    
    # Configurar directorios de salida
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    Path('captures').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)
    
    # Nombres de archivos de salida
    pcap_file = f"captures/sniff_{args.iface}_{timestamp}.pcap"
    creds_file = f"reports/credentials_{args.iface}_{timestamp}.json"
    fingerprint_file = f"reports/fingerprint_{args.target}_{timestamp}.json"
    
    try:
        # Ejecutar fingerprinting en paralelo con la captura
        nmap = NmapScanner(args.target)
        
        # Iniciar captura
        analyzer = TrafficAnalyzer(args.iface, pcap_file, creds_file)
        
        # Ejecutar ambas tareas
        nmap_thread = threading.Thread(target=nmap.run_os_scan)
        nmap_thread.start()
        
        analyzer.run_capture(args.duration)
        nmap_thread.join()
        
        # Guardar resultados del fingerprinting
        if nmap.results:
            nmap.save_results(fingerprint_file)
        
        logger.info("Proceso completado exitosamente")
        
    except KeyboardInterrupt:
        logger.info("Captura detenida por el usuario")
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        sys.exit(1)


if __name__ == '__main__':
    import threading
    main()