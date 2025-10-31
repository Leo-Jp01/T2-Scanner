# T2-Scanner (Threat Tool Scanner)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Made with ❤️ by Leo-Jp01](https://img.shields.io/badge/Made%20with%20%E2%9D%A4%EF%B8%8F-by%20Leo--Jp01-red.svg)

## Descripción.

T2-Scanner (Threat Tool Scanner) es una herramienta para analistas de seguridad, pentesters y estudiantes tipo CLI que automatiza el análisis de reputación de **IP**, **URL** y **ARCHIVOS** consultando servicios como VirusTotal y AbuseIPDB generando **reportes legibles** y claros. 


## Demo.
https://github.com/user-attachments/assets/4dc1f809-8282-4aae-8aed-86bcf654ec12
## Arquitectura.

```
ENTRADA:
   IP    →  ┐
   File  →  ├─→[ VALIDADOR ]
   URL   →  ┘
                     ↓
                [ T2-SCANNER ]
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
   [AbuseIPDB]  [VirusTotal] [VirusTotal]
     (IPs)        (Files)       (URLs)
        │            │            │
        └────────────┼────────────┘
                     ↓
            [ RESULTADOS PARSEADOS ]
                     ↓
                  Reporte

```

## Características.

- Soporte para múltiples inputs.
- Threat Intelligence.
- integración dual VirusTotal y AbuseIPDB.
- Funcional para Windows y Linux.


## Conocimientos previos.

- ¿Qué es malware?
- Threat Intelligence básico
- IOCs (Indicators of Compromise)


## Instalación.
1) Clone el repositorio:
```
git clone https://github.com/Leo-Jp01/T2-Scanner.git ~/Documentos/t2scanner 
cd t2scanner
```
2) Inicie un entorno virtual (evitará problemas de instalación de dependencias):
```
python -m venv venv
source venv/bin/activate
```
3) Instalar dependencias:
```
pip install -r requirements.txt
```
4) Cambie el nombre del archivo que contiene las API KEYS:
```
mv .env.your_keys .env
```
5) Dentro de archivo .env coloque sus API KEYS:
```
nano .env
```
Contenido:
```
API_KEY_VT=your_api_key_here #VirusTotal 
API_KEY_ABUSE=your_api_key_here # AbuseIPsDB
```
Guarde los cambios y cierre el archivo.


## Uso.
1) Ejemplo de uso para IP:
```
python t2scanner.py -i 47.251.89.66
```
```
--------T2-SCANNER--------

IP:47.251.89.66 - IPv4
Confidence Score:MALICIOUS (100%)
Country:United States of America | ISP: Alibaba Cloud - US
Total reports:2426
Last reported:2025-10-18T03:05:32+00:00
Attack categories:DDoS Attack | FTP Brute-Force | Ping of Death | Fraud VoIP | Web Spam | Email Spam | Blog Spam | Port Scan | Hacking | Spoofing | Brute-Force | Bad Web Bot | Exploited Host | Web App Attack | SSH
White list:No
Tor:No

```
2) Ejemplo de uso para URL:
```
python t2scanner.py -u https://www.tiktok.com
```

```
--------T2-SCANNER--------

MALICIOUS:0
SUSPICIOUS:0
UNDETECTED:27
HARMLESS:71
```
3) Ejemplo de uso para Archivo:
```
python t2scanner.py -f archivo_prueba.txt
```
(El archivo debe contener algo por dentro, de lo contrario no lo analizara.)
```
MALICIOUS:0
SUSPICIOUS:0
UNDETECTED:62
HARMLESS:0
TIMEOUT:0
CONFIRMED_TIMEOUT:0
FAILURE:0
UNSUPPORTED:14
```
## Estructura.
```
T2-SCANNER/
├── media/
│   └── t2scanner.mp4
│
├── my_validators/
│   ├── __init__.py
│   ├── file_validator.py
│   ├── ip_validator.py
│   └── url_validator.py
│
├── scanners/
│   ├── __init__.py
│   ├── abuse_ipdb_scanner.py
│   └── vt_scanner.py
│
├── .env.your_keys
├── .gitattributes
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── t2scanner.py

```
## Roadmap.
- [ ] Sistema de cache.
- [ ] Sistema de scoring multiple y unificado.
- [ ] Exportación de resultados.
- [ ] Asincronía para mejor tiempo de respuesta.

## Referencias Técnicas.
Este proyecto se desarrolló tomando como base a la documentación oficial y recursos de las siguientes plataformas:
- [Documentación Oficial Requests - Manejo de excepciones](https://docs.python-requests.org/en/latest/api/)
- [Documentación Oficial AbuseIPDB - Acceso a la API](https://docs.abuseipdb.com/#configuring-fail2ban)
- [Documentación Oficial AbuseIPDB - Categoría de ataques](https://www.abuseipdb.com/categories)
- [Documentación Oficial VirusTotal - Guia inicio libreria VT](https://virustotal.github.io/vt-py/quickstart.html)
- [Documentación Oficial VirusTotal - Manejo de excepciones](https://virustotal.github.io/vt-py/api/client.html#vt.APIError)

La estructura del manejo de errores, autenticación y validaciones se diseñó siguiendo las guías y ejemplos oficiales.

## Disclaimer.
Este proyecto fue desarrollado de forma autónoma. En puntos específicos del proceso (optimización, documentación o depuración) se utilizó asistencia de IA como apoyo técnico. Toda la lógica, estructura y diseño de código fueron realizados por mí y siguiendo las referencias técnicas.

---
#### Made with ❤️ by [Leo-Jp01](https://github.com/Leo-Jp01) 
Estudiante de Ingeniería en Sistemas | Enfocado en Ciberseguridad Defensiva y Threat Intelligence
