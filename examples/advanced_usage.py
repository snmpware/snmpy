#!/usr/bin/env python3
"""
Esempi avanzati di utilizzo della libreria AdvancedSnmp
"""

import sys
import os
import time
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from snmpy import (
    SnmpClient, SnmpVersion, SnmpOctetString, SnmpInteger,
    SnmpObjectIdentifier, SnmpV3User, SnmpV3AuthProtocol
)

def example_network_discovery():
    """Esempio di discovery automatico di dispositivi SNMP in rete"""
    print("=== Network Discovery SNMP ===")
    
    # Rete da scansionare (modifica secondo le tue esigenze)
    network = "192.168.1.0/24"
    timeout = 1.0  # Timeout veloce per lo scanning
    
    def check_snmp_device(ip):
        """Controlla se un IP risponde a SNMP"""
        try:
            client = SnmpClient(
                host=str(ip),
                community="public",
                version=SnmpVersion.V2C,
                timeout=timeout,
                retries=1
            )
            
            # Prova a ottenere sysDescr
            result = client.get("1.3.6.1.2.1.1.1.0")
            if result:
                # Ottieni anche altri dati di base
                name = client.get("1.3.6.1.2.1.1.5.0")  # sysName
                contact = client.get("1.3.6.1.2.1.1.4.0")  # sysContact
                location = client.get("1.3.6.1.2.1.1.6.0")  # sysLocation
                
                return {
                    'ip': str(ip),
                    'sysDescr': str(result),
                    'sysName': str(name) if name else '',
                    'sysContact': str(contact) if contact else '',
                    'sysLocation': str(location) if location else ''
                }
        except:
            pass
        return None
    
    print(f"Scansione rete {network} per dispositivi SNMP...")
    
    # Genera lista di IP da controllare
    net = ipaddress.IPv4Network(network, strict=False)
    ip_list = list(net.hosts())
    
    # Scansione parallela
    discovered_devices = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(check_snmp_device, ip): ip for ip in ip_list}
        
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                discovered_devices.append(result)
                print(f"  Trovato: {result['ip']} - {result['sysDescr'][:50]}...")
    
    print(f"\nTrovati {len(discovered_devices)} dispositivi SNMP:")
    print("-" * 80)
    print(f"{'IP':<15} {'Nome':<20} {'Descrizione':<45}")
    print("-" * 80)
    
    for device in discovered_devices:
        name = device['sysName'][:19] if device['sysName'] else 'N/A'
        descr = device['sysDescr'][:44] if device['sysDescr'] else 'N/A'
        print(f"{device['ip']:<15} {name:<20} {descr}")
    
    print()

def example_interface_monitoring():
    """Esempio di monitoraggio interfacce di rete"""
    print("=== Monitoraggio Interfacce di Rete ===")
    
    client = SnmpClient(
        host="192.168.1.1",  # Router/Switch IP
        community="public",
        version=SnmpVersion.V2C
    )
    
    # OID per le interfacce (IF-MIB)
    interface_oids = {
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',      # Descrizione interfaccia
        'ifType': '1.3.6.1.2.1.2.2.1.3',       # Tipo interfaccia
        'ifMtu': '1.3.6.1.2.1.2.2.1.4',        # MTU
        'ifSpeed': '1.3.6.1.2.1.2.2.1.5',      # Velocità
        'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7', # Stato amministrativo
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',  # Stato operativo
        'ifInOctets': '1.3.6.1.2.1.2.2.1.10',   # Byte in ingresso
        'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',  # Byte in uscita
    }
    
    def get_interface_count():
        """Ottieni il numero di interfacce"""
        result = client.get("1.3.6.1.2.1.2.1.0")  # ifNumber
        return result.value if result else 0
    
    def format_bytes(bytes_value):
        """Formatta i byte in unità leggibili"""
        if bytes_value >= 1024**3:
            return f"{bytes_value / (1024**3):.2f} GB"
        elif bytes_value >= 1024**2:
            return f"{bytes_value / (1024**2):.2f} MB"
        elif bytes_value >= 1024:
            return f"{bytes_value / 1024:.2f} KB"
        else:
            return f"{bytes_value} B"
    
    def interpret_status(status):
        """Interpreta lo stato dell'interfaccia"""
        statuses = {1: "up", 2: "down", 3: "testing"}
        return statuses.get(status, f"unknown({status})")
    
    print("Raccolta informazioni interfacce...")
    
    # Ottieni numero di interfacce
    if_count = get_interface_count()
    print(f"Numero interfacce: {if_count}")
    
    if if_count == 0:
        print("Nessuna interfaccia trovata o dispositivo non raggiungibile")
        return
    
    # Raccoglie dati di tutte le interfacce
    interfaces = {}
    for if_index in range(1, min(if_count + 1, 25)):  # Limita a 24 interfacce max
        interfaces[if_index] = {}
        
        for param, base_oid in interface_oids.items():
            oid = f"{base_oid}.{if_index}"
            result = client.get(oid)
            if result:
                interfaces[if_index][param] = result.value
    
    # Mostra risultati
    print("\nStato Interfacce:")
    print("-" * 100)
    print(f"{'ID':<3} {'Descrizione':<20} {'Tipo':<8} {'Admin':<6} {'Oper':<6} {'Velocità':<12} {'In':<10} {'Out':<10}")
    print("-" * 100)
    
    for if_index, data in interfaces.items():
        if 'ifDescr' in data:  # Solo se abbiamo almeno la descrizione
            descr = str(data.get('ifDescr', ''))[:19]
            if_type = data.get('ifType', 0)
            admin_status = interpret_status(data.get('ifAdminStatus', 0))
            oper_status = interpret_status(data.get('ifOperStatus', 0))
            
            speed = data.get('ifSpeed', 0)
            if speed > 1000000:
                speed_str = f"{speed // 1000000} Mbps"
            else:
                speed_str = f"{speed} bps"
            
            in_octets = format_bytes(data.get('ifInOctets', 0))
            out_octets = format_bytes(data.get('ifOutOctets', 0))
            
            print(f"{if_index:<3} {descr:<20} {if_type:<8} {admin_status:<6} {oper_status:<6} {speed_str:<12} {in_octets:<10} {out_octets:<10}")
    
    print()

def example_performance_monitoring():
    """Esempio di monitoraggio delle performance del sistema"""
    print("=== Monitoraggio Performance Sistema ===")
    
    client = SnmpClient(
        host="192.168.1.100",
        community="public",
        version=SnmpVersion.V2C
    )
    
    # OID per monitoraggio sistema
    system_oids = {
        'cpu_load_1min': '1.3.6.1.4.1.2021.10.1.3.1',     # Load average 1 min (UCD-SNMP)
        'cpu_load_5min': '1.3.6.1.4.1.2021.10.1.3.2',     # Load average 5 min
        'cpu_load_15min': '1.3.6.1.4.1.2021.10.1.3.3',    # Load average 15 min
        'mem_total': '1.3.6.1.4.1.2021.4.5.0',            # Memoria totale (KB)
        'mem_available': '1.3.6.1.4.1.2021.4.6.0',        # Memoria disponibile (KB)
        'disk_total': '1.3.6.1.4.1.2021.9.1.6.1',         # Spazio disco totale (KB)
        'disk_available': '1.3.6.1.4.1.2021.9.1.7.1',     # Spazio disco disponibile (KB)
        'uptime': '1.3.6.1.2.1.1.3.0',                     # System uptime
    }
    
    def collect_metrics():
        """Raccoglie le metriche del sistema"""
        metrics = {}
        
        for metric, oid in system_oids.items():
            result = client.get(oid)
            if result:
                metrics[metric] = result.value
        
        return metrics
    
    def format_uptime(timeticks):
        """Formatta l'uptime da timeticks"""
        if not timeticks:
            return "N/A"
        
        seconds = timeticks // 100  # Timeticks sono in centesimi di secondo
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        return f"{days}d {hours}h {minutes}m {secs}s"
    
    def format_memory(kb):
        """Formatta la memoria da KB"""
        if not kb:
            return "N/A"
        
        if kb >= 1024**2:
            return f"{kb / (1024**2):.1f} GB"
        elif kb >= 1024:
            return f"{kb / 1024:.1f} MB"
        else:
            return f"{kb} KB"
    
    print("Raccolta metriche sistema...")
    metrics = collect_metrics()
    
    if not metrics:
        print("Impossibile raccogliere metriche (dispositivo non supporta UCD-SNMP?)")
        return
    
    print("\nMetriche Sistema:")
    print("-" * 50)
    
    # Uptime
    if 'uptime' in metrics:
        uptime_str = format_uptime(metrics['uptime'])
        print(f"Uptime: {uptime_str}")
    
    # CPU Load
    print("\nCPU Load Average:")
    for period in ['1min', '5min', '15min']:
        key = f'cpu_load_{period}'
        if key in metrics:
            load = metrics[key]
            if isinstance(load, str):
                print(f"  {period}: {load}")
            else:
                print(f"  {period}: {load:.2f}")
    
    # Memoria
    print("\nMemoria:")
    if 'mem_total' in metrics and 'mem_available' in metrics:
        total = metrics['mem_total']
        available = metrics['mem_available']
        used = total - available
        usage_percent = (used / total) * 100 if total > 0 else 0
        
        print(f"  Totale: {format_memory(total)}")
        print(f"  Usata: {format_memory(used)} ({usage_percent:.1f}%)")
        print(f"  Disponibile: {format_memory(available)}")
    
    # Disco
    print("\nDisco (partizione principale):")
    if 'disk_total' in metrics and 'disk_available' in metrics:
        total = metrics['disk_total']
        available = metrics['disk_available']
        used = total - available
        usage_percent = (used / total) * 100 if total > 0 else 0
        
        print(f"  Totale: {format_memory(total)}")
        print(f"  Usato: {format_memory(used)} ({usage_percent:.1f}%)")
        print(f"  Disponibile: {format_memory(available)}")
    
    print()

def example_snmp_table_walking():
    """Esempio di attraversamento di tabelle SNMP"""
    print("=== Attraversamento Tabelle SNMP ===")
    
    client = SnmpClient(
        host="192.168.1.1",
        community="public",
        version=SnmpVersion.V2C
    )
    
    # Esempio: Tabella ARP (ipNetToMediaTable)
    arp_table_oid = "1.3.6.1.2.1.4.22.1"
    
    print("Raccolta tabella ARP...")
    arp_results = client.walk(arp_table_oid)
    
    if not arp_results:
        print("Tabella ARP vuota o dispositivo non raggiungibile")
        return
    
    # Organizza i risultati per entry
    arp_entries = {}
    
    for oid, value in arp_results.items():
        # Estrai l'indice dalla fine dell'OID
        parts = oid.split('.')
        if len(parts) >= 6:
            # Gli ultimi 5 numeri sono: ifIndex.ipAddr1.ipAddr2.ipAddr3.ipAddr4
            entry_parts = parts[-5:]
            if_index = entry_parts[0]
            ip_addr = '.'.join(entry_parts[1:5])
            column = parts[-6]  # Quale colonna della tabella
            
            entry_key = f"{if_index}.{ip_addr}"
            if entry_key not in arp_entries:
                arp_entries[entry_key] = {'ifIndex': if_index, 'ipAddr': ip_addr}
            
            # Mappa le colonne
            if column == '1':  # ipNetToMediaIfIndex
                arp_entries[entry_key]['ifIndex'] = str(value)
            elif column == '2':  # ipNetToMediaPhysAddress
                if hasattr(value, 'value'):
                    mac_bytes = value.value
                    if isinstance(mac_bytes, bytes):
                        mac = ':'.join(f'{b:02x}' for b in mac_bytes)
                        arp_entries[entry_key]['macAddr'] = mac
            elif column == '3':  # ipNetToMediaNetAddress
                arp_entries[entry_key]['ipAddr'] = str(value)
            elif column == '4':  # ipNetToMediaType
                types = {1: 'other', 2: 'invalid', 3: 'dynamic', 4: 'static'}
                arp_entries[entry_key]['type'] = types.get(int(str(value)), 'unknown')
    
    # Mostra la tabella ARP
    print("\nTabella ARP:")
    print("-" * 60)
    print(f"{'IP Address':<15} {'MAC Address':<18} {'Interface':<9} {'Type':<8}")
    print("-" * 60)
    
    for entry in arp_entries.values():
        ip = entry.get('ipAddr', 'N/A')
        mac = entry.get('macAddr', 'N/A')
        iface = entry.get('ifIndex', 'N/A')
        entry_type = entry.get('type', 'N/A')
        
        print(f"{ip:<15} {mac:<18} {iface:<9} {entry_type:<8}")
    
    print()

def example_concurrent_monitoring():
    """Esempio di monitoraggio concorrente di più dispositivi"""
    print("=== Monitoraggio Concorrente ===")
    
    # Lista di dispositivi da monitorare
    devices = [
        {"host": "192.168.1.1", "name": "Router", "community": "public"},
        {"host": "192.168.1.10", "name": "Switch1", "community": "public"},
        {"host": "192.168.1.11", "name": "Switch2", "community": "public"},
        {"host": "192.168.1.100", "name": "Server1", "community": "public"},
        {"host": "192.168.1.101", "name": "Server2", "community": "public"},
    ]
    
    def monitor_device(device):
        """Monitora un singolo dispositivo"""
        try:
            client = SnmpClient(
                host=device["host"],
                community=device["community"],
                version=SnmpVersion.V2C,
                timeout=2.0
            )
            
            # Raccoglie informazioni di base
            info = {}
            
            # System info
            oids = {
                'sysDescr': '1.3.6.1.2.1.1.1.0',
                'sysUpTime': '1.3.6.1.2.1.1.3.0',
                'sysName': '1.3.6.1.2.1.1.5.0',
            }
            
            for key, oid in oids.items():
                result = client.get(oid)
                if result:
                    info[key] = result.value
            
            # Calcola uptime in formato leggibile
            if 'sysUpTime' in info:
                timeticks = info['sysUpTime']
                seconds = timeticks // 100
                days = seconds // 86400
                hours = (seconds % 86400) // 3600
                minutes = (seconds % 3600) // 60
                info['uptimeFormatted'] = f"{days}d {hours}h {minutes}m"
            
            return {
                'device': device,
                'status': 'online',
                'info': info,
                'timestamp': time.strftime("%H:%M:%S")
            }
            
        except Exception as e:
            return {
                'device': device,
                'status': 'offline',
                'error': str(e),
                'timestamp': time.strftime("%H:%M:%S")
            }
    
    print("Monitoraggio dispositivi in parallelo...")
    
    # Esegui monitoraggio concorrente
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(monitor_device, device) for device in devices]
        
        results = []
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
    
    # Mostra risultati
    print("\nRisultati Monitoraggio:")
    print("-" * 80)
    print(f"{'Nome':<12} {'IP':<15} {'Stato':<8} {'Uptime':<12} {'Sistema'}")
    print("-" * 80)
    
    for result in sorted(results, key=lambda x: x['device']['name']):
        device = result['device']
        name = device['name']
        ip = device['host']
        status = result['status']
        
        if status == 'online':
            info = result['info']
            uptime = info.get('uptimeFormatted', 'N/A')
            sys_descr = str(info.get('sysDescr', 'N/A'))[:25]
            print(f"{name:<12} {ip:<15} {status:<8} {uptime:<12} {sys_descr}")
        else:
            print(f"{name:<12} {ip:<15} {status:<8} {'N/A':<12} Error: {result.get('error', 'Unknown')[:20]}")
    
    print()

def example_configuration_backup():
    """Esempio di backup configurazione via SNMP (per dispositivi supportati)"""
    print("=== Backup Configurazione via SNMP ===")
    
    # Questo esempio funziona principalmente con router Cisco
    # Altri vendor potrebbero avere OID diversi
    
    client = SnmpClient(
        host="192.168.1.1",
        community="private",  # Spesso serve community di scrittura
        version=SnmpVersion.V2C
    )
    
    # OID Cisco per backup configurazione
    cisco_oids = {
        'running_config': '1.3.6.1.4.1.9.2.1.40.0',  # Cisco running-config
        'startup_config': '1.3.6.1.4.1.9.2.1.41.0',  # Cisco startup-config
    }
    
    print("Tentativo backup configurazione...")
    print("NOTA: Questo esempio funziona principalmente con dispositivi Cisco")
    print("Altri vendor potrebbero richiedere OID diversi")
    
    # Prova a ottenere la configurazione
    for config_type, oid in cisco_oids.items():
        print(f"\nTentativo lettura {config_type}...")
        
        try:
            result = client.get(oid)
            if result:
                config_data = str(result)
                if len(config_data) > 100:  # Se abbiamo dati significativi
                    filename = f"{config_type}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                    
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(config_data)
                    
                    print(f"✓ Configurazione salvata in: {filename}")
                    print(f"  Dimensione: {len(config_data)} caratteri")
                else:
                    print("✗ Configurazione vuota o non disponibile")
            else:
                print("✗ Impossibile leggere la configurazione")
                
        except Exception as e:
            print(f"✗ Errore: {e}")
    
    print("\nNOTA: Per il backup completo, considera l'uso di protocolli")
    print("dedicati come SSH/Telnet o NETCONF invece di SNMP")
    print()

def main():
    """Esegui tutti gli esempi avanzati"""
    print("Esempi Avanzati AdvancedSnmp")
    print("=" * 50)
    print("NOTA: Modifica gli indirizzi IP secondo la tua rete")
    print()
    
    try:
        # Esempi che non modificano configurazioni
        example_interface_monitoring()
        example_snmp_table_walking()
        example_concurrent_monitoring()
        
        print("ATTENZIONE: Gli esempi seguenti sono commentati")
        print("Decommenta solo se hai dispositivi di test appropriati")
        
        # Esempi che richiedono dispositivi specifici o reti reali
        # example_network_discovery()      # Potrebbe essere lento
        # example_performance_monitoring() # Richiede UCD-SNMP
        # example_configuration_backup()   # Richiede community di scrittura
        
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente")
    except Exception as e:
        print(f"Errore: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
