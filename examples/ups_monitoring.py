#!/usr/bin/env python3
"""
Esempi di monitoraggio UPS con AdvancedSnmp
"""

import sys
import os
import time
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from snmpy import (
    UpsMonitor, SnmpVersion, SnmpV3User, 
    SnmpV3AuthProtocol, SnmpV3PrivProtocol
)

def example_basic_ups_monitoring():
    """Esempio base di monitoraggio UPS"""
    print("=== Monitoraggio UPS Base ===")
    
    # Crea monitor UPS con SNMPv2c
    monitor = UpsMonitor(
        host="192.168.1.100",  # Sostituisci con l'IP del tuo UPS
        community="public",
        version=SnmpVersion.V2C
    )
    
    # Test connessione
    print("Test connessione UPS...")
    if monitor.test_connection():
        print("✓ Connessione UPS OK")
        
        # Ottieni informazioni UPS
        print("\nInformazioni UPS:")
        info = monitor.get_ups_info()
        
        for key, value in info.items():
            if value is not None:
                if key == 'ups_status':
                    status_str = monitor.interpret_status(value)
                    print(f"  {key}: {value} ({status_str})")
                else:
                    print(f"  {key}: {value}")
            else:
                print(f"  {key}: N/A")
    else:
        print("✗ Connessione UPS fallita")
    
    print()

def example_ups_discovery():
    """Esempio di discovery automatico del tipo UPS"""
    print("=== Discovery Automatico UPS ===")
    
    monitor = UpsMonitor(
        host="192.168.1.100",
        community="public",
        version=SnmpVersion.V2C
    )
    
    if monitor.test_connection():
        # Rileva il tipo di UPS
        ups_type = monitor.detect_ups_type()
        print(f"Tipo UPS rilevato: {ups_type}")
        
        # Ottieni modello
        info = monitor.get_ups_info()
        model = info.get('model', 'Sconosciuto')
        print(f"Modello: {model}")
        
        # Walk completo della MIB UPS per vedere tutti gli OID disponibili
        print("\nOID UPS disponibili (primi 10):")
        mib_data = monitor.walk_mib("1.3.6.1.2.1.33")  # Standard UPS MIB
        
        count = 0
        for oid, value in sorted(mib_data.items()):
            if count < 10:
                print(f"  {oid} = {value}")
                count += 1
            else:
                break
        
        if len(mib_data) > 10:
            print(f"  ... e altri {len(mib_data) - 10} OID")
    
    print()

def example_ups_with_snmpv3():
    """Esempio di monitoraggio UPS con SNMPv3"""
    print("=== Monitoraggio UPS con SNMPv3 ===")
    
    # Crea utente SNMPv3
    user = SnmpV3User(
        username="upsmonitor",
        auth_protocol=SnmpV3AuthProtocol.SHA256,
        auth_password="ups_auth_password_123",
        priv_protocol=SnmpV3PrivProtocol.AES256,
        priv_password="ups_priv_password_123"
    )
    
    # Crea monitor UPS
    monitor = UpsMonitor(
        host="192.168.1.100",
        version=SnmpVersion.V3,
        v3_user=user
    )
    
    print(f"Utente SNMPv3: {user.username}")
    print(f"Livello sicurezza: {user.get_security_level().name}")
    
    if monitor.test_connection():
        print("✓ Connessione SNMPv3 UPS OK")
        
        info = monitor.get_ups_info()
        print(f"Carico: {info.get('load', 'N/A')}%")
        print(f"Batteria: {info.get('battery_charge', 'N/A')}%")
        print(f"Stato: {monitor.interpret_status(info.get('ups_status'))}")
    else:
        print("✗ Connessione SNMPv3 fallita")
    
    print()

def example_continuous_monitoring():
    """Esempio di monitoraggio continuo con logging personalizzato"""
    print("=== Monitoraggio Continuo Personalizzato ===")
    
    monitor = UpsMonitor(
        host="192.168.1.100",
        community="public",
        version=SnmpVersion.V2C
    )
    
    if not monitor.test_connection():
        print("Impossibile connettersi all'UPS")
        return
    
    print("Avvio monitoraggio (Ctrl+C per fermare)...")
    print("Timestamp,Load%,Battery%,Status,InputV,OutputV,Temp")
    
    try:
        while True:
            info = monitor.get_ups_info()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Crea riga CSV
            load = info.get('load', 'N/A')
            battery = info.get('battery_charge', 'N/A')
            status = info.get('ups_status', 'N/A')
            input_v = info.get('input_voltage', 'N/A')
            output_v = info.get('output_voltage', 'N/A')
            temp = info.get('temperature', 'N/A')
            
            print(f"{timestamp},{load},{battery},{status},{input_v},{output_v},{temp}")
            
            # Controlla condizioni di allarme
            if isinstance(load, (int, float)) and load > 80:
                print(f"⚠️  ALLARME: Carico alto ({load}%)")
            
            if isinstance(battery, (int, float)) and battery < 20:
                print(f"🔋 ALLARME: Batteria bassa ({battery}%)")
            
            time.sleep(10)  # Polling ogni 10 secondi
            
    except KeyboardInterrupt:
        print("\nMonitoraggio interrotto")
    
    print()

def example_multi_ups_monitoring():
    """Esempio di monitoraggio multipli UPS"""
    print("=== Monitoraggio Multi-UPS ===")
    
    # Lista di UPS da monitorare
    ups_list = [
        {
            "name": "UPS-DC1",
            "host": "192.168.1.100",
            "community": "public"
        },
        {
            "name": "UPS-DC2", 
            "host": "192.168.1.101",
            "community": "public"
        },
        {
            "name": "UPS-Office",
            "host": "192.168.1.102",
            "community": "public"
        }
    ]
    
    print("Stato UPS:")
    print("-" * 80)
    print(f"{'Nome':<15} {'Host':<15} {'Stato':<10} {'Carico':<8} {'Batteria':<8} {'Modello'}")
    print("-" * 80)
    
    for ups_config in ups_list:
        monitor = UpsMonitor(
            host=ups_config["host"],
            community=ups_config["community"],
            version=SnmpVersion.V2C
        )
        
        if monitor.test_connection():
            info = monitor.get_ups_info()
            
            status = monitor.interpret_status(info.get('ups_status'))
            load = f"{info.get('load', 'N/A')}%"
            battery = f"{info.get('battery_charge', 'N/A')}%"
            model = info.get('model', 'N/A')
            
            # Tronca il modello se troppo lungo
            if len(str(model)) > 20:
                model = str(model)[:17] + "..."
            
            print(f"{ups_config['name']:<15} {ups_config['host']:<15} {status:<10} {load:<8} {battery:<8} {model}")
        else:
            print(f"{ups_config['name']:<15} {ups_config['host']:<15} {'OFFLINE':<10} {'N/A':<8} {'N/A':<8} {'N/A'}")
    
    print()

def example_ups_alerting():
    """Esempio di sistema di alerting per UPS"""
    print("=== Sistema di Alerting UPS ===")
    
    monitor = UpsMonitor(
        host="192.168.1.100",
        community="public",
        version=SnmpVersion.V2C
    )
    
    # Soglie di allarme
    ALERT_THRESHOLDS = {
        'load_warning': 70,      # Carico % soglia warning
        'load_critical': 85,     # Carico % soglia critical
        'battery_warning': 30,   # Batteria % soglia warning  
        'battery_critical': 15,  # Batteria % soglia critical
        'temp_warning': 35,      # Temperatura °C soglia warning
        'temp_critical': 45      # Temperatura °C soglia critical
    }
    
    def check_alerts(ups_info):
        """Controlla le condizioni di allarme"""
        alerts = []
        
        # Controllo carico
        load = ups_info.get('load')
        if isinstance(load, (int, float)):
            if load >= ALERT_THRESHOLDS['load_critical']:
                alerts.append(f"🔴 CRITICAL: Carico UPS {load}% (soglia: {ALERT_THRESHOLDS['load_critical']}%)")
            elif load >= ALERT_THRESHOLDS['load_warning']:
                alerts.append(f"🟡 WARNING: Carico UPS {load}% (soglia: {ALERT_THRESHOLDS['load_warning']}%)")
        
        # Controllo batteria
        battery = ups_info.get('battery_charge')
        if isinstance(battery, (int, float)):
            if battery <= ALERT_THRESHOLDS['battery_critical']:
                alerts.append(f"🔴 CRITICAL: Batteria UPS {battery}% (soglia: {ALERT_THRESHOLDS['battery_critical']}%)")
            elif battery <= ALERT_THRESHOLDS['battery_warning']:
                alerts.append(f"🟡 WARNING: Batteria UPS {battery}% (soglia: {ALERT_THRESHOLDS['battery_warning']}%)")
        
        # Controllo temperatura
        temp = ups_info.get('temperature')
        if isinstance(temp, (int, float)):
            if temp >= ALERT_THRESHOLDS['temp_critical']:
                alerts.append(f"🔴 CRITICAL: Temperatura UPS {temp}°C (soglia: {ALERT_THRESHOLDS['temp_critical']}°C)")
            elif temp >= ALERT_THRESHOLDS['temp_warning']:
                alerts.append(f"🟡 WARNING: Temperatura UPS {temp}°C (soglia: {ALERT_THRESHOLDS['temp_warning']}°C)")
        
        # Controllo stato operativo
        status = ups_info.get('ups_status')
        if status is not None and status != 3:  # 3 = Normal
            status_str = monitor.interpret_status(status)
            if status == 5:  # Battery
                alerts.append(f"🔴 CRITICAL: UPS funziona a batteria ({status_str})")
            else:
                alerts.append(f"🟡 WARNING: Stato UPS anomalo ({status_str})")
        
        return alerts
    
    if monitor.test_connection():
        print("Controllo stato UPS...")
        info = monitor.get_ups_info()
        
        # Mostra stato attuale
        print(f"Carico: {info.get('load', 'N/A')}%")
        print(f"Batteria: {info.get('battery_charge', 'N/A')}%")
        print(f"Temperatura: {info.get('temperature', 'N/A')}°C")
        print(f"Stato: {monitor.interpret_status(info.get('ups_status'))}")
        
        # Controlla allarmi
        alerts = check_alerts(info)
        
        if alerts:
            print("\n🚨 ALLARMI ATTIVI:")
            for alert in alerts:
                print(f"  {alert}")
        else:
            print("\n✅ Nessun allarme - UPS funziona correttamente")
    else:
        print("🔴 CRITICAL: Impossibile comunicare con l'UPS")
    
    print()

def example_ups_data_export():
    """Esempio di esportazione dati UPS in JSON"""
    print("=== Esportazione Dati UPS ===")
    
    monitor = UpsMonitor(
        host="192.168.1.100",
        community="public",
        version=SnmpVersion.V2C
    )
    
    if monitor.test_connection():
        # Raccogli tutti i dati disponibili
        info = monitor.get_ups_info()
        ups_type = monitor.detect_ups_type()
        
        # Crea struttura dati completa
        ups_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ups_type": ups_type,
            "host": monitor.host,
            "snmp_version": str(monitor.version),
            "metrics": {},
            "status": {}
        }
        
        # Aggiungi metriche
        for key, value in info.items():
            if value is not None:
                if key == 'ups_status':
                    ups_data["status"]["code"] = value
                    ups_data["status"]["description"] = monitor.interpret_status(value)
                else:
                    ups_data["metrics"][key] = value
        
        # Esporta in JSON
        json_output = json.dumps(ups_data, indent=2, ensure_ascii=False)
        print("Dati UPS in formato JSON:")
        print(json_output)
        
        # Salva su file (opzionale)
        filename = f"ups_data_{time.strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(json_output)
            print(f"\nDati salvati in: {filename}")
        except Exception as e:
            print(f"Errore salvataggio file: {e}")
    
    print()

def main():
    """Esegui tutti gli esempi UPS"""
    print("Esempi Monitoraggio UPS AdvancedSnmp")
    print("=" * 50)
    print("NOTA: Modifica gli indirizzi IP per puntare ai tuoi UPS")
    print()
    
    try:
        example_basic_ups_monitoring()
        example_ups_discovery() 
        example_multi_ups_monitoring()
        example_ups_alerting()
        example_ups_data_export()
        
        print("ATTENZIONE: Gli esempi con SNMPv3 e monitoraggio continuo sono commentati")
        print("Decommenta solo dopo aver configurato correttamente i tuoi UPS")
        # example_ups_with_snmpv3()
        # example_continuous_monitoring()
        
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente")
    except Exception as e:
        print(f"Errore: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
