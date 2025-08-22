#!/usr/bin/env python3
"""
Esempi di uso base della libreria AdvancedSnmp
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from snmpy import (
    SnmpClient, SnmpVersion, SnmpOctetString, SnmpInteger,
    SnmpObjectIdentifier
)

def example_snmpv1():
    """Esempio con SNMPv1"""
    print("=== Esempio SNMPv1 ===")
    
    client = SnmpClient(
        host="127.0.0.1",  # Sostituisci con il tuo IP
        port=161,
        community="public",
        version=SnmpVersion.V1,
        timeout=3.0
    )
    
    # GET singolo - System Description
    print("GET sysDescr:")
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result:
        print(f"  {result}")
    else:
        print("  Errore o OID non trovato")
    
    print()

def example_snmpv2c():
    """Esempio con SNMPv2c"""
    print("=== Esempio SNMPv2c ===")
    
    client = SnmpClient(
        host="127.0.0.1",  # Sostituisci con il tuo IP
        port=161,
        community="public",
        version=SnmpVersion.V2C,
        timeout=3.0
    )
    
    # GET multipli
    print("GET multipli (System MIB):")
    oids = [
        "1.3.6.1.2.1.1.1.0",  # sysDescr
        "1.3.6.1.2.1.1.3.0",  # sysUpTime
        "1.3.6.1.2.1.1.4.0",  # sysContact
        "1.3.6.1.2.1.1.5.0",  # sysName
        "1.3.6.1.2.1.1.6.0",  # sysLocation
    ]
    
    results = client.get_multiple(oids)
    for oid, value in results.items():
        print(f"  {oid} = {value}")
    
    print()
    
    # GETNEXT
    print("GETNEXT da sysDescr:")
    next_oid, next_value = client.get_next("1.3.6.1.2.1.1.1.0")
    if next_oid:
        print(f"  Prossimo OID: {next_oid} = {next_value}")
    
    print()
    
    # GETBULK
    print("GETBULK su System MIB:")
    bulk_results = client.get_bulk(0, 5, ["1.3.6.1.2.1.1"])
    for oid, value in list(bulk_results.items())[:5]:  # Mostra solo i primi 5
        print(f"  {oid} = {value}")
    
    print()

def example_walk():
    """Esempio di SNMP Walk"""
    print("=== Esempio SNMP Walk ===")
    
    client = SnmpClient(
        host="127.0.0.1",
        community="public",
        version=SnmpVersion.V2C
    )
    
    # Walk sul System MIB
    print("Walk su System MIB (1.3.6.1.2.1.1):")
    results = client.walk("1.3.6.1.2.1.1")
    
    for oid, value in sorted(results.items()):
        print(f"  {oid} = {value}")
    
    print()

def example_set():
    """Esempio di SNMP SET"""
    print("=== Esempio SNMP SET ===")
    
    client = SnmpClient(
        host="127.0.0.1",
        community="private",  # Solitamente serve una community diversa per SET
        version=SnmpVersion.V2C
    )
    
    # Salva il valore originale
    print("Lettura valore originale sysLocation:")
    original = client.get("1.3.6.1.2.1.1.6.0")
    print(f"  Valore originale: {original}")
    
    # SET nuovo valore
    print("Impostazione nuovo valore:")
    new_value = SnmpOctetString("Test Location - Advanced SNMP Library")
    success = client.set("1.3.6.1.2.1.1.6.0", new_value)
    
    if success:
        print("  SET eseguito con successo")
        
        # Verifica il nuovo valore
        updated = client.get("1.3.6.1.2.1.1.6.0")
        print(f"  Nuovo valore: {updated}")
        
        # Ripristina il valore originale (se possibile)
        if original:
            print("Ripristino valore originale:")
            client.set("1.3.6.1.2.1.1.6.0", original)
            print("  Valore ripristinato")
    else:
        print("  ERRORE: SET fallito (controlla community/permessi)")
    
    print()

def example_context_manager():
    """Esempio con Context Manager"""
    print("=== Esempio Context Manager ===")
    
    # Il context manager gestisce automaticamente la connessione
    with SnmpClient(host="127.0.0.1", community="public") as client:
        result = client.get("1.3.6.1.2.1.1.1.0")
        print(f"sysDescr: {result}")
    # La connessione viene chiusa automaticamente
    
    print()

def example_error_handling():
    """Esempio di gestione errori"""
    print("=== Esempio Gestione Errori ===")
    
    # Host inesistente
    print("Test con host inesistente:")
    client = SnmpClient(
        host="192.168.99.99",  # IP probabilmente inesistente
        community="public",
        timeout=1.0,
        retries=1
    )
    
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result is None:
        print("  Nessuna risposta (timeout o host irraggiungibile)")
    
    # OID inesistente
    print("Test con OID inesistente:")
    client = SnmpClient(host="127.0.0.1", community="public")
    result = client.get("1.3.6.1.999.999.999.0")
    if result is None:
        print("  OID non trovato")
    
    print()

def main():
    """Esegui tutti gli esempi"""
    print("Esempi Base AdvancedSnmp")
    print("=" * 50)
    print("NOTA: Modifica gli indirizzi IP negli esempi per testare con i tuoi dispositivi")
    print()
    
    try:
        example_snmpv1()
        example_snmpv2c()
        example_walk()
        example_context_manager()
        example_error_handling()
        
        print("ATTENZIONE: L'esempio SET è commentato per sicurezza")
        print("Decommenta example_set() solo se hai un dispositivo di test")
        # example_set()  # Decommenta per testare SET
        
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente")
    except Exception as e:
        print(f"Errore: {e}")

if __name__ == "__main__":
    main()
