#!/usr/bin/env python3
"""
Esempi di SNMPv3 con diversi livelli di sicurezza
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from snmpy import (
    SnmpClient, SnmpVersion, SnmpV3User, 
    SnmpV3AuthProtocol, SnmpV3PrivProtocol, SnmpV3SecurityLevel
)

def example_no_auth_no_priv():
    """SNMPv3 senza autenticazione e senza privacy (noAuthNoPriv)"""
    print("=== SNMPv3 noAuthNoPriv ===")
    
    user = SnmpV3User(
        username="public",
        auth_protocol=SnmpV3AuthProtocol.NO_AUTH,
        priv_protocol=SnmpV3PrivProtocol.NO_PRIV
    )
    
    print(f"Livello sicurezza: {user.get_security_level().name}")
    
    client = SnmpClient(
        host="127.0.0.1",  # Sostituisci con il tuo IP
        version=SnmpVersion.V3,
        v3_user=user,
        timeout=5.0
    )
    
    # Test con GET
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result:
        print(f"sysDescr: {result}")
    else:
        print("Nessuna risposta (verifica configurazione dispositivo)")
    
    print()

def example_auth_no_priv():
    """SNMPv3 con autenticazione ma senza privacy (authNoPriv)"""
    print("=== SNMPv3 authNoPriv ===")
    
    # Esempio con SHA256
    user = SnmpV3User(
        username="authuser",
        auth_protocol=SnmpV3AuthProtocol.SHA256,
        auth_password="authentication_password_123",
        priv_protocol=SnmpV3PrivProtocol.NO_PRIV
    )
    
    print(f"Livello sicurezza: {user.get_security_level().name}")
    print(f"Protocollo auth: {user.auth_protocol.value}")
    
    client = SnmpClient(
        host="127.0.0.1",
        version=SnmpVersion.V3,
        v3_user=user,
        timeout=5.0
    )
    
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result:
        print(f"sysDescr: {result}")
    else:
        print("Autenticazione fallita o dispositivo non configurato")
    
    print()

def example_auth_priv():
    """SNMPv3 con autenticazione e privacy (authPriv)"""
    print("=== SNMPv3 authPriv ===")
    
    # Esempio con SHA512 + AES256 (massima sicurezza)
    user = SnmpV3User(
        username="secureuser",
        auth_protocol=SnmpV3AuthProtocol.SHA512,
        auth_password="very_secure_auth_password_123456",
        priv_protocol=SnmpV3PrivProtocol.AES256,
        priv_password="very_secure_priv_password_123456"
    )
    
    print(f"Livello sicurezza: {user.get_security_level().name}")
    print(f"Protocollo auth: {user.auth_protocol.value}")
    print(f"Protocollo priv: {user.priv_protocol.value}")
    
    client = SnmpClient(
        host="127.0.0.1",
        version=SnmpVersion.V3,
        v3_user=user,
        timeout=5.0
    )
    
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result:
        print(f"sysDescr: {result}")
    else:
        print("Comunicazione fallita (verifica credenziali)")
    
    print()

def example_different_auth_protocols():
    """Esempi con diversi protocolli di autenticazione"""
    print("=== Diversi Protocolli di Autenticazione ===")
    
    auth_protocols = [
        SnmpV3AuthProtocol.MD5,
        SnmpV3AuthProtocol.SHA,
        SnmpV3AuthProtocol.SHA224,
        SnmpV3AuthProtocol.SHA256,
        SnmpV3AuthProtocol.SHA384,
        SnmpV3AuthProtocol.SHA512,
    ]
    
    for auth_proto in auth_protocols:
        print(f"Protocollo: {auth_proto.value}")
        
        user = SnmpV3User(
            username="testuser",
            auth_protocol=auth_proto,
            auth_password="testpassword123",
            priv_protocol=SnmpV3PrivProtocol.NO_PRIV
        )
        
        # Mostra la lunghezza della chiave generata
        if user.auth_key:
            print(f"  Lunghezza chiave auth: {len(user.auth_key)} bytes")
        
    print()

def example_different_priv_protocols():
    """Esempi con diversi protocolli di privacy"""
    print("=== Diversi Protocolli di Privacy ===")
    
    priv_protocols = [
        SnmpV3PrivProtocol.DES,
        SnmpV3PrivProtocol.AES128,
        SnmpV3PrivProtocol.AES192,
        SnmpV3PrivProtocol.AES256,
    ]
    
    for priv_proto in priv_protocols:
        print(f"Protocollo: {priv_proto.value}")
        
        user = SnmpV3User(
            username="testuser",
            auth_protocol=SnmpV3AuthProtocol.SHA256,
            auth_password="authpassword123",
            priv_protocol=priv_proto,
            priv_password="privpassword123"
        )
        
        # Mostra la lunghezza della chiave generata
        if user.priv_key:
            print(f"  Lunghezza chiave priv: {len(user.priv_key)} bytes")
        
    print()

def example_engine_discovery():
    """Esempio di discovery del motore SNMPv3"""
    print("=== Engine Discovery SNMPv3 ===")
    
    from snmpy import SnmpV3MessageProcessor
    
    user = SnmpV3User(
        username="discoveryuser",
        auth_protocol=SnmpV3AuthProtocol.NO_AUTH,
        priv_protocol=SnmpV3PrivProtocol.NO_PRIV
    )
    
    processor = SnmpV3MessageProcessor(user)
    
    print("Tentativo discovery...")
    success = processor.discover_engine("127.0.0.1", timeout=3.0)
    
    if success:
        print(f"Engine ID: {processor.engine_id.hex() if processor.engine_id else 'N/A'}")
        print(f"Engine Boots: {processor.engine_boots}")
        print(f"Engine Time: {processor.engine_time}")
    else:
        print("Discovery fallito (dispositivo non risponde o non supporta SNMPv3)")
    
    print()

def example_secure_configuration():
    """Esempio di configurazione sicura per produzione"""
    print("=== Configurazione Sicura per Produzione ===")
    
    # Configurazione consigliata per ambienti di produzione
    secure_user = SnmpV3User(
        username="prod_monitor_user_2024",  # Username non prevedibile
        auth_protocol=SnmpV3AuthProtocol.SHA256,  # Algoritmo moderno
        auth_password="Pr0d_Auth_P@ssw0rd_2024!#$%",  # Password complessa
        priv_protocol=SnmpV3PrivProtocol.AES256,  # Crittografia forte
        priv_password="Pr0d_Priv_P@ssw0rd_2024!#$%"   # Password complessa diversa
    )
    
    print("Configurazione raccomandata:")
    print(f"  Username: {secure_user.username}")
    print(f"  Auth Protocol: {secure_user.auth_protocol.value}")
    print(f"  Priv Protocol: {secure_user.priv_protocol.value}")
    print(f"  Security Level: {secure_user.get_security_level().name}")
    print()
    
    print("Best practices per la sicurezza:")
    print("  ✓ Username non prevedibili (evita 'admin', 'user', etc.)")
    print("  ✓ Password lunghe e complesse (>16 caratteri)")
    print("  ✓ Password diverse per auth e priv")
    print("  ✓ Usa SHA256+ per autenticazione")
    print("  ✓ Usa AES256 per privacy")
    print("  ✓ Cambia le password regolarmente")
    print("  ✓ Monitora i log per tentativi di accesso")
    print("  ✓ Limita l'accesso SNMP con firewall")
    print()

def example_bulk_operations_v3():
    """Esempio di operazioni bulk con SNMPv3"""
    print("=== Operazioni Bulk con SNMPv3 ===")
    
    user = SnmpV3User(
        username="bulkuser",
        auth_protocol=SnmpV3AuthProtocol.SHA,
        auth_password="bulkpassword123"
    )
    
    client = SnmpClient(
        host="127.0.0.1",
        version=SnmpVersion.V3,
        v3_user=user
    )
    
    # GetBulk per ottenere molti valori in una richiesta
    print("GetBulk su System MIB:")
    results = client.get_bulk(0, 10, ["1.3.6.1.2.1.1"])
    
    for oid, value in list(results.items())[:5]:  # Mostra solo i primi 5
        print(f"  {oid} = {value}")
    
    if len(results) > 5:
        print(f"  ... e altri {len(results) - 5} risultati")
    
    print()

def main():
    """Esegui tutti gli esempi SNMPv3"""
    print("Esempi SNMPv3 AdvancedSnmp")
    print("=" * 50)
    print("NOTA: Questi esempi richiedono un dispositivo configurato per SNMPv3")
    print("Modifica IP e credenziali secondo la tua configurazione")
    print()
    
    try:
        example_no_auth_no_priv()
        example_different_auth_protocols()
        example_different_priv_protocols()
        example_engine_discovery()
        example_secure_configuration()
        
        print("ATTENZIONE: Gli esempi con autenticazione sono commentati")
        print("Decommenta solo se hai un dispositivo SNMPv3 configurato")
        # example_auth_no_priv()
        # example_auth_priv()
        # example_bulk_operations_v3()
        
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente")
    except Exception as e:
        print(f"Errore: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
