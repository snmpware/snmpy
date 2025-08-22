# SNMPY

Una libreria SNMP completa e avanzata per Python che supporta SNMPv1, SNMPv2c e SNMPv3 con autenticazione e crittografia.

## 🚀 Caratteristiche

- **Supporto completo per SNMPv1, SNMPv2c e SNMPv3**
- **SNMPv3 Security**: Autenticazione (MD5, SHA, SHA224, SHA256, SHA384, SHA512) e Privacy (DES, AES128, AES192, AES256)
- **Operazioni SNMP complete**: GET, GETNEXT, GETBULK, SET, WALK
- **Monitoraggio UPS specializzato** con supporto per APC, Eaton, CyberPower
- **Codifica/decodifica ASN.1 BER nativa**
- **Gestione automatica del discovery SNMPv3**
- **Logging integrato** per debugging
- **Interface CLI** per monitoraggio UPS
- **Context manager support** per gestione automatica delle connessioni

## 📦 Installazione

### Dipendenze

```bash
pip install pycryptodome
```

### Download

Scarica il file `snmpy.py` e inseriscilo nel tuo progetto:

```python
from snmpy import SnmpClient, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol, SnmpV3PrivProtocol
```

## 🔧 Uso Base

### SNMPv2c Semplice

```python
from snmpy import SnmpClient, SnmpVersion

# Crea un client SNMPv2c
client = SnmpClient(
    host="192.168.1.100",
    community="public",
    version=SnmpVersion.V2C
)

# GET singolo
result = client.get("1.3.6.1.2.1.1.1.0")  # sysDescr
print(result)

# GET multipli
results = client.get_multiple([
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.3.0",  # sysUpTime
])
for oid, value in results.items():
    print(f"{oid} = {value}")
```

### SNMPv3 con Autenticazione e Privacy

```python
from snmpy import SnmpClient, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol, SnmpV3PrivProtocol

# Crea un utente SNMPv3
user = SnmpV3User(
    username="admin",
    auth_protocol=SnmpV3AuthProtocol.SHA256,
    auth_password="authpassword123",
    priv_protocol=SnmpV3PrivProtocol.AES256,
    priv_password="privpassword123"
)

# Crea un client SNMPv3
client = SnmpClient(
    host="192.168.1.100",
    version=SnmpVersion.V3,
    v3_user=user
)

# L'engine discovery avviene automaticamente
result = client.get("1.3.6.1.2.1.1.1.0")
print(result)
```

### SNMP Walk

```python
# Walk su un sottoalbero MIB
results = client.walk("1.3.6.1.2.1.2.2.1.2")  # ifDescr
for oid, value in results.items():
    print(f"{oid} = {value}")

# Bulk Walk (più efficiente per SNMPv2c/v3)
results = client.bulk_walk("1.3.6.1.2.1.2.2.1.2", max_repetitions=20)
```

### SNMP SET

```python
from snmpy import SnmpOctetString, SnmpInteger

# SET singolo
success = client.set("1.3.6.1.2.1.1.6.0", SnmpOctetString("Nuovo location"))

# SET multipli
success = client.set_multiple({
    "1.3.6.1.2.1.1.6.0": SnmpOctetString("Data Center"),
    "1.3.6.1.2.1.1.4.0": SnmpOctetString("admin@example.com")
})
```

## 🔋 Monitoraggio UPS

### Uso Base

```python
from snmpy import UpsMonitor, SnmpVersion

# Monitor UPS con SNMPv2c
monitor = UpsMonitor(
    host="192.168.1.200",
    community="public",
    version=SnmpVersion.V2C
)

# Test connessione
if monitor.test_connection():
    print("Connessione UPS OK")

# Ottieni informazioni UPS
info = monitor.get_ups_info()
print(f"Carico: {info['load']}%")
print(f"Batteria: {info['battery_charge']}%")
print(f"Stato: {monitor.interpret_status(info['ups_status'])}")
```

### Monitoraggio Continuo

```python
# Monitoraggio continuo (ogni 5 secondi)
monitor.monitor(interval=5.0)

# Monitoraggio per 1 ora
monitor.monitor(interval=5.0, duration=3600)
```

### UPS con SNMPv3

```python
from snmpy import UpsMonitor, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol

user = SnmpV3User(
    username="upsadmin",
    auth_protocol=SnmpV3AuthProtocol.SHA,
    auth_password="upspassword"
)

monitor = UpsMonitor(
    host="192.168.1.200",
    version=SnmpVersion.V3,
    v3_user=user
)

monitor.monitor()
```

## 🖥️ Interface a Riga di Comando

### Monitoraggio UPS

```bash
# SNMPv2c di base
python snmpy.py --ip 192.168.1.200 --version 2 --community public

# SNMPv3 con autenticazione
python snmpy.py --ip 192.168.1.200 --version 3 \
    --v3-user admin \
    --v3-auth-protocol SHA256 \
    --v3-auth-password mypassword

# SNMPv3 con autenticazione e privacy
python snmpy.py --ip 192.168.1.200 --version 3 \
    --v3-user admin \
    --v3-auth-protocol SHA256 \
    --v3-auth-password authpass \
    --v3-priv-protocol AES256 \
    --v3-priv-password privpass

# Test connessione
python snmpy.py --ip 192.168.1.200 --test

# SNMP Walk per scoprire OID
python snmpy.py --ip 192.168.1.200 --walk

# Monitoraggio con intervallo personalizzato
python snmpy.py --ip 192.168.1.200 --interval 10 --duration 300
```

## 📊 Tipi di Dati SNMP Supportati

La libreria supporta tutti i tipi di dati SNMP standard:

```python
from snmpy import (
    SnmpInteger, SnmpOctetString, SnmpNull, SnmpObjectIdentifier,
    SnmpSequence, SnmpIpAddress, SnmpCounter32, SnmpGauge32,
    SnmpTimeTicks, SnmpOpaque, SnmpCounter64
)

# Esempi di creazione
integer_val = SnmpInteger(42)
string_val = SnmpOctetString("Hello World")
oid_val = SnmpObjectIdentifier("1.3.6.1.2.1.1.1.0")
ip_val = SnmpIpAddress("192.168.1.1")
counter_val = SnmpCounter32(1234567)
```

## 🔐 Configurazioni di Sicurezza SNMPv3

### Livelli di Sicurezza

1. **noAuthNoPriv**: Nessuna autenticazione, nessuna privacy
2. **authNoPriv**: Solo autenticazione
3. **authPriv**: Autenticazione + Privacy

### Protocolli di Autenticazione

- MD5
- SHA
- SHA224
- SHA256
- SHA384
- SHA512

### Protocolli di Privacy

- DES
- AES128
- AES192
- AES256

### Esempio Configurazione Completa

```python
# Configurazione massima sicurezza
user = SnmpV3User(
    username="secureuser",
    auth_protocol=SnmpV3AuthProtocol.SHA512,
    auth_password="very_secure_auth_password_123",
    priv_protocol=SnmpV3PrivProtocol.AES256,
    priv_password="very_secure_priv_password_456"
)
```

## 🏗️ Context Manager

```python
# Gestione automatica della connessione
with SnmpClient(host="192.168.1.100", community="public") as client:
    result = client.get("1.3.6.1.2.1.1.1.0")
    print(result)
# La connessione viene chiusa automaticamente
```

## 🐛 Debugging

```python
import logging

# Abilita logging dettagliato
logging.basicConfig(level=logging.DEBUG)

# O usa il flag --debug nella CLI
python snmpy.py --ip 192.168.1.200 --debug
```

## 🔍 Esempi Avanzati

### Discovery Automatico UPS

```python
monitor = UpsMonitor("192.168.1.200")
ups_type = monitor.detect_ups_type()
print(f"Tipo UPS rilevato: {ups_type}")

# Walk completo della MIB UPS
mib_data = monitor.walk_mib("1.3.6.1.2.1.33")
for oid, value in mib_data.items():
    print(f"{oid} = {value}")
```

### Gestione Errori

```python
try:
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result is None:
        print("OID non trovato o errore di comunicazione")
except Exception as e:
    print(f"Errore: {e}")
```

### Monitoraggio Multi-UPS

```python
ups_list = [
    {"host": "192.168.1.200", "name": "UPS-DC1"},
    {"host": "192.168.1.201", "name": "UPS-DC2"},
]

for ups_config in ups_list:
    monitor = UpsMonitor(ups_config["host"])
    if monitor.test_connection():
        info = monitor.get_ups_info()
        print(f"{ups_config['name']}: Load={info['load']}%, Battery={info['battery_charge']}%")
```

## 📝 Logging

La libreria include logging dettagliato per debugging:

```python
import logging
logging.getLogger("Snmpy").setLevel(logging.INFO)
```

Livelli di log:
- `DEBUG`: Dettagli completi della comunicazione SNMP
- `INFO`: Operazioni principali
- `WARNING`: Problemi non critici
- `ERROR`: Errori di comunicazione

## 🤝 Supporto UPS

La libreria include supporto specializzato per:

- **APC UPS** (OID Enterprise 318)
- **Eaton UPS** (OID Enterprise 534)
- **CyberPower UPS** (OID Enterprise 3808)
- **UPS Standard RFC 1628**

Il rilevamento del tipo UPS avviene automaticamente.

## ⚠️ Note di Sicurezza

- **Non utilizzare password deboli** per SNMPv3
- **Evita community string predefiniti** come "public" in produzione
- **Usa sempre HTTPS/VPN** per reti non sicure
- **Limita l'accesso SNMP** con firewall/ACL
- **Monitora i log** per tentativi di accesso non autorizzati

## 📄 Licenza

MIT License - Vedi LICENSE file per dettagli.

## 🛠️ Contribuire

1. Fork del repository
2. Crea un branch per la tua feature
3. Commit delle modifiche
4. Push al branch
5. Crea una Pull Request

## 📞 Supporto

Per bug, feature request o domande, apri una issue su GitHub.

---

**Snmpy** - Una libreria SNMP potente e flessibile per Python 🐍
