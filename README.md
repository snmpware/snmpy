# SNMPY – Pure Python SNMP Library with Zero Core Dependencies

**snmpy** is a lightweight, pure Python library for SNMP v1/v2c/v3, built from scratch with **no external dependencies** for core functionality.  

It supports:

- ✅ SNMP GET, WALK, SET operations  
- ✅ SNMPv3 authentication and privacy (encryption)  
- ✅ Sending and decoding SNMP TRAPs  
- ✅ Monitoring UPS status (battery, voltage, etc.)  
- ✅ Built-in CLI for quick usage  

**No need for Net-SNMP or PySNMP.**  
**Zero core dependencies** (optional: `pycryptodome` for SNMPv3 encryption).  
**Cross-platform**, readable code, MIT license.

---

## 🔧 Installation

```bash
git clone https://github.com/snmpware/snmpy.git
cd snmpy
python3 setup.py install
````

Optional (for SNMPv3 with encryption):

```bash
pip install pycryptodome
```

---

## 🚀 Quick Start

### SNMPv2c GET

```python
from snmpy import SnmpClient, SnmpVersion

# Crea client SNMP
client = SnmpClient(
    host="192.168.1.1",
    port=161,
    community="public",
    version=SnmpVersion.V2C
)

# GET singolo
result = client.get("1.3.6.1.2.1.1.1.0")  # sysDescr
print(result)

# GET multiplo
oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]
results = client.get_multiple(oids)
for oid, value in results.items():
    print(f"{oid} = {value}")
```

### SNMPv3 GET

```python
from snmpy import SnmpClient, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol, SnmpV3PrivProtocol

# Crea utente SNMPv3
v3_user = SnmpV3User(
    username="admin",
    auth_protocol=SnmpV3AuthProtocol.SHA,
    auth_password="authpass123",
    priv_protocol=SnmpV3PrivProtocol.AES128,
    priv_password="privpass456"
)

# Crea client SNMPv3
client = SnmpClient(
    host="192.168.1.1",
    port=161,
    version=SnmpVersion.V3,
    v3_user=v3_user
)

result = client.get("1.3.6.1.2.1.1.1.0")
print(result)
```

> More examples (WALK, SET, TRAPs) available in the `examples/` folder.

---

## ⚡ UPS Monitoring Example

```python
from snmpy import UpsMonitor, SnmpVersion

# Monitor UPS v2c
ups = UpsMonitor(
    host="192.168.1.100",
    port=161,
    community="public",
    version=SnmpVersion.V2C
)

# Test connessione
if ups.test_connection():
    print("✅ Connessione OK")

# Rileva tipo di UPS
ups_type = ups.detect_ups_type()  # "APC", "Eaton", "CyberPower", etc.

# Ottieni informazioni
info = ups.get_ups_info()
print(f"Carico: {info['load']}%")
print(f"Batteria: {info['battery_charge']}%")
print(f"Tensione in: {info['input_voltage']}V")
print(f"Tensione out: {info['output_voltage']}V")
print(f"Temperatura: {info['temperature']}°C")
print(f"Runtime: {info['estimated_runtime']} minuti")

# Interpreta stato
status = ups.interpret_status(info['ups_status'])
print(f"Stato: {status}")  # "Normale", "Batteria", etc.

# Monitor continuo con visualizzazione
ups.monitor(interval=5.0)  # Aggiorna ogni 5 secondi

# SNMP Walk su MIB UPS
ups_data = ups.walk_mib("1.3.6.1.2.1.33")  # UPS-MIB completo
```

---

## 🔒 SNMPv3 Authentication & Privacy

* Auth protocols: `MD5`, `SHA`
* Privacy protocols: `AES`, `DES`
* USM security model
* RFC-compliant packet encoding

---

## 🛠 Features

* SNMP GET / WALK / SET
* SNMPv1, v2c, v3 support
* TRAP sending & decoding
* UPS monitoring (APC / RFC-1628)
* No C libraries or compiled extensions
* Python 3.6+

---

## 🧪 Testing & Stability

* ✅ Lightweight and easy to debug
* ❗ Test coverage is in progress – contributions welcome!
* ✅ Cross-platform: Linux, macOS, Windows

---

## 📦 CLI Tool

```bash
snmpy get 192.168.1.1 -c public -o 1.3.6.1.2.1.1.1.0
```

---

## 📚 More Examples

See the [`examples/`](examples/) folder for:

* SNMPv3 encrypted GET/SET
* UPS status polling scripts
* Trap listener & decoder
* CLI usage

---

## 📈 Roadmap

* SNMP bulk operations
* Async support
* More MIB decoders
* Full test suite & CI
* Community examples

---

## 🤝 Contributing

Bug reports, suggestions, and pull requests are welcome!
See `CONTRIBUTING.md` or [open an issue](https://github.com/snmpware/snmpy/issues) to start a discussion.

---

## 📄 License

**MIT License** — free for commercial and personal use.
