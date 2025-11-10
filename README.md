<p align="center">
  <img src="snmpy.png" alt="PolymCP Logo" width="400"/>
</p>

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

# Create SNMP client
client = SnmpClient(
    host="192.168.1.1",
    port=161,
    community="public",
    version=SnmpVersion.V2C
)

# Single GET
result = client.get("1.3.6.1.2.1.1.1.0")  # sysDescr
print(result)

# Multiple GET
oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]
results = client.get_multiple(oids)
for oid, value in results.items():
    print(f"{oid} = {value}")
```

### SNMPv3 GET

```python
from snmpy import SnmpClient, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol, SnmpV3PrivProtocol

# Create SNMPv3 user
v3_user = SnmpV3User(
    username="admin",
    auth_protocol=SnmpV3AuthProtocol.SHA,
    auth_password="authpass123",
    priv_protocol=SnmpV3PrivProtocol.AES128,
    priv_password="privpass456"
)

# Create SNMPv3 client
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

# Test connection
if ups.test_connection():
    print("✅ Connection OK")

# Detect UPS type
ups_type = ups.detect_ups_type()  # "APC", "Eaton", "CyberPower", etc.

# Get information
info = ups.get_ups_info()
print(f"Load: {info['load']}%")
print(f"Battery: {info['battery_charge']}%")
print(f"Input voltage: {info['input_voltage']}V")
print(f"Output voltage: {info['output_voltage']}V")
print(f"Temperature: {info['temperature']}°C")
print(f"Runtime: {info['estimated_runtime']} minutes")

# Interpret status
status = ups.interpret_status(info['ups_status'])
print(f"Status: {status}")  # "Normal", "Battery", etc.

# Continuous monitoring with display
ups.monitor(interval=5.0)  # Update every 5 seconds

# SNMP Walk on UPS MIB
ups_data = ups.walk_mib("1.3.6.1.2.1.33")  # Complete UPS-MIB
```

---

### 📤 SNMP Traps

```python
from snmpy import SnmpTrapSender, SnmpVersion, SnmpOctetString, SnmpInteger

# Create sender
sender = SnmpTrapSender(
    trap_host="192.168.1.50",
    trap_port=162,
    community="public",
    version=SnmpVersion.V2C
)

# Standard traps
sender.send_cold_start()
sender.send_link_down(if_index=1, if_descr="eth0")

# Custom trap
sender.send_test_trap("System under maintenance")

# UPS trap
sender.send_ups_trap(
    'on_battery',
    battery_charge=75,
    runtime=45,
    load_percent=80,
    message="Power failure"
)
```

---

## 🔒 SNMPv3 Authentication & Privacy

* Auth protocols: `MD5`, `SHA`
* Privacy protocols: `AES`, `DES`
* USM security model
* RFC-compliant packet encoding

---

---

## 🛠️ Utilities

```python
from snmpy import decode_snmp_hex

# Decode hex dump (e.g. from Wireshark)
hex_packet = "302c020101040670..."
result = decode_snmp_hex(hex_packet, return_dict=True)

print(f"Version: {result['version']}")
print(f"Community: {result['community']}")
print(f"PDU Type: {result['pdu_type']}")
for vb in result['varbinds']:
    print(f"  {vb['oid']} = {vb['value']}")
```

---

## 🧪 Testing & Stability

* ✅ Lightweight and easy to debug
* ❗ Test coverage is in progress – contributions welcome!
* ✅ Cross-platform: Linux, macOS, Windows

---

## 📦 CLI Tool

```bash
# Monitor UPS
python snmpy.py monitor --ip 192.168.1.100 --interval 5

# Test connection
python snmpy.py monitor --ip 192.168.1.100 --test

# SNMP Walk
python snmpy.py monitor --ip 192.168.1.100 --walk

# Send trap
python snmpy.py trap --host 192.168.1.50 --type coldstart

# UPS trap
python snmpy.py trap --host 192.168.1.50 --type ups-battery

# Interactive test (guided menu)
python snmpy.py
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
