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
from snmpy import SNMP

snmp = SNMP(host="192.168.1.1", community="public")
result = snmp.get("1.3.6.1.2.1.1.1.0")  # sysDescr
print(result)
```

### SNMPv3 GET

```python
from snmpy import SNMP

snmp = SNMP(
    host="192.168.1.1",
    version=3,
    username="user",
    authkey="password",
    privkey="secret",
    authproto="sha",
    privproto="aes",
)
print(snmp.get("1.3.6.1.2.1.1.1.0"))
```

> More examples (WALK, SET, TRAPs) available in the `examples/` folder.

---

## ⚡ UPS Monitoring Example

```python
from snmpy.ups import UPS

ups = UPS("192.168.1.100", community="public")
print(ups.status())       # ON LINE / ON BATTERY
print(ups.battery())      # Battery charge %
print(ups.voltage())      # Input/output voltage
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
