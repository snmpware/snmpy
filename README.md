# SNMPY

A complete and advanced SNMP library for Python that supports SNMPv1, SNMPv2c and SNMPv3 with authentication and encryption.

## 🚀 Features

- **Full support for SNMPv1, SNMPv2c and SNMPv3**
- **SNMPv3 Security**: Authentication (MD5, SHA, SHA224, SHA256, SHA384, SHA512) and Privacy (DES, AES128, AES192, AES256)
- **Complete SNMP operations**: GET, GETNEXT, GETBULK, SET, WALK
- **Specialized UPS monitoring** with support for APC, Eaton, CyberPower
- **Native ASN.1 BER encoding/decoding**
- **Automatic SNMPv3 discovery management**
- **Integrated logging** for debugging
- **CLI interface** for UPS monitoring
- **Context manager support** for automatic connection management

## 📦 Installation

### Dependencies

```bash
pip install pycryptodome
```

### Download

Download the `snmpy.py` file and include it in your project:

```python
from snmpy import SnmpClient, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol, SnmpV3PrivProtocol
```

## 🔧 Basic Usage

### Simple SNMPv2c

```python
from snmpy import SnmpClient, SnmpVersion

# Create an SNMPv2c client
client = SnmpClient(
    host="192.168.1.100",
    community="public",
    version=SnmpVersion.V2C
)

# Single GET
result = client.get("1.3.6.1.2.1.1.1.0")  # sysDescr
print(result)

# Multiple GETs
results = client.get_multiple([
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.3.0",  # sysUpTime
])
for oid, value in results.items():
    print(f"{oid} = {value}")
```

### SNMPv3 with Authentication and Privacy

```python
from snmpy import SnmpClient, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol, SnmpV3PrivProtocol

# Create an SNMPv3 user
user = SnmpV3User(
    username="admin",
    auth_protocol=SnmpV3AuthProtocol.SHA256,
    auth_password="authpassword123",
    priv_protocol=SnmpV3PrivProtocol.AES256,
    priv_password="privpassword123"
)

# Create an SNMPv3 client
client = SnmpClient(
    host="192.168.1.100",
    version=SnmpVersion.V3,
    v3_user=user
)

# Engine discovery happens automatically
result = client.get("1.3.6.1.2.1.1.1.0")
print(result)
```

### SNMP Walk

```python
# Walk a MIB subtree
results = client.walk("1.3.6.1.2.1.2.2.1.2")  # ifDescr
for oid, value in results.items():
    print(f"{oid} = {value}")

# Bulk Walk (more efficient for SNMPv2c/v3)
results = client.bulk_walk("1.3.6.1.2.1.2.2.1.2", max_repetitions=20)
```

### SNMP SET

```python
from snmpy import SnmpOctetString, SnmpInteger

# Single SET
success = client.set("1.3.6.1.2.1.1.6.0", SnmpOctetString("New location"))

# Multiple SETs
success = client.set_multiple({
    "1.3.6.1.2.1.1.6.0": SnmpOctetString("Data Center"),
    "1.3.6.1.2.1.1.4.0": SnmpOctetString("admin@example.com")
})
```

## 🔋 UPS Monitoring

### Basic Usage

```python
from snmpy import UpsMonitor, SnmpVersion

# Monitor UPS with SNMPv2c
monitor = UpsMonitor(
    host="192.168.1.200",
    community="public",
    version=SnmpVersion.V2C
)

# Test connection
if monitor.test_connection():
    print("UPS connection OK")

# Get UPS information
info = monitor.get_ups_info()
print(f"Load: {info['load']}%")
print(f"Battery: {info['battery_charge']}%")
print(f"Status: {monitor.interpret_status(info['ups_status'])}")
```

### Continuous Monitoring

```python
# Continuous monitoring (every 5 seconds)
monitor.monitor(interval=5.0)

# Monitor for 1 hour
monitor.monitor(interval=5.0, duration=3600)
```

### UPS with SNMPv3

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

## 🖥️ Command Line Interface

### UPS Monitoring

```bash
# Basic SNMPv2c
python snmpy.py --ip 192.168.1.200 --version 2 --community public

# SNMPv3 with authentication
python snmpy.py --ip 192.168.1.200 --version 3 \
    --v3-user admin \
    --v3-auth-protocol SHA256 \
    --v3-auth-password mypassword

# SNMPv3 with authentication and privacy
python snmpy.py --ip 192.168.1.200 --version 3 \
    --v3-user admin \
    --v3-auth-protocol SHA256 \
    --v3-auth-password authpass \
    --v3-priv-protocol AES256 \
    --v3-priv-password privpass

# Test connection
python snmpy.py --ip 192.168.1.200 --test

# SNMP Walk to discover OIDs
python snmpy.py --ip 192.168.1.200 --walk

# Monitoring with custom interval
python snmpy.py --ip 192.168.1.200 --interval 10 --duration 300
```

## 📊 Supported SNMP Data Types

The library supports all standard SNMP data types:

```python
from snmpy import (
    SnmpInteger, SnmpOctetString, SnmpNull, SnmpObjectIdentifier,
    SnmpSequence, SnmpIpAddress, SnmpCounter32, SnmpGauge32,
    SnmpTimeTicks, SnmpOpaque, SnmpCounter64
)

# Creation examples
integer_val = SnmpInteger(42)
string_val = SnmpOctetString("Hello World")
oid_val = SnmpObjectIdentifier("1.3.6.1.2.1.1.1.0")
ip_val = SnmpIpAddress("192.168.1.1")
counter_val = SnmpCounter32(1234567)
```

## 🔐 SNMPv3 Security Configurations

### Security Levels

1. **noAuthNoPriv**: No authentication, no privacy
2. **authNoPriv**: Authentication only
3. **authPriv**: Authentication + Privacy

### Authentication Protocols

- MD5
- SHA
- SHA224
- SHA256
- SHA384
- SHA512

### Privacy Protocols

- DES
- AES128
- AES192
- AES256

### Complete Configuration Example

```python
# Maximum security configuration
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
# Automatic connection management
with SnmpClient(host="192.168.1.100", community="public") as client:
    result = client.get("1.3.6.1.2.1.1.1.0")
    print(result)
# Connection is automatically closed
```

## 🐛 Debugging

```python
import logging

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)

# Or use the --debug flag in CLI
python snmpy.py --ip 192.168.1.200 --debug
```

## 🔍 Advanced Examples

### Automatic UPS Discovery

```python
monitor = UpsMonitor("192.168.1.200")
ups_type = monitor.detect_ups_type()
print(f"Detected UPS type: {ups_type}")

# Complete walk of UPS MIB
mib_data = monitor.walk_mib("1.3.6.1.2.1.33")
for oid, value in mib_data.items():
    print(f"{oid} = {value}")
```

### Error Handling

```python
try:
    result = client.get("1.3.6.1.2.1.1.1.0")
    if result is None:
        print("OID not found or communication error")
except Exception as e:
    print(f"Error: {e}")
```

### Multi-UPS Monitoring

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

The library includes detailed logging for debugging:

```python
import logging
logging.getLogger("Snmpy").setLevel(logging.INFO)
```

Log levels:
- `DEBUG`: Complete SNMP communication details
- `INFO`: Main operations
- `WARNING`: Non-critical issues
- `ERROR`: Communication errors

## 🤝 UPS Support

The library includes specialized support for:

- **APC UPS** (Enterprise OID 318)
- **Eaton UPS** (Enterprise OID 534)
- **CyberPower UPS** (Enterprise OID 3808)
- **Standard RFC 1628 UPS**

UPS type detection happens automatically.

## ⚠️ Security Notes

- **Don't use weak passwords** for SNMPv3
- **Avoid default community strings** like "public" in production
- **Always use HTTPS/VPN** for insecure networks
- **Limit SNMP access** with firewall/ACLs
- **Monitor logs** for unauthorized access attempts

## 📄 License

MIT License - See LICENSE file for details.

## 🛠️ Contributing

1. Fork the repository
2. Create a branch for your feature
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For bugs, feature requests or questions, open an issue on GitHub.

---

**Snmpy** - A powerful and flexible SNMP library for Python 🐍
