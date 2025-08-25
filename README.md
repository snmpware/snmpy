# SNMPY

A complete and advanced SNMP library for Python that supports SNMPv1, SNMPv2c and SNMPv3 with authentication, encryption, comprehensive trap handling, and packet decoding capabilities.

## 🚀 Features

- **Full support for SNMPv1, SNMPv2c and SNMPv3**
- **SNMPv3 Security**: Authentication (MD5, SHA, SHA224, SHA256, SHA384, SHA512) and Privacy (DES, AES128, AES192, AES256)
- **Complete SNMP operations**: GET, GETNEXT, GETBULK, SET, WALK
- **SNMP Trap Sender**: Send v1, v2c, and v3 traps/notifications
- **SNMP Packet Decoder**: Decode and analyze raw SNMP packets in hex format
- **Specialized UPS monitoring** with support for APC, Eaton, CyberPower
- **Native ASN.1 BER encoding/decoding**
- **Automatic SNMPv3 engine discovery**
- **Integrated logging** for debugging
- **CLI interface** for UPS monitoring, trap sending, and packet analysis
- **Context manager support** for automatic connection management

## 📦 Installation

### Dependencies

```bash
pip install pycryptodome
```

### Download

Download the `snmpy.py` file and include it in your project:

```python
from snmpy import (
    SnmpClient, SnmpVersion, SnmpV3User, 
    SnmpV3AuthProtocol, SnmpV3PrivProtocol,
    SnmpTrapSender, decode_snmp_hex
)
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

# Create an SNMPv3 user with full security
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

## 🔔 SNMP Trap Sender

### Send SNMPv2c Trap

```python
from snmpy import SnmpTrapSender, SnmpVersion, SnmpOctetString, SnmpInteger

# Create trap sender
sender = SnmpTrapSender(
    trap_host="192.168.1.10",  # Trap receiver IP
    trap_port=162,
    community="public",
    version=SnmpVersion.V2C
)

# Send a test trap
sender.send_test_trap("System alert: High CPU usage")

# Send standard traps
sender.send_cold_start()
sender.send_warm_start()
sender.send_link_down(if_index=2, if_descr="eth1")
sender.send_link_up(if_index=2, if_descr="eth1")
sender.send_authentication_failure()

# Send UPS-specific traps
sender.send_ups_trap(
    'on_battery',
    battery_charge=75,
    runtime=45,
    load_percent=80,
    message="Power failure detected"
)
```

### Send SNMPv1 Trap

```python
sender = SnmpTrapSender(
    trap_host="192.168.1.10",
    version=SnmpVersion.V1
)

# SNMPv1 trap with enterprise-specific parameters
sender.send_v1_trap(
    enterprise="1.3.6.1.4.1.318",  # APC enterprise OID
    agent_addr="192.168.1.100",
    generic_trap=6,  # enterpriseSpecific
    specific_trap=1,
    varbinds=[
        ("1.3.6.1.4.1.318.1.1.1.2.2.1.0", SnmpInteger(50)),  # Battery capacity
        ("1.3.6.1.4.1.318.1.1.1.4.2.3.0", SnmpInteger(75))   # Load percentage
    ]
)
```

### Send SNMPv3 Trap

```python
# Create SNMPv3 user
v3_user = SnmpV3User(
    username="trapuser",
    auth_protocol=SnmpV3AuthProtocol.SHA256,
    auth_password="authpass123"
)

# Create v3 trap sender
sender = SnmpTrapSender(
    trap_host="192.168.1.10",
    version=SnmpVersion.V3,
    v3_user=v3_user
)

# Send authenticated trap
sender.send_test_trap("Secure notification from SNMPv3")
```

### Custom Trap with Varbinds

```python
# Send custom trap with multiple variables
custom_oid = "1.3.6.1.4.1.99999.1.1"
varbinds = [
    ("1.3.6.1.4.1.99999.1.2", SnmpOctetString("Alert message")),
    ("1.3.6.1.4.1.99999.1.3", SnmpInteger(severity_level)),
    ("1.3.6.1.4.1.99999.1.4", SnmpOctetString(device_name))
]

sender.send_v2c_trap(custom_oid, varbinds=varbinds)
```

## 🔍 SNMP Packet Decoder

### Decode Raw SNMP Packets

```python
from snmpy import decode_snmp_hex

# Decode a raw SNMP packet in hex format
hex_packet = "3081a202010104067075626c6963a78194..."

# Print decoded information
decode_snmp_hex(hex_packet)

# Get decoded data as dictionary
decoded_data = decode_snmp_hex(hex_packet, return_dict=True)
print(f"Version: SNMPv{decoded_data['version']}")
print(f"Community: {decoded_data['community']}")
print(f"PDU Type: {decoded_data['pdu_type']}")

# Access varbinds
for varbind in decoded_data['varbinds']:
    print(f"  {varbind['oid']} = {varbind['value']}")
    if varbind['name']:
        print(f"    ({varbind['name']})")
```

### Analyze Trap Packets

```python
# Decode and analyze a trap packet
trap_hex = "your_trap_packet_hex_here"
decoded = decode_snmp_hex(trap_hex, return_dict=True)

if 'trap_type' in decoded:
    print(f"Trap Type: {decoded['trap_type']}")
    
# Check specific trap types
if decoded.get('trap_type') == 'coldStart':
    print("System has been restarted!")
elif decoded.get('trap_type') == 'linkDown':
    print("Network interface is down!")
```

## 🔋 UPS Monitoring

### Basic UPS Monitoring

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

# Continuous monitoring
monitor.monitor(interval=5.0, duration=3600)
```

### UPS with SNMPv3

```python
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
# Basic SNMPv2c monitoring
python snmpy.py monitor --ip 192.168.1.200 --version 2 --community public

# SNMPv3 with authentication
python snmpy.py monitor --ip 192.168.1.200 --version 3 \
    --v3-user admin \
    --v3-auth-protocol SHA256 \
    --v3-auth-password mypassword

# Test connection
python snmpy.py monitor --ip 192.168.1.200 --test

# SNMP Walk
python snmpy.py monitor --ip 192.168.1.200 --walk
```

### Trap Sending

```bash
# Interactive trap sender
python snmpy.py

# Send test trap
python snmpy.py trap --host 192.168.1.10 --type test --message "Test notification"

# Send cold start trap
python snmpy.py trap --host 192.168.1.10 --type coldstart

# Send link down trap
python snmpy.py trap --host 192.168.1.10 --type linkdown --interface 2

# Send UPS battery alert
python snmpy.py trap --host 192.168.1.10 --type ups-battery

# SNMPv3 trap
python snmpy.py trap --host 192.168.1.10 --version 3 \
    --v3-user trapuser \
    --v3-auth-protocol SHA \
    --v3-auth-password secret123 \
    --type test --message "Secure trap"
```

## 📊 Supported SNMP Data Types

```python
from snmpy import (
    SnmpInteger,          # 32-bit integer
    SnmpOctetString,      # String/bytes
    SnmpNull,             # Null value
    SnmpObjectIdentifier, # OID
    SnmpSequence,         # Sequence of values
    SnmpIpAddress,        # IPv4 address
    SnmpCounter32,        # 32-bit counter
    SnmpGauge32,          # 32-bit gauge
    SnmpTimeTicks,        # Time in centiseconds
    SnmpOpaque,           # Opaque data
    SnmpCounter64,        # 64-bit counter
    SnmpNoSuchObject,     # Error: no such object
    SnmpNoSuchInstance,   # Error: no such instance
    SnmpEndOfMibView      # End of MIB view
)

# Examples
integer_val = SnmpInteger(42)
string_val = SnmpOctetString("Hello World")
oid_val = SnmpObjectIdentifier("1.3.6.1.2.1.1.1.0")
ip_val = SnmpIpAddress("192.168.1.1")
counter_val = SnmpCounter32(1234567)
timeticks_val = SnmpTimeTicks(500000)  # 5000 seconds
```

## 🔐 SNMPv3 Security

### Security Levels

1. **noAuthNoPriv**: No authentication, no privacy
2. **authNoPriv**: Authentication only  
3. **authPriv**: Authentication + Privacy

### Authentication Protocols

- MD5 (128-bit)
- SHA (160-bit)
- SHA224 (224-bit)
- SHA256 (256-bit)
- SHA384 (384-bit)
- SHA512 (512-bit)

### Privacy Protocols

- DES (56-bit)
- AES128 (128-bit)
- AES192 (192-bit)
- AES256 (256-bit)

### Security Configuration Example

```python
# Maximum security configuration
user = SnmpV3User(
    username="secureuser",
    auth_protocol=SnmpV3AuthProtocol.SHA512,
    auth_password="very_secure_auth_password_123",
    priv_protocol=SnmpV3PrivProtocol.AES256,
    priv_password="very_secure_priv_password_456"
)

# Engine discovery is automatic
client = SnmpClient(host="192.168.1.100", version=SnmpVersion.V3, v3_user=user)
```

## 🏗️ Context Manager

```python
# Automatic connection management
with SnmpClient(host="192.168.1.100", community="public") as client:
    result = client.get("1.3.6.1.2.1.1.1.0")
    print(result)
# Connection is automatically closed

# Also works with trap sender
with SnmpTrapSender(trap_host="192.168.1.10") as sender:
    sender.send_test_trap("Context manager test")
```

## 🐛 Debugging

```python
import logging

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("AdvancedSnmp").setLevel(logging.DEBUG)

# Decode packets for debugging
hex_data = "3081a202010104067075626c6963..."
decode_snmp_hex(hex_data)  # Prints detailed packet structure
```

## 🔍 Advanced Examples

### Multi-Device Scanning

```python
devices = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

for device in devices:
    client = SnmpClient(host=device, community="public")
    try:
        sysname = client.get("1.3.6.1.2.1.1.5.0")
        print(f"{device}: {sysname}")
    except:
        print(f"{device}: No response")
```

### Packet Analysis for Network Troubleshooting

```python
# Capture and decode SNMP packets
def analyze_snmp_traffic(packet_hex):
    decoded = decode_snmp_hex(packet_hex, return_dict=True)
    
    # Check for errors
    if decoded.get('error_status', 0) != 0:
        print(f"Error detected: {decoded['error_status']}")
    
    # Analyze response times
    if 'timestamp' in decoded:
        print(f"Response time analysis needed")
    
    # Check for authentication failures
    if decoded.get('trap_type') == 'authenticationFailure':
        print("Security alert: Authentication failure detected!")
    
    return decoded
```

### Automated UPS Monitoring with Alerts

```python
def monitor_ups_with_alerts(host, threshold_battery=20, threshold_load=90):
    monitor = UpsMonitor(host)
    sender = SnmpTrapSender(trap_host="192.168.1.10")
    
    while True:
        info = monitor.get_ups_info()
        
        # Check battery
        if info['battery_charge'] and info['battery_charge'] < threshold_battery:
            sender.send_ups_trap('battery_low', 
                battery_charge=info['battery_charge'],
                message=f"Low battery on {host}")
        
        # Check load
        if info['load'] and info['load'] > threshold_load:
            sender.send_ups_trap('overload',
                load_percent=info['load'],
                message=f"High load on {host}")
        
        time.sleep(60)  # Check every minute
```

### Bulk Operations with Error Handling

```python
def bulk_config_backup(devices, oids_to_backup):
    results = {}
    
    for device in devices:
        results[device] = {}
        try:
            client = SnmpClient(host=device, community="private")
            
            # Get multiple values efficiently
            values = client.get_multiple(oids_to_backup)
            results[device] = values
            
            print(f"✓ {device}: Backed up {len(values)} OIDs")
        except Exception as e:
            print(f"✗ {device}: {e}")
            results[device] = {"error": str(e)}
    
    # Save to file
    with open('config_backup.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    return results
```

## 📝 Logging

The library includes comprehensive logging:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('snmp.log'),
        logging.StreamHandler()
    ]
)

# Set library log level
logging.getLogger("AdvancedSnmp").setLevel(logging.DEBUG)
```

Log levels:
- `DEBUG`: Complete SNMP communication details, packet dumps
- `INFO`: Main operations, trap events, discoveries
- `WARNING`: Non-critical issues, retries, timeouts
- `ERROR`: Communication errors, authentication failures

## 🤝 Device Support

### UPS Support
- **APC UPS** (Enterprise OID 318)
- **Eaton UPS** (Enterprise OID 534)
- **CyberPower UPS** (Enterprise OID 3808)
- **Standard RFC 1628 UPS MIB**

### Network Devices
- **Cisco** (Enterprise OID 9)
- **Juniper** (Enterprise OID 2636)
- **HP** (Enterprise OID 11)
- **Dell** (Enterprise OID 674)

UPS type detection happens automatically.

## 🔔 Trap Types

### Standard Traps
- `coldStart` - System reinitialized
- `warmStart` - System restarted
- `linkDown` - Interface down
- `linkUp` - Interface up
- `authenticationFailure` - Auth failed
- `egpNeighborLoss` - EGP neighbor lost

### UPS-Specific Traps
- `on_battery` - Running on battery
- `battery_low` - Battery critically low
- `battery_replaced` - Battery replaced
- `overload` - Load too high
- `temperature_high` - Over temperature
- `power_restored` - Mains power restored

### Custom Enterprise Traps
- Support for any enterprise OID
- Flexible varbind configuration
- Full v1/v2c/v3 compatibility

## ⚠️ Security Best Practices

1. **Use SNMPv3** for production environments
2. **Avoid default communities** like "public" or "private"
3. **Implement ACLs** to restrict SNMP access
4. **Use strong passwords** (minimum 12 characters)
5. **Enable encryption** (AES256) for sensitive data
6. **Monitor trap sources** to detect unauthorized access
7. **Rotate credentials** regularly
8. **Log all SNMP operations** for audit trails
9. **Use VPN/TLS tunnels** over untrusted networks
10. **Validate trap sources** before processing

## 🚀 Performance Tips

- Use **BULK operations** for SNMPv2c/v3 (up to 10x faster)
- **Cache engine IDs** for SNMPv3 to avoid repeated discovery
- **Reuse client connections** when polling multiple OIDs
- Set appropriate **timeout values** based on network latency
- Use **context managers** to ensure proper resource cleanup
- **Limit walk operations** to specific subtrees
- Implement **rate limiting** for trap sending

## 📄 License

MIT License - See LICENSE file for details.

## 🛠️ Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📈 Changelog

### Version 2.1.0 (Latest)
- Added SNMP packet decoder for hex analysis
- Improved trap timestamp handling (modulo for TimeTicks limits)
- Enhanced debugging capabilities
- Added packet structure visualization
- Fixed TimeTicks overflow issues

### Version 2.0.0
- Complete SNMP Trap Sender functionality
- Support for v1, v2c, and v3 traps
- UPS-specific trap templates
- Automatic engine ID generation
- Context manager support

### Version 1.0.0
- Initial release with full SNMPv1/v2c/v3 support
- Complete SNMP operations (GET, SET, WALK)
- UPS monitoring capabilities

## 📞 Support

For bugs, feature requests, or questions:
- Open an issue on [GitHub](https://github.com/yourusername/snmpy)
- Check existing issues before creating new ones
- Include debug logs when reporting bugs

## 🌟 Examples Repository

Find more examples and use cases at: [snmpy-examples](https://github.com/yourusername/snmpy-examples)

---

**SNMPY** - A powerful, secure, and flexible SNMP library for Python 🐍🔐📡

*Making SNMP simple, secure, and pythonic!*
