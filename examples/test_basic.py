#!/usr/bin/env python3
"""
Test di base per la libreria AdvancedSnmp
"""

import sys
import os
import unittest
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from snmpy import (
    SnmpInteger, SnmpOctetString, SnmpNull, SnmpObjectIdentifier,
    SnmpSequence, SnmpIpAddress, SnmpCounter32, SnmpGauge32,
    SnmpTimeTicks, SnmpClient, SnmpVersion, SnmpV3User,
    SnmpV3AuthProtocol, SnmpV3PrivProtocol, encode_length,
    decode_length, decode_tlv
)

class TestSnmpDataTypes(unittest.TestCase):
    """Test per i tipi di dati SNMP"""
    
    def test_snmp_integer(self):
        """Test SnmpInteger"""
        # Test numeri positivi
        int_pos = SnmpInteger(42)
        encoded = int_pos.encode()
        decoded, _ = SnmpInteger.decode(encoded, 0)
        self.assertEqual(decoded.value, 42)
        
        # Test numeri negativi
        int_neg = SnmpInteger(-123)
        encoded = int_neg.encode()
        decoded, _ = SnmpInteger.decode(encoded, 0)
        self.assertEqual(decoded.value, -123)
        
        # Test zero
        int_zero = SnmpInteger(0)
        encoded = int_zero.encode()
        decoded, _ = SnmpInteger.decode(encoded, 0)
        self.assertEqual(decoded.value, 0)
        
        # Test numeri grandi
        int_big = SnmpInteger(2147483647)
        encoded = int_big.encode()
        decoded, _ = SnmpInteger.decode(encoded, 0)
        self.assertEqual(decoded.value, 2147483647)
    
    def test_snmp_octet_string(self):
        """Test SnmpOctetString"""
        # Test stringa normale
        str_normal = SnmpOctetString("Hello World")
        encoded = str_normal.encode()
        decoded, _ = SnmpOctetString.decode(encoded, 0)
        self.assertEqual(decoded.value.decode('utf-8'), "Hello World")
        
        # Test stringa vuota
        str_empty = SnmpOctetString("")
        encoded = str_empty.encode()
        decoded, _ = SnmpOctetString.decode(encoded, 0)
        self.assertEqual(decoded.value.decode('utf-8'), "")
        
        # Test bytes
        str_bytes = SnmpOctetString(b'\x01\x02\x03\x04')
        encoded = str_bytes.encode()
        decoded, _ = SnmpOctetString.decode(encoded, 0)
        self.assertEqual(decoded.value, b'\x01\x02\x03\x04')
        
        # Test caratteri speciali
        str_special = SnmpOctetString("Test àèìòù 中文")
        encoded = str_special.encode()
        decoded, _ = SnmpOctetString.decode(encoded, 0)
        self.assertEqual(decoded.value.decode('utf-8'), "Test àèìòù 中文")
    
    def test_snmp_null(self):
        """Test SnmpNull"""
        null_obj = SnmpNull()
        encoded = null_obj.encode()
        decoded, _ = SnmpNull.decode(encoded, 0)
        self.assertIsNone(decoded.value)
    
    def test_snmp_object_identifier(self):
        """Test SnmpObjectIdentifier"""
        # Test da stringa
        oid_str = SnmpObjectIdentifier("1.3.6.1.2.1.1.1.0")
        encoded = oid_str.encode()
        decoded, _ = SnmpObjectIdentifier.decode(encoded, 0)
        self.assertEqual(decoded.value, [1, 3, 6, 1, 2, 1, 1, 1, 0])
        
        # Test da lista
        oid_list = SnmpObjectIdentifier([1, 3, 6, 1, 4, 1, 318, 1, 1, 1])
        encoded = oid_list.encode()
        decoded, _ = SnmpObjectIdentifier.decode(encoded, 0)
        self.assertEqual(decoded.value, [1, 3, 6, 1, 4, 1, 318, 1, 1, 1])
        
        # Test OID complessi con numeri grandi
        oid_big = SnmpObjectIdentifier("1.3.6.1.4.1.9999.123456.789")
        encoded = oid_big.encode()
        decoded, _ = SnmpObjectIdentifier.decode(encoded, 0)
        self.assertEqual(decoded.value, [1, 3, 6, 1, 4, 1, 9999, 123456, 789])
    
    def test_snmp_ip_address(self):
        """Test SnmpIpAddress"""
        # Test da stringa
        ip_str = SnmpIpAddress("192.168.1.1")
        encoded = ip_str.encode()
        decoded, _ = SnmpIpAddress.decode(encoded, 0)
        self.assertEqual(decoded.value, b'\xc0\xa8\x01\x01')  # 192.168.1.1 in bytes
        
        # Test da bytes
        ip_bytes = SnmpIpAddress(b'\x08\x08\x08\x08')  # 8.8.8.8
        encoded = ip_bytes.encode()
        decoded, _ = SnmpIpAddress.decode(encoded, 0)
        self.assertEqual(decoded.value, b'\x08\x08\x08\x08')
        
        # Test da lista
        ip_list = SnmpIpAddress([10, 0, 0, 1])
        encoded = ip_list.encode()
        decoded, _ = SnmpIpAddress.decode(encoded, 0)
        self.assertEqual(decoded.value, b'\x0a\x00\x00\x01')  # 10.0.0.1
    
    def test_snmp_counter32(self):
        """Test SnmpCounter32"""
        # Test valore normale
        counter = SnmpCounter32(12345)
        encoded = counter.encode()
        decoded, _ = SnmpCounter32.decode(encoded, 0)
        self.assertEqual(decoded.value, 12345)
        
        # Test valore massimo
        counter_max = SnmpCounter32(4294967295)  # 2^32 - 1
        encoded = counter_max.encode()
        decoded, _ = SnmpCounter32.decode(encoded, 0)
        self.assertEqual(decoded.value, 4294967295)
        
        # Test zero
        counter_zero = SnmpCounter32(0)
        encoded = counter_zero.encode()
        decoded, _ = SnmpCounter32.decode(encoded, 0)
        self.assertEqual(decoded.value, 0)
        
        # Test valore fuori range
        with self.assertRaises(ValueError):
            SnmpCounter32(-1)
        
        with self.assertRaises(ValueError):
            SnmpCounter32(4294967296)
    
    def test_snmp_gauge32(self):
        """Test SnmpGauge32"""
        gauge = SnmpGauge32(99)
        encoded = gauge.encode()
        decoded, _ = SnmpGauge32.decode(encoded, 0)
        self.assertEqual(decoded.value, 99)
    
    def test_snmp_time_ticks(self):
        """Test SnmpTimeTicks"""
        # Test valore normale
        ticks = SnmpTimeTicks(8640000)  # 1 giorno in centesimi di secondo
        encoded = ticks.encode()
        decoded, _ = SnmpTimeTicks.decode(encoded, 0)
        self.assertEqual(decoded.value, 8640000)
        
        # Verifica la conversione stringa
        str_repr = str(ticks)
        self.assertIn("1d", str_repr)
    
    def test_snmp_sequence(self):
        """Test SnmpSequence"""
        # Crea una sequenza con diversi tipi
        seq_items = [
            SnmpInteger(42),
            SnmpOctetString("test"),
            SnmpObjectIdentifier("1.3.6.1.2.1.1.1.0"),
            SnmpNull()
        ]
        
        sequence = SnmpSequence(seq_items)
        encoded = sequence.encode()
        decoded, _ = SnmpSequence.decode(encoded, 0)
        
        self.assertEqual(len(decoded.value), 4)
        self.assertEqual(decoded.value[0].value, 42)
        self.assertEqual(decoded.value[1].value.decode('utf-8'), "test")
        self.assertEqual(decoded.value[2].value, [1, 3, 6, 1, 2, 1, 1, 1, 0])
        self.assertIsNone(decoded.value[3].value)

class TestSnmpV3User(unittest.TestCase):
    """Test per utenti SNMPv3"""
    
    def test_user_creation(self):
        """Test creazione utente SNMPv3"""
        # Utente senza autenticazione
        user_noauth = SnmpV3User("testuser")
        self.assertEqual(user_noauth.username, "testuser")
        self.assertEqual(user_noauth.auth_protocol, SnmpV3AuthProtocol.NO_AUTH)
        self.assertEqual(user_noauth.priv_protocol, SnmpV3PrivProtocol.NO_PRIV)
        self.assertIsNone(user_noauth.auth_key)
        self.assertIsNone(user_noauth.priv_key)
        
        # Utente con autenticazione
        user_auth = SnmpV3User(
            "authuser",
            auth_protocol=SnmpV3AuthProtocol.SHA256,
            auth_password="testpassword123"
        )
        self.assertEqual(user_auth.username, "authuser")
        self.assertEqual(user_auth.auth_protocol, SnmpV3AuthProtocol.SHA256)
        self.assertIsNotNone(user_auth.auth_key)
        self.assertEqual(len(user_auth.auth_key), 32)  # SHA256 = 32 bytes
        
        # Utente con autenticazione e privacy
        user_full = SnmpV3User(
            "fulluser",
            auth_protocol=SnmpV3AuthProtocol.SHA,
            auth_password="authpass123",
            priv_protocol=SnmpV3PrivProtocol.AES128,
            priv_password="privpass123"
        )
        self.assertEqual(user_full.username, "fulluser")
        self.assertIsNotNone(user_full.auth_key)
        self.assertIsNotNone(user_full.priv_key)
        self.assertEqual(len(user_full.auth_key), 20)  # SHA = 20 bytes
        self.assertEqual(len(user_full.priv_key), 20)
    
    def test_security_levels(self):
        """Test livelli di sicurezza"""
        from snmpy import SnmpV3SecurityLevel
        
        # noAuthNoPriv
        user1 = SnmpV3User("user1")
        self.assertEqual(user1.get_security_level(), SnmpV3SecurityLevel.NO_AUTH_NO_PRIV)
        
        # authNoPriv
        user2 = SnmpV3User("user2", auth_protocol=SnmpV3AuthProtocol.MD5, auth_password="pass")
        self.assertEqual(user2.get_security_level(), SnmpV3SecurityLevel.AUTH_NO_PRIV)
        
        # authPriv
        user3 = SnmpV3User(
            "user3",
            auth_protocol=SnmpV3AuthProtocol.SHA,
            auth_password="authpass",
            priv_protocol=SnmpV3PrivProtocol.DES,
            priv_password="privpass"
        )
        self.assertEqual(user3.get_security_level(), SnmpV3SecurityLevel.AUTH_PRIV)
    
    def test_key_localization(self):
        """Test localizzazione chiavi"""
        user = SnmpV3User(
            "testuser",
            auth_protocol=SnmpV3AuthProtocol.SHA,
            auth_password="testpassword"
        )
        
        # Test localizzazione chiave
        engine_id = b'\x80\x00\x13\x70\x03\x00\x11\x22\x33\x44'
        localized_key = user.localize_key(engine_id, user.auth_key)
        
        self.assertIsNotNone(localized_key)
        self.assertEqual(len(localized_key), len(user.auth_key))
        self.assertNotEqual(localized_key, user.auth_key)  # Deve essere diversa

class TestBerEncoding(unittest.TestCase):
    """Test per la codifica/decodifica BER"""
    
    def test_length_encoding(self):
        """Test codifica lunghezze"""
        # Lunghezza corta (< 128)
        short_len = encode_length(42)
        self.assertEqual(short_len, b'\x2a')
        
        decoded_len, offset = decode_length(short_len, 0)
        self.assertEqual(decoded_len, 42)
        self.assertEqual(offset, 1)
        
        # Lunghezza lunga (>= 128)
        long_len = encode_length(300)
        decoded_len, offset = decode_length(long_len, 0)
        self.assertEqual(decoded_len, 300)
        
        # Lunghezza molto lunga
        very_long_len = encode_length(65536)
        decoded_len, offset = decode_length(very_long_len, 0)
        self.assertEqual(decoded_len, 65536)
    
    def test_tlv_encoding(self):
        """Test codifica/decodifica TLV"""
        # Crea un TLV semplice
        tag = 0x02  # INTEGER
        value = b'\x01\x02\x03'
        
        # Costruisci manualmente il TLV
        tlv_data = bytes([tag]) + encode_length(len(value)) + value
        
        # Decodifica
        decoded_tag, decoded_value, offset = decode_tlv(tlv_data, 0)
        
        self.assertEqual(decoded_tag, tag)
        self.assertEqual(decoded_value, value)
        self.assertEqual(offset, len(tlv_data))

class TestSnmpClientMock(unittest.TestCase):
    """Test per SnmpClient con dati mock"""
    
    def setUp(self):
        """Setup per i test"""
        self.mock_host = "127.0.0.1"  # Localhost per test
        self.client = SnmpClient(
            host=self.mock_host,
            community="public",
            version=SnmpVersion.V2C,
            timeout=1.0,
            retries=1
        )
    
    def test_client_creation(self):
        """Test creazione client"""
        self.assertEqual(self.client.host, self.mock_host)
        self.assertEqual(self.client.community, "public")
        self.assertEqual(self.client.version, SnmpVersion.V2C)
        self.assertEqual(self.client.timeout, 1.0)
        self.assertEqual(self.client.retries, 1)
    
    def test_request_id_generation(self):
        """Test generazione ID richiesta"""
        id1 = self.client._get_next_request_id()
        id2 = self.client._get_next_request_id()
        
        self.assertNotEqual(id1, id2)
        self.assertGreater(id2, id1)
    
    def test_context_manager(self):
        """Test context manager"""
        with SnmpClient(host=self.mock_host, community="public") as client:
            self.assertIsNotNone(client)
            # Il socket viene creato al primo utilizzo
            # Qui non possiamo testare molto senza un server SNMP reale

class TestDataValidation(unittest.TestCase):
    """Test per la validazione dei dati"""
    
    def test_counter32_validation(self):
        """Test validazione Counter32"""
        # Valori validi
        SnmpCounter32(0)
        SnmpCounter32(4294967295)
        
        # Valori non validi
        with self.assertRaises(ValueError):
            SnmpCounter32(-1)
        
        with self.assertRaises(ValueError):
            SnmpCounter32(4294967296)
    
    def test_gauge32_validation(self):
        """Test validazione Gauge32"""
        # Valori validi
        SnmpGauge32(0)
        SnmpGauge32(4294967295)
        
        # Valori non validi
        with self.assertRaises(ValueError):
            SnmpGauge32(-1)
        
        with self.assertRaises(ValueError):
            SnmpGauge32(4294967296)
    
    def test_time_ticks_validation(self):
        """Test validazione TimeTicks"""
        # Valori validi
        SnmpTimeTicks(0)
        SnmpTimeTicks(4294967295)
        
        # Valori non validi
        with self.assertRaises(ValueError):
            SnmpTimeTicks(-1)
        
        with self.assertRaises(ValueError):
            SnmpTimeTicks(4294967296)

class TestStringRepresentations(unittest.TestCase):
    """Test per le rappresentazioni stringa"""
    
    def test_integer_str(self):
        """Test rappresentazione stringa SnmpInteger"""
        int_obj = SnmpInteger(42)
        str_repr = str(int_obj)
        self.assertIn("42", str_repr)
        self.assertIn("SnmpInteger", str_repr)
    
    def test_octet_string_str(self):
        """Test rappresentazione stringa SnmpOctetString"""
        str_obj = SnmpOctetString("test")
        str_repr = str(str_obj)
        self.assertIn("test", str_repr)
        self.assertIn("SnmpOctetString", str_repr)
        
        # Test con bytes non stampabili
        bytes_obj = SnmpOctetString(b'\x01\x02\x03')
        str_repr = str(bytes_obj)
        self.assertIn("SnmpOctetString", str_repr)
    
    def test_oid_str(self):
        """Test rappresentazione stringa SnmpObjectIdentifier"""
        oid_obj = SnmpObjectIdentifier("1.3.6.1.2.1.1.1.0")
        str_repr = str(oid_obj)
        self.assertIn("1.3.6.1.2.1.1.1.0", str_repr)
        self.assertIn("SnmpObjectIdentifier", str_repr)
    
    def test_ip_address_str(self):
        """Test rappresentazione stringa SnmpIpAddress"""
        ip_obj = SnmpIpAddress("192.168.1.1")
        str_repr = str(ip_obj)
        self.assertIn("192.168.1.1", str_repr)
        self.assertIn("SnmpIpAddress", str_repr)
    
    def test_time_ticks_str(self):
        """Test rappresentazione stringa SnmpTimeTicks"""
        # 1 giorno = 8640000 centesimi di secondo
        ticks_obj = SnmpTimeTicks(8640000)
        str_repr = str(ticks_obj)
        self.assertIn("1d", str_repr)
        self.assertIn("SnmpTimeTicks", str_repr)

def run_tests():
    """Esegui tutti i test"""
    print("Esecuzione Test AdvancedSnmp")
    print("=" * 50)
    
    # Crea test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Aggiungi test classes
    test_classes = [
        TestSnmpDataTypes,
        TestSnmpV3User,
        TestBerEncoding,
        TestSnmpClientMock,
        TestDataValidation,
        TestStringRepresentations
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Esegui i test
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Riassunto
    print("\n" + "=" * 50)
    print(f"Test eseguiti: {result.testsRun}")
    print(f"Falliti: {len(result.failures)}")
    print(f"Errori: {len(result.errors)}")
    
    if result.failures:
        print("\nFallimenti:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nErrori:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nRisultato: {'✓ TUTTI I TEST PASSATI' if success else '✗ ALCUNI TEST FALLITI'}")
    
    return success

def benchmark_encoding():
    """Benchmark delle operazioni di codifica/decodifica"""
    print("\nBenchmark Prestazioni")
    print("=" * 30)
    
    # Test Integer
    start_time = time.time()
    for i in range(10000):
        int_obj = SnmpInteger(i)
        encoded = int_obj.encode()
        decoded, _ = SnmpInteger.decode(encoded, 0)
    int_time = time.time() - start_time
    print(f"Integer (10k): {int_time:.3f}s")
    
    # Test OctetString
    start_time = time.time()
    for i in range(10000):
        str_obj = SnmpOctetString(f"test string {i}")
        encoded = str_obj.encode()
        decoded, _ = SnmpOctetString.decode(encoded, 0)
    str_time = time.time() - start_time
    print(f"OctetString (10k): {str_time:.3f}s")
    
    # Test OID
    start_time = time.time()
    for i in range(1000):
        oid_obj = SnmpObjectIdentifier(f"1.3.6.1.2.1.1.{i}.0")
        encoded = oid_obj.encode()
        decoded, _ = SnmpObjectIdentifier.decode(encoded, 0)
    oid_time = time.time() - start_time
    print(f"ObjectIdentifier (1k): {oid_time:.3f}s")
    
    print(f"\nPrestazioni complessive: OK")

if __name__ == "__main__":
    success = run_tests()
    
    if success:
        benchmark_encoding()
    
    print("\nPer test con dispositivi reali, modifica gli IP negli esempi")
    print("e usa: python examples/basic_usage.py")
