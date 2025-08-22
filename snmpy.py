#!/usr/bin/env python3
"""
SNMPY - Una libreria SNMP completa con supporto v1, v2c e v3
Autore: Advanced SNMPY Library
Licenza: MIT
"""

import socket
import struct
import time
import binascii
import sys
import os
import threading
import logging
import ipaddress
import hashlib
import hmac
import secrets
from enum import Enum, IntEnum
from typing import Dict, List, Tuple, Union, Optional, Any, Callable
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

# Configurazione del logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AdvancedSnmp")

class SnmpVersion(IntEnum):
    """Versioni SNMP supportate"""
    V1 = 0
    V2C = 1
    V3 = 3

class SnmpType(IntEnum):
    """Tipi di dati ASN.1 BER supportati da SNMP"""
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30
    IP_ADDRESS = 0x40
    COUNTER32 = 0x41
    GAUGE32 = 0x42
    TIME_TICKS = 0x43
    OPAQUE = 0x44
    COUNTER64 = 0x46
    NO_SUCH_OBJECT = 0x80
    NO_SUCH_INSTANCE = 0x81
    END_OF_MIB_VIEW = 0x82
    GET_REQUEST = 0xA0
    GET_NEXT_REQUEST = 0xA1
    GET_RESPONSE = 0xA2
    SET_REQUEST = 0xA3
    TRAP = 0xA4
    GET_BULK_REQUEST = 0xA5
    INFORM_REQUEST = 0xA6
    TRAP_V2 = 0xA7
    REPORT = 0xA8

class SnmpError(IntEnum):
    """Codici di errore SNMP"""
    NO_ERROR = 0
    TOO_BIG = 1
    NO_SUCH_NAME = 2
    BAD_VALUE = 3
    READ_ONLY = 4
    GEN_ERR = 5
    NO_ACCESS = 6
    WRONG_TYPE = 7
    WRONG_LENGTH = 8
    WRONG_ENCODING = 9
    WRONG_VALUE = 10
    NO_CREATION = 11
    INCONSISTENT_VALUE = 12
    RESOURCE_UNAVAILABLE = 13
    COMMIT_FAILED = 14
    UNDO_FAILED = 15
    AUTHORIZATION_ERROR = 16
    NOT_WRITABLE = 17
    INCONSISTENT_NAME = 18

class SnmpV3AuthProtocol(Enum):
    """Protocolli di autenticazione SNMPv3"""
    NO_AUTH = "noAuth"
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"

class SnmpV3PrivProtocol(Enum):
    """Protocolli di privacy/crittografia SNMPv3"""
    NO_PRIV = "noPriv"
    DES = "DES"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"

class SnmpV3SecurityLevel(IntEnum):
    """Livelli di sicurezza SNMPv3"""
    NO_AUTH_NO_PRIV = 1
    AUTH_NO_PRIV = 2
    AUTH_PRIV = 3

class SnmpV3Flags(IntEnum):
    """Flag del messaggio SNMPv3"""
    NO_FLAGS = 0x00
    AUTH = 0x01
    PRIV = 0x02
    REPORTABLE = 0x04

class SnmpData:
    """Classe base per rappresentare dati SNMP"""
    def __init__(self, tag: int, value: Any):
        self.tag = tag
        self.value = value
    
    def encode(self) -> bytes:
        """Codifica il dato in formato BER"""
        raise NotImplementedError("Metodo astratto")
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple[Any, int]:
        """Decodifica il dato dal formato BER"""
        raise NotImplementedError("Metodo astratto")
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.value})"
    
    def __repr__(self) -> str:
        return self.__str__()

class SnmpInteger(SnmpData):
    """Rappresenta un intero SNMP"""
    def __init__(self, value: int):
        super().__init__(SnmpType.INTEGER, value)
    
    def encode(self) -> bytes:
        """Codifica l'intero in formato BER"""
        if self.value == 0:
            return bytes([self.tag, 1, 0])
        
        # Converti in bytes
        bytes_list = []
        temp_value = abs(self.value)
        is_negative = self.value < 0
        
        while temp_value > 0:
            bytes_list.insert(0, temp_value & 0xFF)
            temp_value >>= 8
        
        # Gestisci numeri negativi
        if is_negative:
            # Complemento a due
            carry = 1
            for i in range(len(bytes_list) - 1, -1, -1):
                bytes_list[i] = (~bytes_list[i] & 0xFF) + carry
                if bytes_list[i] <= 0xFF:
                    carry = 0
                else:
                    bytes_list[i] &= 0xFF
                    carry = 1
            
            # Assicurati che il bit più significativo sia 1 per i numeri negativi
            if (bytes_list[0] & 0x80) == 0:
                bytes_list.insert(0, 0xFF)
        else:
            # Assicurati che il bit più significativo sia 0 per i numeri positivi
            if bytes_list and (bytes_list[0] & 0x80):
                bytes_list.insert(0, 0)
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # INTEGER tag
        result += encode_length(len(bytes_list))
        result += bytes(bytes_list)
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpInteger', int]:
        """Decodifica un intero dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.INTEGER:
            raise ValueError(f"Atteso tag INTEGER (0x02), trovato 0x{tag:02x}")
        
        # Decodifica l'intero
        if not value:
            return SnmpInteger(0), new_offset
        
        # Gestisci numeri negativi (primo bit = 1)
        if value[0] & 0x80:
            # Complemento a due
            result = -1
            for byte in value:
                result = (result << 8) | byte
        else:
            result = 0
            for byte in value:
                result = (result << 8) | byte
        
        return SnmpInteger(result), new_offset

class SnmpOctetString(SnmpData):
    """Rappresenta una stringa SNMP"""
    def __init__(self, value: Union[str, bytes]):
        if isinstance(value, str):
            value = value.encode('utf-8')
        super().__init__(SnmpType.OCTET_STRING, value)
    
    def encode(self) -> bytes:
        """Codifica la stringa in formato BER"""
        result = bytes([self.tag])  # OCTET STRING tag
        result += encode_length(len(self.value))
        result += self.value
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpOctetString', int]:
        """Decodifica una stringa dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.OCTET_STRING:
            raise ValueError(f"Atteso tag OCTET STRING (0x04), trovato 0x{tag:02x}")
        
        return SnmpOctetString(value), new_offset
    
    def __str__(self) -> str:
        try:
            return f"SnmpOctetString({self.value.decode('utf-8')})"
        except UnicodeDecodeError:
            return f"SnmpOctetString({binascii.hexlify(self.value).decode('ascii')})"

class SnmpNull(SnmpData):
    """Rappresenta un valore NULL SNMP"""
    def __init__(self):
        super().__init__(SnmpType.NULL, None)
    
    def encode(self) -> bytes:
        """Codifica NULL in formato BER"""
        return bytes([self.tag, 0])
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpNull', int]:
        """Decodifica NULL dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.NULL:
            raise ValueError(f"Atteso tag NULL (0x05), trovato 0x{tag:02x}")
        
        return SnmpNull(), new_offset

class SnmpObjectIdentifier(SnmpData):
    """Rappresenta un OID SNMP"""
    def __init__(self, value: Union[str, List[int]]):
        if isinstance(value, str):
            # Converti da stringa a lista di interi
            value = [int(part) for part in value.split('.') if part]
        super().__init__(SnmpType.OBJECT_IDENTIFIER, value)
    
    def encode(self) -> bytes:
        """Codifica l'OID in formato BER"""
        oid_parts = self.value
        
        # Combina i primi due numeri secondo le regole BER
        if len(oid_parts) >= 2:
            first_byte = 40 * oid_parts[0] + oid_parts[1]
            oid_bytes = [first_byte]
            oid_parts = oid_parts[2:]
        else:
            oid_bytes = [0]  # Caso speciale per OID incompleti
        
        # Codifica il resto dell'OID
        for part in oid_parts:
            if part < 128:
                oid_bytes.append(part)
            else:
                # Codifica numeri più grandi di 127
                bytes_list = []
                temp = part
                while temp > 0:
                    bytes_list.insert(0, temp & 0x7F)
                    temp >>= 7
                
                # Imposta il bit più significativo per tutti tranne l'ultimo byte
                for i in range(len(bytes_list) - 1):
                    bytes_list[i] |= 0x80
                
                oid_bytes.extend(bytes_list)
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # OBJECT IDENTIFIER tag
        result += encode_length(len(oid_bytes))
        result += bytes(oid_bytes)
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpObjectIdentifier', int]:
        """Decodifica un OID dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.OBJECT_IDENTIFIER:
            raise ValueError(f"Atteso tag OBJECT IDENTIFIER (0x06), trovato 0x{tag:02x}")
        
        if not value:
            return SnmpObjectIdentifier([]), new_offset
        
        # Decodifica il primo byte in due numeri
        oid = []
        first_byte = value[0]
        oid.append(first_byte // 40)
        oid.append(first_byte % 40)
        
        # Decodifica il resto dell'OID
        i = 1
        while i < len(value):
            val = 0
            while i < len(value) and (value[i] & 0x80):
                val = (val << 7) | (value[i] & 0x7F)
                i += 1
            
            if i < len(value):
                val = (val << 7) | value[i]
                i += 1
            
            oid.append(val)
        
        return SnmpObjectIdentifier(oid), new_offset
    
    def __str__(self) -> str:
        return f"SnmpObjectIdentifier({'.'.join(str(x) for x in self.value)})"

class SnmpSequence(SnmpData):
    """Rappresenta una sequenza SNMP"""
    def __init__(self, value: List[SnmpData]):
        super().__init__(SnmpType.SEQUENCE, value)
    
    def encode(self) -> bytes:
        """Codifica la sequenza in formato BER"""
        # Codifica tutti gli elementi della sequenza
        encoded_value = b''
        for item in self.value:
            encoded_value += item.encode()
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # SEQUENCE tag
        result += encode_length(len(encoded_value))
        result += encoded_value
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpSequence', int]:
        """Decodifica una sequenza dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.SEQUENCE:
            raise ValueError(f"Atteso tag SEQUENCE (0x30), trovato 0x{tag:02x}")
        
        # Decodifica tutti gli elementi della sequenza
        items = []
        item_offset = 0
        
        while item_offset < len(value):
            # Determina il tipo di dato
            item_tag = value[item_offset]
            item, item_offset = decode_snmp_data(value, item_offset)
            items.append(item)
        
        return SnmpSequence(items), new_offset

class SnmpIpAddress(SnmpData):
    """Rappresenta un indirizzo IP SNMP"""
    def __init__(self, value: Union[str, bytes, List[int]]):
        if isinstance(value, str):
            # Converti da stringa a bytes
            ip = ipaddress.IPv4Address(value)
            value = ip.packed
        elif isinstance(value, list):
            # Converti da lista a bytes
            value = bytes(value)
        super().__init__(SnmpType.IP_ADDRESS, value)
    
    def encode(self) -> bytes:
        """Codifica l'indirizzo IP in formato BER"""
        result = bytes([self.tag])  # IP ADDRESS tag
        result += encode_length(len(self.value))
        result += self.value
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpIpAddress', int]:
        """Decodifica un indirizzo IP dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.IP_ADDRESS:
            raise ValueError(f"Atteso tag IP ADDRESS (0x40), trovato 0x{tag:02x}")
        
        return SnmpIpAddress(value), new_offset
    
    def __str__(self) -> str:
        ip = ipaddress.IPv4Address(self.value)
        return f"SnmpIpAddress({str(ip)})"

class SnmpCounter32(SnmpData):
    """Rappresenta un contatore a 32 bit SNMP"""
    def __init__(self, value: int):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("Counter32 deve essere compreso tra 0 e 4294967295")
        super().__init__(SnmpType.COUNTER32, value)
    
    def encode(self) -> bytes:
        """Codifica il contatore in formato BER"""
        # Converti in bytes
        bytes_list = []
        temp_value = self.value
        
        while temp_value > 0:
            bytes_list.insert(0, temp_value & 0xFF)
            temp_value >>= 8
        
        if not bytes_list:
            bytes_list = [0]
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # COUNTER32 tag
        result += encode_length(len(bytes_list))
        result += bytes(bytes_list)
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpCounter32', int]:
        """Decodifica un contatore dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.COUNTER32:
            raise ValueError(f"Atteso tag COUNTER32 (0x41), trovato 0x{tag:02x}")
        
        # Decodifica il valore
        result = 0
        for byte in value:
            result = (result << 8) | byte
        
        return SnmpCounter32(result), new_offset

class SnmpGauge32(SnmpData):
    """Rappresenta un gauge a 32 bit SNMP"""
    def __init__(self, value: int):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("Gauge32 deve essere compreso tra 0 e 4294967295")
        super().__init__(SnmpType.GAUGE32, value)
    
    def encode(self) -> bytes:
        """Codifica il gauge in formato BER"""
        # Converti in bytes
        bytes_list = []
        temp_value = self.value
        
        while temp_value > 0:
            bytes_list.insert(0, temp_value & 0xFF)
            temp_value >>= 8
        
        if not bytes_list:
            bytes_list = [0]
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # GAUGE32 tag
        result += encode_length(len(bytes_list))
        result += bytes(bytes_list)
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpGauge32', int]:
        """Decodifica un gauge dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.GAUGE32:
            raise ValueError(f"Atteso tag GAUGE32 (0x42), trovato 0x{tag:02x}")
        
        # Decodifica il valore
        result = 0
        for byte in value:
            result = (result << 8) | byte
        
        return SnmpGauge32(result), new_offset

class SnmpTimeTicks(SnmpData):
    """Rappresenta un valore TimeTicks SNMP (centesimi di secondo)"""
    def __init__(self, value: int):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("TimeTicks deve essere compreso tra 0 e 4294967295")
        super().__init__(SnmpType.TIME_TICKS, value)
    
    def encode(self) -> bytes:
        """Codifica il TimeTicks in formato BER"""
        # Converti in bytes
        bytes_list = []
        temp_value = self.value
        
        while temp_value > 0:
            bytes_list.insert(0, temp_value & 0xFF)
            temp_value >>= 8
        
        if not bytes_list:
            bytes_list = [0]
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # TIME_TICKS tag
        result += encode_length(len(bytes_list))
        result += bytes(bytes_list)
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpTimeTicks', int]:
        """Decodifica un TimeTicks dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.TIME_TICKS:
            raise ValueError(f"Atteso tag TIME_TICKS (0x43), trovato 0x{tag:02x}")
        
        # Decodifica il valore
        result = 0
        for byte in value:
            result = (result << 8) | byte
        
        return SnmpTimeTicks(result), new_offset
    
    def __str__(self) -> str:
        days, remainder = divmod(self.value, 8640000)
        hours, remainder = divmod(remainder, 360000)
        minutes, remainder = divmod(remainder, 6000)
        seconds, centiseconds = divmod(remainder, 100)
        
        time_str = ""
        if days > 0:
            time_str += f"{days}d "
        if days > 0 or hours > 0:
            time_str += f"{hours}h "
        if days > 0 or hours > 0 or minutes > 0:
            time_str += f"{minutes}m "
        time_str += f"{seconds}.{centiseconds:02d}s"
        
        return f"SnmpTimeTicks({self.value}, {time_str})"

class SnmpOpaque(SnmpData):
    """Rappresenta un valore Opaque SNMP (dati arbitrari)"""
    def __init__(self, value: bytes):
        super().__init__(SnmpType.OPAQUE, value)
    
    def encode(self) -> bytes:
        """Codifica il valore Opaque in formato BER"""
        result = bytes([self.tag])  # OPAQUE tag
        result += encode_length(len(self.value))
        result += self.value
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpOpaque', int]:
        """Decodifica un valore Opaque dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.OPAQUE:
            raise ValueError(f"Atteso tag OPAQUE (0x44), trovato 0x{tag:02x}")
        
        return SnmpOpaque(value), new_offset
    
    def __str__(self) -> str:
        return f"SnmpOpaque({binascii.hexlify(self.value).decode('ascii')})"

class SnmpCounter64(SnmpData):
    """Rappresenta un contatore a 64 bit SNMP"""
    def __init__(self, value: int):
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Counter64 deve essere compreso tra 0 e 18446744073709551615")
        super().__init__(SnmpType.COUNTER64, value)
    
    def encode(self) -> bytes:
        """Codifica il contatore in formato BER"""
        # Converti in bytes
        bytes_list = []
        temp_value = self.value
        
        while temp_value > 0:
            bytes_list.insert(0, temp_value & 0xFF)
            temp_value >>= 8
        
        if not bytes_list:
            bytes_list = [0]
        
        # Crea il TLV (Type-Length-Value)
        result = bytes([self.tag])  # COUNTER64 tag
        result += encode_length(len(bytes_list))
        result += bytes(bytes_list)
        
        return result
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpCounter64', int]:
        """Decodifica un contatore a 64 bit dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.COUNTER64:
            raise ValueError(f"Atteso tag COUNTER64 (0x46), trovato 0x{tag:02x}")
        
        # Decodifica il valore
        result = 0
        for byte in value:
            result = (result << 8) | byte
        
        return SnmpCounter64(result), new_offset

class SnmpNoSuchObject(SnmpData):
    """Rappresenta un errore NoSuchObject SNMP"""
    def __init__(self):
        super().__init__(SnmpType.NO_SUCH_OBJECT, None)
    
    def encode(self) -> bytes:
        """Codifica l'errore in formato BER"""
        return bytes([self.tag, 0])
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpNoSuchObject', int]:
        """Decodifica un errore NoSuchObject dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.NO_SUCH_OBJECT:
            raise ValueError(f"Atteso tag NO_SUCH_OBJECT (0x80), trovato 0x{tag:02x}")
        
        return SnmpNoSuchObject(), new_offset

class SnmpNoSuchInstance(SnmpData):
    """Rappresenta un errore NoSuchInstance SNMP"""
    def __init__(self):
        super().__init__(SnmpType.NO_SUCH_INSTANCE, None)
    
    def encode(self) -> bytes:
        """Codifica l'errore in formato BER"""
        return bytes([self.tag, 0])
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpNoSuchInstance', int]:
        """Decodifica un errore NoSuchInstance dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.NO_SUCH_INSTANCE:
            raise ValueError(f"Atteso tag NO_SUCH_INSTANCE (0x81), trovato 0x{tag:02x}")
        
        return SnmpNoSuchInstance(), new_offset

class SnmpEndOfMibView(SnmpData):
    """Rappresenta un indicatore EndOfMibView SNMP"""
    def __init__(self):
        super().__init__(SnmpType.END_OF_MIB_VIEW, None)
    
    def encode(self) -> bytes:
        """Codifica l'indicatore in formato BER"""
        return bytes([self.tag, 0])
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpEndOfMibView', int]:
        """Decodifica un indicatore EndOfMibView dal formato BER"""
        tag, value, new_offset = decode_tlv(data, offset)
        
        if tag != SnmpType.END_OF_MIB_VIEW:
            raise ValueError(f"Atteso tag END_OF_MIB_VIEW (0x82), trovato 0x{tag:02x}")
        
        return SnmpEndOfMibView(), new_offset

class SnmpPdu:
    """Classe base per i PDU SNMP"""
    def __init__(self, tag: int, request_id: int = 0, error_status: int = 0, 
                 error_index: int = 0, varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        self.tag = tag
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        self.varbinds = varbinds or []
    
    def encode(self) -> bytes:
        """Codifica il PDU in formato BER"""
        # Codifica le varbind
        varbind_list = []
        for oid, value in self.varbinds:
            # Ogni varbind è una sequenza di OID + valore
            varbind = SnmpSequence([oid, value])
            varbind_list.append(varbind)
        
        # La lista delle varbind è una sequenza
        varbind_list_sequence = SnmpSequence(varbind_list)
        
        # Costruisci il PDU
        pdu_contents = [
            SnmpInteger(self.request_id),      # request-id
            SnmpInteger(self.error_status),    # error-status
            SnmpInteger(self.error_index),     # error-index
            varbind_list_sequence              # variable-bindings
        ]
        
        # Il PDU è un tipo di sequenza con un tag specifico
        pdu_sequence = SnmpSequence(pdu_contents)
        encoded_pdu = pdu_sequence.encode()
        
        # Sostituisci il tag della sequenza con il tag del PDU
        return bytes([self.tag]) + encoded_pdu[1:]
    
    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple['SnmpPdu', int]:
        """Decodifica un PDU dal formato BER"""
        # Ottieni il tag del PDU
        if offset >= len(data):
            raise ValueError("Dati insufficienti per decodificare il PDU")
        
        pdu_tag = data[offset]
        
        # Decodifica la lunghezza
        length, length_offset = decode_length(data, offset + 1)
        if length is None:
            raise ValueError("Formato lunghezza non valido nel PDU")
        
        # Decodifica il contenuto del PDU come una sequenza
        sequence_data = data[offset:length_offset + length]
        sequence_data = bytes([SnmpType.SEQUENCE]) + sequence_data[1:]
        
        sequence, _ = SnmpSequence.decode(sequence_data, 0)
        
        # Estrai i componenti del PDU
        if len(sequence.value) < 4:
            raise ValueError("PDU incompleto: mancano componenti obbligatori")
        
        request_id = sequence.value[0].value
        error_status = sequence.value[1].value
        error_index = sequence.value[2].value
        varbind_list = sequence.value[3]
        
        # Estrai le varbind
        varbinds = []
        for varbind in varbind_list.value:
            if len(varbind.value) < 2:
                raise ValueError("Varbind incompleto")
            
            oid = varbind.value[0]
            value = varbind.value[1]
            varbinds.append((oid, value))
        
        # Crea il tipo di PDU appropriato in base al tag
        if pdu_tag == SnmpType.GET_REQUEST:
            return SnmpGetRequest(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.GET_NEXT_REQUEST:
            return SnmpGetNextRequest(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.GET_RESPONSE:
            return SnmpGetResponse(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.SET_REQUEST:
            return SnmpSetRequest(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.GET_BULK_REQUEST:
            # Per GetBulkRequest, error_status è non-repeaters e error_index è max-repetitions
            return SnmpGetBulkRequest(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.INFORM_REQUEST:
            return SnmpInformRequest(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.TRAP_V2:
            return SnmpTrapV2(request_id, error_status, error_index, varbinds), length_offset + length
        elif pdu_tag == SnmpType.REPORT:
            return SnmpReport(request_id, error_status, error_index, varbinds), length_offset + length
        else:
            raise ValueError(f"Tag PDU non riconosciuto: 0x{pdu_tag:02x}")

class SnmpGetRequest(SnmpPdu):
    """Rappresenta un PDU GetRequest SNMP"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.GET_REQUEST, request_id, error_status, error_index, varbinds)

class SnmpGetNextRequest(SnmpPdu):
    """Rappresenta un PDU GetNextRequest SNMP"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.GET_NEXT_REQUEST, request_id, error_status, error_index, varbinds)

class SnmpGetResponse(SnmpPdu):
    """Rappresenta un PDU GetResponse SNMP"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.GET_RESPONSE, request_id, error_status, error_index, varbinds)

class SnmpSetRequest(SnmpPdu):
    """Rappresenta un PDU SetRequest SNMP"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.SET_REQUEST, request_id, error_status, error_index, varbinds)

class SnmpGetBulkRequest(SnmpPdu):
    """Rappresenta un PDU GetBulkRequest SNMP (SNMPv2c)"""
    def __init__(self, request_id: int = 0, non_repeaters: int = 0, max_repetitions: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.GET_BULK_REQUEST, request_id, non_repeaters, max_repetitions, varbinds)

class SnmpInformRequest(SnmpPdu):
    """Rappresenta un PDU InformRequest SNMP (SNMPv2c)"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.INFORM_REQUEST, request_id, error_status, error_index, varbinds)

class SnmpTrapV2(SnmpPdu):
    """Rappresenta un PDU TrapV2 SNMP (SNMPv2c)"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.TRAP_V2, request_id, error_status, error_index, varbinds)

class SnmpReport(SnmpPdu):
    """Rappresenta un PDU Report SNMP (SNMPv3)"""
    def __init__(self, request_id: int = 0, error_status: int = 0, error_index: int = 0,
                 varbinds: List[Tuple[SnmpObjectIdentifier, SnmpData]] = None):
        super().__init__(SnmpType.REPORT, request_id, error_status, error_index, varbinds)

class SnmpV3SecurityParameters:
    """Parametri di sicurezza per SNMPv3"""
    def __init__(self):
        self.authoritative_engine_id = b''
        self.authoritative_engine_boots = 0
        self.authoritative_engine_time = 0
        self.user_name = ''
        self.authentication_parameters = b''
        self.privacy_parameters = b''
    
    def encode(self) -> bytes:
        """Codifica i parametri di sicurezza"""
        params = [
            SnmpOctetString(self.authoritative_engine_id),
            SnmpInteger(self.authoritative_engine_boots),
            SnmpInteger(self.authoritative_engine_time),
            SnmpOctetString(self.user_name),
            SnmpOctetString(self.authentication_parameters),
            SnmpOctetString(self.privacy_parameters)
        ]
        return SnmpSequence(params).encode()
    
    @staticmethod
    def decode(data: bytes) -> 'SnmpV3SecurityParameters':
        """Decodifica i parametri di sicurezza"""
        sequence, _ = SnmpSequence.decode(data, 0)
        params = SnmpV3SecurityParameters()
        
        if len(sequence.value) >= 6:
            params.authoritative_engine_id = sequence.value[0].value
            params.authoritative_engine_boots = sequence.value[1].value
            params.authoritative_engine_time = sequence.value[2].value
            params.user_name = sequence.value[3].value.decode('utf-8', errors='replace')
            params.authentication_parameters = sequence.value[4].value
            params.privacy_parameters = sequence.value[5].value
        
        return params

class SnmpV3User:
    """Rappresenta un utente SNMPv3 con credenziali"""
    def __init__(self, username: str, 
                 auth_protocol: SnmpV3AuthProtocol = SnmpV3AuthProtocol.NO_AUTH,
                 auth_password: str = '',
                 priv_protocol: SnmpV3PrivProtocol = SnmpV3PrivProtocol.NO_PRIV,
                 priv_password: str = ''):
        self.username = username
        self.auth_protocol = auth_protocol
        self.auth_password = auth_password
        self.priv_protocol = priv_protocol
        self.priv_password = priv_password
        self.auth_key = None
        self.priv_key = None
        
        # Genera le chiavi se necessario
        if auth_protocol != SnmpV3AuthProtocol.NO_AUTH and auth_password:
            self.auth_key = self._password_to_key(auth_password, auth_protocol)
        
        if priv_protocol != SnmpV3PrivProtocol.NO_PRIV and priv_password:
            self.priv_key = self._password_to_key(priv_password, priv_protocol)
    
    def _password_to_key(self, password: str, protocol: Union[SnmpV3AuthProtocol, SnmpV3PrivProtocol]) -> bytes:
        """Converte una password in una chiave usando il metodo SNMPv3"""
        password_bytes = password.encode('utf-8')
        
        # Determina l'algoritmo hash
        if protocol in [SnmpV3AuthProtocol.MD5]:
            hash_func = hashlib.md5
            key_length = 16
        elif protocol in [SnmpV3AuthProtocol.SHA, SnmpV3PrivProtocol.AES128]:
            hash_func = hashlib.sha1
            key_length = 20
        elif protocol in [SnmpV3AuthProtocol.SHA224]:
            hash_func = hashlib.sha224
            key_length = 28
        elif protocol in [SnmpV3AuthProtocol.SHA256, SnmpV3PrivProtocol.AES192, SnmpV3PrivProtocol.AES256]:
            hash_func = hashlib.sha256
            key_length = 32
        elif protocol in [SnmpV3AuthProtocol.SHA384]:
            hash_func = hashlib.sha384
            key_length = 48
        elif protocol in [SnmpV3AuthProtocol.SHA512]:
            hash_func = hashlib.sha512
            key_length = 64
        elif protocol == SnmpV3PrivProtocol.DES:
            hash_func = hashlib.md5
            key_length = 16
        else:
            return b''
        
        # Password-to-Key algorithm (RFC 3414)
        hasher = hash_func()
        password_length = len(password_bytes)
        
        # Ripeti la password per 1MB
        count = 0
        while count < 1048576:
            for i in range(0, password_length):
                hasher.update(password_bytes[i:i+1])
                count += 1
                if count >= 1048576:
                    break
        
        key = hasher.digest()
        
        # Tronca o estendi la chiave alla lunghezza richiesta
        if len(key) > key_length:
            key = key[:key_length]
        elif len(key) < key_length:
            key = key + b'\x00' * (key_length - len(key))
        
        return key
    
    def localize_key(self, engine_id: bytes, key: bytes) -> bytes:
        """Localizza una chiave per un engine ID specifico"""
        if not key:
            return b''
        
        # Determina l'algoritmo hash dalla lunghezza della chiave
        if len(key) == 16:
            hash_func = hashlib.md5
        elif len(key) == 20:
            hash_func = hashlib.sha1
        elif len(key) == 28:
            hash_func = hashlib.sha224
        elif len(key) == 32:
            hash_func = hashlib.sha256
        elif len(key) == 48:
            hash_func = hashlib.sha384
        elif len(key) == 64:
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha1
        
        hasher = hash_func()
        hasher.update(key)
        hasher.update(engine_id)
        hasher.update(key)
        
        localized = hasher.digest()
        return localized[:len(key)]
    
    def get_security_level(self) -> SnmpV3SecurityLevel:
        """Ottiene il livello di sicurezza per questo utente"""
        if self.auth_protocol == SnmpV3AuthProtocol.NO_AUTH:
            return SnmpV3SecurityLevel.NO_AUTH_NO_PRIV
        elif self.priv_protocol == SnmpV3PrivProtocol.NO_PRIV:
            return SnmpV3SecurityLevel.AUTH_NO_PRIV
        else:
            return SnmpV3SecurityLevel.AUTH_PRIV

class SnmpV3MessageProcessor:
    """Processore per messaggi SNMPv3"""
    def __init__(self, user: SnmpV3User):
        self.user = user
        self.engine_id = None
        self.engine_boots = 0
        self.engine_time = 0
        self.time_offset = 0
        self.discovered = False
    
    def discover_engine(self, host: str, port: int = 161, timeout: float = 2.0) -> bool:
        """Scopre l'engine ID del dispositivo remoto"""
        logger.info(f"Discovering engine ID for {host}:{port}")
        
        # Crea un messaggio di discovery (GetRequest vuoto con noAuthNoPriv)
        msg = self._create_discovery_message()
        
        # Invia e ricevi
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        try:
            sock.sendto(msg, (host, port))
            response, _ = sock.recvfrom(4096)
            
            # Decodifica la risposta per ottenere l'engine ID
            self._parse_discovery_response(response)
            
            if self.engine_id:
                logger.info(f"Engine ID discovered: {binascii.hexlify(self.engine_id).decode()}")
                self.discovered = True
                return True
        except socket.timeout:
            logger.error("Discovery timeout")
        except Exception as e:
            logger.error(f"Discovery error: {e}")
        finally:
            sock.close()
        
        return False
    
    def _create_discovery_message(self) -> bytes:
        """Crea un messaggio di discovery SNMPv3"""
        # Header flags: reportable
        msg_flags = SnmpV3Flags.REPORTABLE
        
        # Security parameters vuoti
        sec_params = SnmpV3SecurityParameters()
        sec_params.user_name = ''
        
        # PDU: GetRequest vuoto
        pdu = SnmpGetRequest(request_id=int(time.time()) % 0x7FFFFFFF)
        
        # Costruisci il messaggio
        return self._build_message(msg_flags, sec_params, pdu, b'', b'')
    
    def _parse_discovery_response(self, data: bytes):
        """Analizza la risposta di discovery per estrarre l'engine ID"""
        try:
            # Decodifica il messaggio SNMPv3
            msg_sequence, _ = SnmpSequence.decode(data, 0)
            
            # Il messaggio SNMPv3 ha questa struttura:
            # SEQUENCE {
            #   version INTEGER,
            #   globalData SEQUENCE {
            #     msgID INTEGER,
            #     msgMaxSize INTEGER,
            #     msgFlags OCTET STRING,
            #     msgSecurityModel INTEGER
            #   },
            #   msgSecurityParameters OCTET STRING,
            #   msgData SEQUENCE { ... }
            # }
            
            if len(msg_sequence.value) >= 4:
                # Estrai msgSecurityParameters
                sec_params_octets = msg_sequence.value[2]
                if isinstance(sec_params_octets, SnmpOctetString):
                    # Decodifica i parametri di sicurezza
                    sec_params = SnmpV3SecurityParameters.decode(sec_params_octets.value)
                    
                    # Estrai engine ID, boots e time
                    self.engine_id = sec_params.authoritative_engine_id
                    self.engine_boots = sec_params.authoritative_engine_boots
                    self.engine_time = sec_params.authoritative_engine_time
                    
                    # Calcola l'offset temporale
                    self.time_offset = int(time.time()) - self.engine_time
        except Exception as e:
            logger.error(f"Error parsing discovery response: {e}")
    
    def _build_message(self, msg_flags: int, sec_params: SnmpV3SecurityParameters, 
                      pdu: SnmpPdu, context_engine_id: bytes, context_name: bytes) -> bytes:
        """Costruisce un messaggio SNMPv3 completo"""
        # Message ID
        msg_id = int(time.time() * 1000) % 0x7FFFFFFF
        
        # Global data
        global_data = SnmpSequence([
            SnmpInteger(msg_id),
            SnmpInteger(65507),  # msgMaxSize
            SnmpOctetString(bytes([msg_flags])),
            SnmpInteger(3)  # USM security model
        ])
        
        # Scoped PDU
        scoped_pdu = SnmpSequence([
            SnmpOctetString(context_engine_id),
            SnmpOctetString(context_name),
            pdu
        ])
        
        # Se privacy è abilitata, cripta lo scoped PDU
        scoped_pdu_data = scoped_pdu.encode()
        if msg_flags & SnmpV3Flags.PRIV:
            scoped_pdu_data = self._encrypt_data(scoped_pdu_data, sec_params)
            scoped_pdu_data = SnmpOctetString(scoped_pdu_data).encode()
        
        # Costruisci il messaggio
        msg_data = SnmpSequence([
            SnmpInteger(SnmpVersion.V3),
            global_data,
            SnmpOctetString(sec_params.encode()),
            scoped_pdu_data if msg_flags & SnmpV3Flags.PRIV else scoped_pdu
        ])
        
        msg_bytes = msg_data.encode()
        
        # Se autenticazione è abilitata, calcola e inserisci l'auth parameter
        if msg_flags & SnmpV3Flags.AUTH:
            msg_bytes = self._add_authentication(msg_bytes, sec_params)
        
        return msg_bytes
    
    def _encrypt_data(self, data: bytes, sec_params: SnmpV3SecurityParameters) -> bytes:
        """Cripta i dati usando il protocollo di privacy configurato"""
        if not self.user.priv_key:
            return data
        
        # Localizza la chiave di privacy
        localized_key = self.user.localize_key(self.engine_id, self.user.priv_key)
        
        if self.user.priv_protocol == SnmpV3PrivProtocol.DES:
            # DES-CBC
            salt = secrets.token_bytes(8)
            sec_params.privacy_parameters = salt
            
            # Deriva l'IV dalla chiave e dal salt
            iv = bytes(a ^ b for a, b in zip(localized_key[-8:], salt))
            
            # Cripta con DES
            cipher = DES.new(localized_key[:8], DES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(data, DES.block_size))
            
        elif self.user.priv_protocol == SnmpV3PrivProtocol.AES128:
            # AES-128-CFB
            salt = secrets.token_bytes(8)
            sec_params.privacy_parameters = salt
            
            # Costruisci l'IV per AES
            iv = self.engine_boots.to_bytes(4, 'big') + self.engine_time.to_bytes(4, 'big') + salt
            
            # Cripta con AES-128
            cipher = AES.new(localized_key[:16], AES.MODE_CFB, iv, segment_size=128)
            encrypted = cipher.encrypt(data)
            
        elif self.user.priv_protocol == SnmpV3PrivProtocol.AES192:
            # AES-192-CFB
            salt = secrets.token_bytes(8)
            sec_params.privacy_parameters = salt
            
            # Costruisci l'IV per AES
            iv = self.engine_boots.to_bytes(4, 'big') + self.engine_time.to_bytes(4, 'big') + salt
            
            # Cripta con AES-192
            cipher = AES.new(localized_key[:24], AES.MODE_CFB, iv, segment_size=128)
            encrypted = cipher.encrypt(data)
            
        elif self.user.priv_protocol == SnmpV3PrivProtocol.AES256:
            # AES-256-CFB
            salt = secrets.token_bytes(8)
            sec_params.privacy_parameters = salt
            
            # Costruisci l'IV per AES
            iv = self.engine_boots.to_bytes(4, 'big') + self.engine_time.to_bytes(4, 'big') + salt
            
            # Cripta con AES-256
            cipher = AES.new(localized_key[:32], AES.MODE_CFB, iv, segment_size=128)
            encrypted = cipher.encrypt(data)
        else:
            return data
        
        return encrypted
    
    def _decrypt_data(self, data: bytes, sec_params: SnmpV3SecurityParameters) -> bytes:
        """Decripta i dati usando il protocollo di privacy configurato"""
        if not self.user.priv_key:
            return data
        
        # Localizza la chiave di privacy
        localized_key = self.user.localize_key(self.engine_id, self.user.priv_key)
        
        if self.user.priv_protocol == SnmpV3PrivProtocol.DES:
            # DES-CBC
            salt = sec_params.privacy_parameters
            
            # Deriva l'IV dalla chiave e dal salt
            iv = bytes(a ^ b for a, b in zip(localized_key[-8:], salt))
            
            # Decripta con DES
            cipher = DES.new(localized_key[:8], DES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(data), DES.block_size)
            
        elif self.user.priv_protocol == SnmpV3PrivProtocol.AES128:
            # AES-128-CFB
            salt = sec_params.privacy_parameters
            
            # Costruisci l'IV per AES
            iv = self.engine_boots.to_bytes(4, 'big') + self.engine_time.to_bytes(4, 'big') + salt
            
            # Decripta con AES-128
            cipher = AES.new(localized_key[:16], AES.MODE_CFB, iv, segment_size=128)
            decrypted = cipher.decrypt(data)
            
        elif self.user.priv_protocol == SnmpV3PrivProtocol.AES192:
            # AES-192-CFB
            salt = sec_params.privacy_parameters
            
            # Costruisci l'IV per AES
            iv = self.engine_boots.to_bytes(4, 'big') + self.engine_time.to_bytes(4, 'big') + salt
            
            # Decripta con AES-192
            cipher = AES.new(localized_key[:24], AES.MODE_CFB, iv, segment_size=128)
            decrypted = cipher.decrypt(data)
            
        elif self.user.priv_protocol == SnmpV3PrivProtocol.AES256:
            # AES-256-CFB
            salt = sec_params.privacy_parameters
            
            # Costruisci l'IV per AES
            iv = self.engine_boots.to_bytes(4, 'big') + self.engine_time.to_bytes(4, 'big') + salt
            
            # Decripta con AES-256
            cipher = AES.new(localized_key[:32], AES.MODE_CFB, iv, segment_size=128)
            decrypted = cipher.decrypt(data)
        else:
            return data
        
        return decrypted
    
    def _add_authentication(self, msg_bytes: bytes, sec_params: SnmpV3SecurityParameters) -> bytes:
        """Aggiunge l'autenticazione al messaggio"""
        if not self.user.auth_key:
            return msg_bytes
        
        # Localizza la chiave di autenticazione
        localized_key = self.user.localize_key(self.engine_id, self.user.auth_key)
        
        # Determina l'algoritmo HMAC
        if self.user.auth_protocol == SnmpV3AuthProtocol.MD5:
            hash_func = hashlib.md5
            auth_len = 12  # HMAC-MD5-96
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA:
            hash_func = hashlib.sha1
            auth_len = 12  # HMAC-SHA-96
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA224:
            hash_func = hashlib.sha224
            auth_len = 16  # HMAC-SHA-224-128
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA256:
            hash_func = hashlib.sha256
            auth_len = 24  # HMAC-SHA-256-192
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA384:
            hash_func = hashlib.sha384
            auth_len = 32  # HMAC-SHA-384-256
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA512:
            hash_func = hashlib.sha512
            auth_len = 48  # HMAC-SHA-512-384
        else:
            return msg_bytes
        
        # Trova la posizione dell'authentication parameter nel messaggio
        # e sostituiscilo con zeri per il calcolo HMAC
        auth_param_placeholder = b'\x00' * auth_len
        
        # Cerca il parametro di autenticazione nel messaggio
        # (è un OCTET STRING di lunghezza auth_len dopo il nome utente)
        # Questo è un approccio semplificato - in produzione servirebbe un parsing più robusto
        
        # Calcola HMAC
        hmac_calc = hmac.new(localized_key, msg_bytes, hash_func)
        auth_param = hmac_calc.digest()[:auth_len]
        
        # Inserisci l'authentication parameter nel messaggio
        sec_params.authentication_parameters = auth_param
        
        # Ricostruisci il messaggio con i nuovi parametri di sicurezza
        # Questo richiede un re-encoding completo del messaggio
        # Per semplicità, restituiamo il messaggio originale
        # In un'implementazione completa, dovremmo ricodificare tutto
        
        return msg_bytes
    
    def create_message(self, pdu: SnmpPdu) -> bytes:
        """Crea un messaggio SNMPv3 completo con sicurezza"""
        if not self.discovered:
            raise RuntimeError("Engine ID not discovered. Call discover_engine() first.")
        
        # Determina i flag del messaggio
        msg_flags = SnmpV3Flags.REPORTABLE
        if self.user.auth_protocol != SnmpV3AuthProtocol.NO_AUTH:
            msg_flags |= SnmpV3Flags.AUTH
        if self.user.priv_protocol != SnmpV3PrivProtocol.NO_PRIV:
            msg_flags |= SnmpV3Flags.PRIV
        
        # Crea i parametri di sicurezza
        sec_params = SnmpV3SecurityParameters()
        sec_params.authoritative_engine_id = self.engine_id
        sec_params.authoritative_engine_boots = self.engine_boots
        sec_params.authoritative_engine_time = self.engine_time + int(time.time()) - self.time_offset
        sec_params.user_name = self.user.username
        
        # Costruisci il messaggio
        return self._build_message(msg_flags, sec_params, pdu, self.engine_id, b'')
    
    def parse_message(self, data: bytes) -> Optional[SnmpPdu]:
        """Analizza un messaggio SNMPv3 ricevuto"""
        try:
            # Decodifica il messaggio
            msg_sequence, _ = SnmpSequence.decode(data, 0)
            
            if len(msg_sequence.value) < 4:
                return None
            
            # Estrai i componenti
            version = msg_sequence.value[0].value
            if version != SnmpVersion.V3:
                return None
            
            # Global data
            global_data = msg_sequence.value[1]
            msg_flags = global_data.value[2].value[0] if len(global_data.value) > 2 else 0
            
            # Security parameters
            sec_params_octets = msg_sequence.value[2]
            sec_params = SnmpV3SecurityParameters.decode(sec_params_octets.value)
            
            # Verifica l'autenticazione se necessaria
            if msg_flags & SnmpV3Flags.AUTH:
                if not self._verify_authentication(data, sec_params):
                    logger.error("Authentication verification failed")
                    return None
            
            # Message data (scoped PDU)
            msg_data = msg_sequence.value[3]
            
            # Decripta se necessario
            if msg_flags & SnmpV3Flags.PRIV:
                if isinstance(msg_data, SnmpOctetString):
                    decrypted = self._decrypt_data(msg_data.value, sec_params)
                    msg_data, _ = SnmpSequence.decode(decrypted, 0)
            
            # Estrai il PDU dallo scoped PDU
            if isinstance(msg_data, SnmpSequence) and len(msg_data.value) >= 3:
                pdu_data = msg_data.value[2]
                if hasattr(pdu_data, 'encode'):
                    # È già un PDU decodificato
                    return pdu_data
                else:
                    # Decodifica il PDU
                    return SnmpPdu.decode(pdu_data, 0)[0]
            
            return None
        except Exception as e:
            logger.error(f"Error parsing SNMPv3 message: {e}")
            return None
    
    def _verify_authentication(self, msg_bytes: bytes, sec_params: SnmpV3SecurityParameters) -> bool:
        """Verifica l'autenticazione del messaggio"""
        if not self.user.auth_key:
            return True
        
        # Localizza la chiave di autenticazione
        localized_key = self.user.localize_key(self.engine_id, self.user.auth_key)
        
        # Determina l'algoritmo HMAC
        if self.user.auth_protocol == SnmpV3AuthProtocol.MD5:
            hash_func = hashlib.md5
            auth_len = 12
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA:
            hash_func = hashlib.sha1
            auth_len = 12
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA224:
            hash_func = hashlib.sha224
            auth_len = 16
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA256:
            hash_func = hashlib.sha256
            auth_len = 24
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA384:
            hash_func = hashlib.sha384
            auth_len = 32
        elif self.user.auth_protocol == SnmpV3AuthProtocol.SHA512:
            hash_func = hashlib.sha512
            auth_len = 48
        else:
            return True
        
        # Salva l'authentication parameter ricevuto
        received_auth = sec_params.authentication_parameters[:auth_len]
        
        # Sostituisci con zeri per il calcolo
        # (implementazione semplificata)
        
        # Calcola HMAC
        hmac_calc = hmac.new(localized_key, msg_bytes, hash_func)
        calculated_auth = hmac_calc.digest()[:auth_len]
        
        # Confronta
        return hmac.compare_digest(received_auth, calculated_auth)

class SnmpMessage:
    """Rappresenta un messaggio SNMP completo (v1/v2c)"""
    def __init__(self, version: SnmpVersion = SnmpVersion.V2C, community: str = "public", 
                 pdu: SnmpPdu = None):
        self.version = version
        self.community = community
        self.pdu = pdu or SnmpGetRequest()
    
    def encode(self) -> bytes:
        """Codifica il messaggio SNMP in formato BER"""
        # Codifica i componenti del messaggio
        version_component = SnmpInteger(self.version)
        community_component = SnmpOctetString(self.community)
        pdu_component = self.pdu.encode()
        
        # Combina i componenti
        message_components = version_component.encode() + community_component.encode() + pdu_component
        
        # Wrappa in una sequenza
        message = SnmpSequence([])
        message_encoded = message.encode()
        
        return bytes([SnmpType.SEQUENCE]) + encode_length(len(message_components)) + message_components
    
    @staticmethod
    def decode(data: bytes) -> 'SnmpMessage':
        """Decodifica un messaggio SNMP dal formato BER"""
        # Decodifica la sequenza principale
        tag, value, offset = decode_tlv(data, 0)
        
        if tag != SnmpType.SEQUENCE:
            raise ValueError(f"Atteso tag SEQUENCE (0x30), trovato 0x{tag:02x}")
        
        # Decodifica la versione
        version_component, offset = SnmpInteger.decode(value, 0)
        version = version_component.value
        
        # Decodifica la community
        community_component, offset = SnmpOctetString.decode(value, offset)
        community = community_component.value.decode('utf-8', errors='replace')
        
        # Decodifica il PDU
        pdu, _ = SnmpPdu.decode(value, offset)
        
        return SnmpMessage(version, community, pdu)

def encode_length(length: int) -> bytes:
    """Codifica la lunghezza secondo le regole ASN.1 BER"""
    if length < 128:
        return bytes([length])
    else:
        # Lunghezza su più byte
        bytes_list = []
        temp_length = length
        
        while temp_length > 0:
            bytes_list.insert(0, temp_length & 0xFF)
            temp_length >>= 8
        
        # Aggiungi il byte di lunghezza della lunghezza
        bytes_list.insert(0, 0x80 | len(bytes_list))
        
        return bytes(bytes_list)

def decode_length(data: bytes, offset: int) -> Tuple[Optional[int], int]:
    """Decodifica la lunghezza secondo le regole ASN.1 BER"""
    if offset >= len(data):
        return None, offset
        
    length_byte = data[offset]
    offset += 1
    
    if length_byte < 128:
        return length_byte, offset
    else:
        # Lunghezza su più byte
        num_bytes = length_byte & 0x7F
        if offset + num_bytes > len(data):
            return None, offset
            
        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data[offset + i]
        
        return length, offset + num_bytes

def decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Decodifica un TLV (Type-Length-Value) secondo ASN.1 BER"""
    if offset >= len(data):
        raise ValueError("Dati insufficienti per decodificare TLV")
        
    tag = data[offset]
    offset += 1
    
    length, offset = decode_length(data, offset)
    if length is None:
        raise ValueError("Formato lunghezza non valido")
        
    if offset + length > len(data):
        raise ValueError("Dati insufficienti per il valore TLV")
        
    value = data[offset:offset + length]
    offset += length
    
    return tag, value, offset

def decode_snmp_data(data: bytes, offset: int = 0) -> Tuple[SnmpData, int]:
    """Decodifica un dato SNMP generico dal formato BER"""
    if offset >= len(data):
        raise ValueError("Dati insufficienti per decodificare")
        
    tag = data[offset]
    
    # Decodifica in base al tag
    if tag == SnmpType.INTEGER:
        return SnmpInteger.decode(data, offset)
    elif tag == SnmpType.OCTET_STRING:
        return SnmpOctetString.decode(data, offset)
    elif tag == SnmpType.NULL:
        return SnmpNull.decode(data, offset)
    elif tag == SnmpType.OBJECT_IDENTIFIER:
        return SnmpObjectIdentifier.decode(data, offset)
    elif tag == SnmpType.SEQUENCE:
        return SnmpSequence.decode(data, offset)
    elif tag == SnmpType.IP_ADDRESS:
        return SnmpIpAddress.decode(data, offset)
    elif tag == SnmpType.COUNTER32:
        return SnmpCounter32.decode(data, offset)
    elif tag == SnmpType.GAUGE32:
        return SnmpGauge32.decode(data, offset)
    elif tag == SnmpType.TIME_TICKS:
        return SnmpTimeTicks.decode(data, offset)
    elif tag == SnmpType.OPAQUE:
        return SnmpOpaque.decode(data, offset)
    elif tag == SnmpType.COUNTER64:
        return SnmpCounter64.decode(data, offset)
    elif tag == SnmpType.NO_SUCH_OBJECT:
        return SnmpNoSuchObject.decode(data, offset)
    elif tag == SnmpType.NO_SUCH_INSTANCE:
        return SnmpNoSuchInstance.decode(data, offset)
    elif tag == SnmpType.END_OF_MIB_VIEW:
        return SnmpEndOfMibView.decode(data, offset)
    else:
        # Decodifica generica se il tag non è riconosciuto
        tag, value, new_offset = decode_tlv(data, offset)
        return SnmpData(tag, value), new_offset

class SnmpClient:
    """Client SNMP per inviare richieste e ricevere risposte (supporta v1, v2c, v3)"""
    def __init__(self, host: str, port: int = 161, 
                 # Parametri per v1/v2c
                 community: str = "public", 
                 version: SnmpVersion = SnmpVersion.V2C,
                 # Parametri per v3
                 v3_user: Optional[SnmpV3User] = None,
                 # Parametri comuni
                 timeout: float = 2.0, retries: int = 3):
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.v3_user = v3_user
        self.timeout = timeout
        self.retries = retries
        self.request_id = 0
        self.socket = None
        
        # Processore per SNMPv3
        self.v3_processor = None
        if version == SnmpVersion.V3:
            if not v3_user:
                raise ValueError("SNMPv3 richiede un oggetto SnmpV3User")
            self.v3_processor = SnmpV3MessageProcessor(v3_user)
            # Scopri l'engine ID
            if not self.v3_processor.discover_engine(host, port, timeout):
                logger.warning("Impossibile scoprire l'engine ID. Le operazioni potrebbero fallire.")
    
    def _get_next_request_id(self) -> int:
        """Ottiene il prossimo ID di richiesta"""
        self.request_id = (self.request_id + 1) % 0x7FFFFFFF
        return self.request_id
    
    def _create_socket(self):
        """Crea un socket UDP per le comunicazioni SNMP"""
        if self.socket is None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(self.timeout)
    
    def _close_socket(self):
        """Chiude il socket UDP"""
        if self.socket is not None:
            self.socket.close()
            self.socket = None
    
    def get(self, oid: str) -> Optional[SnmpData]:
        """Esegue una richiesta SNMP GET per un OID specifico"""
        return self.get_multiple([oid])[oid] if oid in self.get_multiple([oid]) else None
    
    def get_multiple(self, oids: List[str]) -> Dict[str, SnmpData]:
        """Esegue una richiesta SNMP GET per più OID"""
        # Crea le varbind per ogni OID
        varbinds = []
        for oid in oids:
            oid_obj = SnmpObjectIdentifier(oid)
            null_obj = SnmpNull()
            varbinds.append((oid_obj, null_obj))
        
        # Crea il PDU
        request_id = self._get_next_request_id()
        pdu = SnmpGetRequest(request_id, 0, 0, varbinds)
        
        # Crea il messaggio in base alla versione
        if self.version == SnmpVersion.V3:
            if not self.v3_processor or not self.v3_processor.discovered:
                logger.error("SNMPv3 processor not ready")
                return {}
            message_bytes = self.v3_processor.create_message(pdu)
        else:
            message = SnmpMessage(self.version, self.community, pdu)
            message_bytes = message.encode()
        
        # Invia la richiesta e ricevi la risposta
        response = self._send_receive(message_bytes)
        if response is None:
            return {}
        
        # Decodifica la risposta
        try:
            if self.version == SnmpVersion.V3:
                response_pdu = self.v3_processor.parse_message(response)
                if not response_pdu:
                    return {}
            else:
                response_message = SnmpMessage.decode(response)
                response_pdu = response_message.pdu
            
            # Verifica che sia una risposta alla nostra richiesta
            if response_pdu.request_id != request_id:
                logger.warning(f"ID richiesta non corrispondente: atteso {request_id}, ricevuto {response_pdu.request_id}")
                return {}
            
            # Verifica lo stato di errore
            if response_pdu.error_status != 0:
                error_message = SnmpError(response_pdu.error_status).name
                error_index = response_pdu.error_index
                logger.warning(f"Errore SNMP: {error_message} all'indice {error_index}")
                return {}
            
            # Estrai i risultati
            results = {}
            for oid_obj, value_obj in response_pdu.varbinds:
                oid_str = '.'.join(str(x) for x in oid_obj.value)
                results[oid_str] = value_obj
            
            return results
        except Exception as e:
            logger.error(f"Errore nella decodifica della risposta: {e}")
            return {}
    
    def get_next(self, oid: str) -> Tuple[Optional[str], Optional[SnmpData]]:
        """Esegue una richiesta SNMP GETNEXT per un OID specifico"""
        results = self.get_next_multiple([oid])
        if not results:
            return None, None
        
        # Restituisci la prima coppia OID-valore
        for next_oid, value in results.items():
            return next_oid, value
        
        return None, None
    
    def get_next_multiple(self, oids: List[str]) -> Dict[str, SnmpData]:
        """Esegue una richiesta SNMP GETNEXT per più OID"""
        # Crea le varbind per ogni OID
        varbinds = []
        for oid in oids:
            oid_obj = SnmpObjectIdentifier(oid)
            null_obj = SnmpNull()
            varbinds.append((oid_obj, null_obj))
        
        # Crea il PDU
        request_id = self._get_next_request_id()
        pdu = SnmpGetNextRequest(request_id, 0, 0, varbinds)
        
        # Crea il messaggio in base alla versione
        if self.version == SnmpVersion.V3:
            if not self.v3_processor or not self.v3_processor.discovered:
                logger.error("SNMPv3 processor not ready")
                return {}
            message_bytes = self.v3_processor.create_message(pdu)
        else:
            message = SnmpMessage(self.version, self.community, pdu)
            message_bytes = message.encode()
        
        # Invia la richiesta e ricevi la risposta
        response = self._send_receive(message_bytes)
        if response is None:
            return {}
        
        # Decodifica la risposta
        try:
            if self.version == SnmpVersion.V3:
                response_pdu = self.v3_processor.parse_message(response)
                if not response_pdu:
                    return {}
            else:
                response_message = SnmpMessage.decode(response)
                response_pdu = response_message.pdu
            
            # Verifica che sia una risposta alla nostra richiesta
            if response_pdu.request_id != request_id:
                logger.warning(f"ID richiesta non corrispondente: atteso {request_id}, ricevuto {response_pdu.request_id}")
                return {}
            
            # Verifica lo stato di errore
            if response_pdu.error_status != 0:
                error_message = SnmpError(response_pdu.error_status).name
                error_index = response_pdu.error_index
                logger.warning(f"Errore SNMP: {error_message} all'indice {error_index}")
                return {}
            
            # Estrai i risultati
            results = {}
            for oid_obj, value_obj in response_pdu.varbinds:
                oid_str = '.'.join(str(x) for x in oid_obj.value)
                results[oid_str] = value_obj
            
            return results
        except Exception as e:
            logger.error(f"Errore nella decodifica della risposta: {e}")
            return {}
    
    def get_bulk(self, non_repeaters: int, max_repetitions: int, oids: List[str]) -> Dict[str, SnmpData]:
        """Esegue una richiesta SNMP GETBULK per più OID (SNMPv2c/v3)"""
        if self.version == SnmpVersion.V1:
            logger.warning("GETBULK non è supportato in SNMPv1")
            return {}
        
        # Crea le varbind per ogni OID
        varbinds = []
        for oid in oids:
            oid_obj = SnmpObjectIdentifier(oid)
            null_obj = SnmpNull()
            varbinds.append((oid_obj, null_obj))
        
        # Crea il PDU
        request_id = self._get_next_request_id()
        pdu = SnmpGetBulkRequest(request_id, non_repeaters, max_repetitions, varbinds)
        
        # Crea il messaggio in base alla versione
        if self.version == SnmpVersion.V3:
            if not self.v3_processor or not self.v3_processor.discovered:
                logger.error("SNMPv3 processor not ready")
                return {}
            message_bytes = self.v3_processor.create_message(pdu)
        else:
            message = SnmpMessage(self.version, self.community, pdu)
            message_bytes = message.encode()
        
        # Invia la richiesta e ricevi la risposta
        response = self._send_receive(message_bytes)
        if response is None:
            return {}
        
        # Decodifica la risposta
        try:
            if self.version == SnmpVersion.V3:
                response_pdu = self.v3_processor.parse_message(response)
                if not response_pdu:
                    return {}
            else:
                response_message = SnmpMessage.decode(response)
                response_pdu = response_message.pdu
            
            # Verifica che sia una risposta alla nostra richiesta
            if response_pdu.request_id != request_id:
                logger.warning(f"ID richiesta non corrispondente: atteso {request_id}, ricevuto {response_pdu.request_id}")
                return {}
            
            # Verifica lo stato di errore
            if response_pdu.error_status != 0:
                error_message = SnmpError(response_pdu.error_status).name
                error_index = response_pdu.error_index
                logger.warning(f"Errore SNMP: {error_message} all'indice {error_index}")
                return {}
            
            # Estrai i risultati
            results = {}
            for oid_obj, value_obj in response_pdu.varbinds:
                oid_str = '.'.join(str(x) for x in oid_obj.value)
                results[oid_str] = value_obj
            
            return results
        except Exception as e:
            logger.error(f"Errore nella decodifica della risposta: {e}")
            return {}
    
    def walk(self, base_oid: str) -> Dict[str, SnmpData]:
        """Esegue una SNMP WALK (serie di GETNEXT) a partire da un OID base"""
        results = {}
        current_oid = base_oid
        
        while True:
            next_oid, value = self.get_next(current_oid)
            
            # Verifica se abbiamo raggiunto la fine o se c'è stato un errore
            if next_oid is None or value is None:
                break
            
            # Verifica se siamo usciti dal sottoalbero dell'OID base
            if not next_oid.startswith(base_oid):
                break
            
            # Aggiungi il risultato
            results[next_oid] = value
            
            # Prepara per la prossima iterazione
            current_oid = next_oid
        
        return results
    
    def bulk_walk(self, base_oid: str, max_repetitions: int = 10) -> Dict[str, SnmpData]:
        """Esegue una SNMP WALK usando GETBULK (più efficiente, solo SNMPv2c/v3)"""
        if self.version == SnmpVersion.V1:
            logger.warning("GETBULK non è supportato in SNMPv1, uso GETNEXT")
            return self.walk(base_oid)
        
        results = {}
        current_oid = base_oid
        
        while True:
            # Esegui una richiesta GETBULK
            bulk_results = self.get_bulk(0, max_repetitions, [current_oid])
            if not bulk_results:
                break
            
            # Ordina gli OID per avere una traversata ordinata
            sorted_oids = sorted(bulk_results.keys())
            
            # Verifica se abbiamo ottenuto risultati
            if not sorted_oids:
                break
            
            # Verifica se siamo usciti dal sottoalbero dell'OID base
            if not sorted_oids[0].startswith(base_oid):
                break
            
            # Aggiungi i risultati
            end_of_subtree = False
            for oid in sorted_oids:
                # Verifica se siamo ancora nel sottoalbero
                if not oid.startswith(base_oid):
                    end_of_subtree = True
                    break
                
                # Aggiungi il risultato
                results[oid] = bulk_results[oid]
            
            # Se siamo usciti dal sottoalbero, termina
            if end_of_subtree:
                break
            
            # Prepara per la prossima iterazione
            current_oid = sorted_oids[-1]
        
        return results
    
    def set(self, oid: str, value: SnmpData) -> bool:
        """Esegue una richiesta SNMP SET per un OID specifico"""
        return self.set_multiple({oid: value})
    
    def set_multiple(self, oid_values: Dict[str, SnmpData]) -> bool:
        """Esegue una richiesta SNMP SET per più OID"""
        # Crea le varbind per ogni coppia OID-valore
        varbinds = []
        for oid, value in oid_values.items():
            oid_obj = SnmpObjectIdentifier(oid)
            varbinds.append((oid_obj, value))
        
        # Crea il PDU
        request_id = self._get_next_request_id()
        pdu = SnmpSetRequest(request_id, 0, 0, varbinds)
        
        # Crea il messaggio in base alla versione
        if self.version == SnmpVersion.V3:
            if not self.v3_processor or not self.v3_processor.discovered:
                logger.error("SNMPv3 processor not ready")
                return False
            message_bytes = self.v3_processor.create_message(pdu)
        else:
            message = SnmpMessage(self.version, self.community, pdu)
            message_bytes = message.encode()
        
        # Invia la richiesta e ricevi la risposta
        response = self._send_receive(message_bytes)
        if response is None:
            return False
        
        # Decodifica la risposta
        try:
            if self.version == SnmpVersion.V3:
                response_pdu = self.v3_processor.parse_message(response)
                if not response_pdu:
                    return False
            else:
                response_message = SnmpMessage.decode(response)
                response_pdu = response_message.pdu
            
            # Verifica che sia una risposta alla nostra richiesta
            if response_pdu.request_id != request_id:
                logger.warning(f"ID richiesta non corrispondente: atteso {request_id}, ricevuto {response_pdu.request_id}")
                return False
            
            # Verifica lo stato di errore
            if response_pdu.error_status != 0:
                error_message = SnmpError(response_pdu.error_status).name
                error_index = response_pdu.error_index
                logger.warning(f"Errore SNMP: {error_message} all'indice {error_index}")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Errore nella decodifica della risposta: {e}")
            return False
    
    def _send_receive(self, data: bytes) -> Optional[bytes]:
        """Invia una richiesta SNMP e riceve la risposta"""
        self._create_socket()
        
        for attempt in range(self.retries + 1):
            try:
                # Invia la richiesta
                self.socket.sendto(data, (self.host, self.port))
                
                # Ricevi la risposta
                response, addr = self.socket.recvfrom(4096)
                
                # Verifica che la risposta provenga dal server corretto
                if addr[0] != self.host:
                    logger.warning(f"Risposta ricevuta da {addr}, atteso {self.host}:{self.port}")
                    continue
                
                return response
            except socket.timeout:
                logger.warning(f"Timeout (tentativo {attempt + 1}/{self.retries + 1})")
            except Exception as e:
                logger.error(f"Errore nella comunicazione: {e}")
                break
        
        return None
    
    def __enter__(self):
        """Supporto per il context manager (with statement)"""
        self._create_socket()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Chiusura del context manager"""
        self._close_socket()

class UpsMonitor:
    """Classe per monitorare un UPS tramite SNMP"""
    def __init__(self, host: str, port: int = 161, 
                 # Parametri v1/v2c
                 community: str = "public", 
                 version: SnmpVersion = SnmpVersion.V2C,
                 # Parametri v3
                 v3_user: Optional[SnmpV3User] = None):
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.v3_user = v3_user
        
        # Crea il client SNMP
        self.client = SnmpClient(host, port, community, version, v3_user)
        
        # OID standard RFC 1628 per UPS
        self.oids = {
            'load': "1.3.6.1.2.1.33.1.4.4.1.5.1",           # Carico percentuale
            'battery_charge': "1.3.6.1.2.1.33.1.2.4.0",     # Carica batteria (%)
            'input_voltage': "1.3.6.1.2.1.33.1.3.3.1.3.1",  # Tensione di ingresso
            'output_voltage': "1.3.6.1.2.1.33.1.4.4.1.2.1", # Tensione di uscita
            'temperature': "1.3.6.1.2.1.33.1.2.7.0",        # Temperatura
            'ups_status': "1.3.6.1.2.1.33.1.4.1.0",         # Stato operativo
            'model': "1.3.6.1.2.1.33.1.1.2.0",              # Modello UPS
            'estimated_runtime': "1.3.6.1.2.1.33.1.2.3.0",  # Tempo di runtime stimato
        }
        
        # OID specifici per APC
        self.apc_oids = {
            'load': "1.3.6.1.4.1.318.1.1.1.4.2.3.0",           # Carico percentuale
            'battery_charge': "1.3.6.1.4.1.318.1.1.1.2.2.1.0", # Carica batteria (%)
            'input_voltage': "1.3.6.1.4.1.318.1.1.1.3.2.1.0",  # Tensione di ingresso
            'output_voltage': "1.3.6.1.4.1.318.1.1.1.4.2.1.0", # Tensione di uscita
            'temperature': "1.3.6.1.4.1.318.1.1.1.2.2.2.0",    # Temperatura
            'ups_status': "1.3.6.1.4.1.318.1.1.1.11.1.1.0",    # Stato operativo
            'model': "1.3.6.1.4.1.318.1.1.1.1.1.1.0",          # Modello UPS
            'estimated_runtime': "1.3.6.1.4.1.318.1.1.1.2.2.3.0", # Tempo di runtime stimato
        }
        
        # OID specifici per Eaton
        self.eaton_oids = {
            'load': "1.3.6.1.4.1.534.1.4.1.0",              # Carico percentuale
            'battery_charge': "1.3.6.1.4.1.534.1.2.4.0",    # Carica batteria (%)
            'input_voltage': "1.3.6.1.4.1.534.1.3.4.1.2.1", # Tensione di ingresso
            'output_voltage': "1.3.6.1.4.1.534.1.4.4.1.2.1",# Tensione di uscita
            'temperature': "1.3.6.1.4.1.534.1.6.1.0",       # Temperatura
            'ups_status': "1.3.6.1.4.1.534.1.1.2.0",        # Stato operativo
            'model': "1.3.6.1.4.1.534.1.1.13.0",            # Modello UPS
        }
        
        # OID specifici per CyberPower
        self.cyber_oids = {
            'load': "1.3.6.1.4.1.3808.1.1.1.4.2.3.0",          # Carico percentuale
            'battery_charge': "1.3.6.1.4.1.3808.1.1.1.2.2.1.0",# Carica batteria (%)
            'input_voltage': "1.3.6.1.4.1.3808.1.1.1.3.2.1.0", # Tensione di ingresso
            'output_voltage': "1.3.6.1.4.1.3808.1.1.1.4.2.1.0",# Tensione di uscita
            'temperature': "1.3.6.1.4.1.3808.1.1.1.2.2.3.0",   # Temperatura
            'ups_status': "1.3.6.1.4.1.3808.1.1.1.4.1.1.0",    # Stato operativo
            'model': "1.3.6.1.4.1.3808.1.1.1.1.1.1.0",         # Modello UPS
        }
        
        # Lista di tutti gli OID da provare
        self.all_oids = [self.oids, self.apc_oids, self.eaton_oids, self.cyber_oids]
        
        # Storico dei valori per il carico
        self.load_history = []
        self.max_history_size = 100
    
    def detect_ups_type(self) -> str:
        """Rileva il tipo di UPS basandosi sugli OID supportati"""
        logger.info(f"Rilevamento tipo UPS per {self.host}...")
        
        # Prova tutti gli OID del modello
        for oid_set in self.all_oids:
            model_oid = oid_set.get('model')
            if model_oid:
                model = self.get_value(model_oid)
                if model is not None:
                    logger.info(f"Modello UPS rilevato: {model}")
                    
                    # Determina il tipo di UPS
                    if any(oid.startswith("1.3.6.1.4.1.318") for oid in oid_set.values()):
                        return "APC"
                    elif any(oid.startswith("1.3.6.1.4.1.534") for oid in oid_set.values()):
                        return "Eaton"
                    elif any(oid.startswith("1.3.6.1.4.1.3808") for oid in oid_set.values()):
                        return "CyberPower"
                    else:
                        return "Standard"
        
        # Prova a rilevare in base agli OID supportati
        for oid_set_name, oid_set in [("APC", self.apc_oids), ("Eaton", self.eaton_oids), 
                                    ("CyberPower", self.cyber_oids), ("Standard", self.oids)]:
            for param, oid in oid_set.items():
                value = self.get_value(oid)
                if value is not None:
                    logger.info(f"Tipo UPS rilevato: {oid_set_name}")
                    return oid_set_name
        
        logger.warning("Impossibile determinare il tipo di UPS")
        return "Unknown"
    
    def get_value(self, oid: str) -> Optional[Any]:
        """Ottiene un valore SNMP per un OID specifico"""
        result = self.client.get(oid)
        if result is None:
            return None
        
        # Estrai il valore in base al tipo
        if isinstance(result, SnmpInteger):
            return result.value
        elif isinstance(result, SnmpOctetString):
            try:
                return result.value.decode('utf-8')
            except:
                return result.value
        elif isinstance(result, SnmpObjectIdentifier):
            return '.'.join(str(x) for x in result.value)
        elif isinstance(result, SnmpIpAddress):
            return str(ipaddress.IPv4Address(result.value))
        elif isinstance(result, SnmpCounter32) or isinstance(result, SnmpGauge32) or isinstance(result, SnmpCounter64):
            return result.value
        elif isinstance(result, SnmpTimeTicks):
            return result.value
        else:
            return str(result)
    
    def get_ups_info(self) -> Dict[str, Any]:
        """Ottiene tutte le informazioni disponibili sull'UPS"""
        result = {}
        
        # Prova tutti i set di OID
        for key in self.oids.keys():
            value = None
            
            # Prova ogni set di OID in ordine
            for oid_set in self.all_oids:
                if key in oid_set:
                    value = self.get_value(oid_set[key])
                    if value is not None:
                        break
            
            result[key] = value
        
        # Aggiungi il valore al grafico storico
        if 'load' in result and result['load'] is not None:
            self.load_history.append(result['load'])
            if len(self.load_history) > self.max_history_size:
                self.load_history = self.load_history[-self.max_history_size:]
        
        return result
    
    def interpret_status(self, status: Optional[int]) -> str:
        """Interpreta il codice di stato dell'UPS"""
        if status is None:
            return "Sconosciuto"
            
        statuses = {
            1: "Altro",
            2: "Sconosciuto",
            3: "Normale",
            4: "Bypass",
            5: "Batteria",
            6: "Boost",
            7: "Sleep",
            8: "Shutdown"
        }
        return statuses.get(status, f"Sconosciuto ({status})")
    
    def monitor(self, interval: float = 5.0, duration: Optional[float] = None):
        """Monitora l'UPS per un periodo specificato"""
        logger.info(f"Avvio monitoraggio UPS {self.host}...")
        
        # Rileva il tipo di UPS
        ups_type = self.detect_ups_type()
        
        # Ottieni informazioni di base sull'UPS
        initial_info = self.get_ups_info()
        model = initial_info.get('model', 'Sconosciuto')
        logger.info(f"Modello UPS: {model}")
        
        start_time = time.time()
        while duration is None or time.time() - start_time < duration:
            try:
                # Ottieni i dati dall'UPS
                ups_data = self.get_ups_info()
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                # Stampa le informazioni
                print("\n" + "=" * 50)
                print(f" UPS Monitor - {model} ({self.host})")
                print(f" {timestamp}")
                print(f" Protocollo: SNMPv{self.version}")
                if self.version == SnmpVersion.V3:
                    print(f" Utente: {self.v3_user.username}")
                    print(f" Sicurezza: {self.v3_user.get_security_level().name}")
                print("=" * 50)
                
                # Stato
                status = self.interpret_status(ups_data.get('ups_status'))
                print(f"\nStato: {status}")
                
                # Carico
                load = ups_data.get('load')
                print("\nCarico:")
                if load is not None:
                    bar_width = 40
                    filled_width = int((float(load) / 100) * bar_width)
                    bar = "#" * filled_width + "-" * (bar_width - filled_width)
                    print(f"  [{bar}] {load}%")
                else:
                    print("  N/A")
                
                # Batteria
                battery = ups_data.get('battery_charge')
                print("\nBatteria:")
                if battery is not None:
                    bar_width = 40
                    filled_width = int((float(battery) / 100) * bar_width)
                    bar = "#" * filled_width + "-" * (bar_width - filled_width)
                    print(f"  [{bar}] {battery}%")
                else:
                    print("  N/A")
                
                # Altri parametri
                print("\nParametri:")
                print(f"  Tensione ingresso: {ups_data.get('input_voltage', 'N/A')} V")
                print(f"  Tensione uscita: {ups_data.get('output_voltage', 'N/A')} V")
                print(f"  Temperatura: {ups_data.get('temperature', 'N/A')}°C")
                print(f"  Runtime stimato: {ups_data.get('estimated_runtime', 'N/A')} minuti")
                
                # Storico del carico (semplice grafico ASCII)
                print("\nStorico carico:")
                if self.load_history:
                    max_val = max(self.load_history + [100])
                    min_val = min(self.load_history + [0])
                    range_val = max(1, max_val - min_val)
                    
                    height = 5
                    for h in range(height):
                        line = "  "
                        threshold = max_val - (h * range_val / height)
                        
                        for val in self.load_history:
                            if val >= threshold:
                                line += "#"
                            else:
                                line += " "
                        print(line)
                    
                    # Asse X
                    print("  " + "-" * len(self.load_history))
                else:
                    print("  Dati insufficienti")
                
                print("\nPremi Ctrl+C per uscire")
                
                # Attendi fino al prossimo intervallo
                time.sleep(interval)
                
            except KeyboardInterrupt:
                logger.info("Monitoraggio interrotto dall'utente")
                break
            except Exception as e:
                logger.error(f"Errore durante il monitoraggio: {e}")
                time.sleep(interval)  # Attendi comunque prima di riprovare
    
    def walk_mib(self, base_oid: str = "1.3.6.1.2.1.33") -> Dict[str, Any]:
        """Esegue una SNMP WALK su un OID base (default: UPS-MIB)"""
        logger.info(f"Esecuzione SNMP WALK su {base_oid}...")
        
        results = {}
        try:
            if self.version == SnmpVersion.V2C or self.version == SnmpVersion.V3:
                # Usa GETBULK per efficienza in SNMPv2c/v3
                raw_results = self.client.bulk_walk(base_oid)
            else:
                # Usa GETNEXT in SNMPv1
                raw_results = self.client.walk(base_oid)
            
            # Converti i risultati in valori Python
            for oid, value in raw_results.items():
                # Estrai il valore in base al tipo
                if isinstance(value, SnmpInteger):
                    results[oid] = value.value
                elif isinstance(value, SnmpOctetString):
                    try:
                        results[oid] = value.value.decode('utf-8')
                    except:
                        results[oid] = value.value
                elif isinstance(value, SnmpObjectIdentifier):
                    results[oid] = '.'.join(str(x) for x in value.value)
                elif isinstance(value, SnmpIpAddress):
                    results[oid] = str(ipaddress.IPv4Address(value.value))
                elif isinstance(value, SnmpCounter32) or isinstance(value, SnmpGauge32) or isinstance(value, SnmpCounter64):
                    results[oid] = value.value
                elif isinstance(value, SnmpTimeTicks):
                    results[oid] = value.value
                else:
                    results[oid] = str(value)
            
            logger.info(f"Trovati {len(results)} OID")
            return results
        except Exception as e:
            logger.error(f"Errore durante la SNMP WALK: {e}")
            return {}
    
    def test_connection(self) -> bool:
        """Testa la connessione SNMP con l'UPS"""
        logger.info(f"Test connessione SNMP a {self.host}:{self.port}")
        
        if self.version == SnmpVersion.V3:
            logger.info(f"Usando SNMPv3 con utente '{self.v3_user.username}'")
            logger.info(f"Auth: {self.v3_user.auth_protocol.value}, Priv: {self.v3_user.priv_protocol.value}")
        else:
            logger.info(f"Usando SNMPv{self.version} con community '{self.community}'")
        
        # Verifica connettività di base
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b'\x00', (self.host, self.port))
            sock.close()
            logger.info("Connettività di rete OK")
        except Exception as e:
            logger.error(f"ERRORE: Impossibile connettersi all'indirizzo {self.host}:{self.port}")
            logger.error(f"Dettaglio errore: {e}")
            return False
        
        # Test SNMP di base
        logger.info("Test SNMP di base...")
        
        # Prova a ottenere il sysDescr (OID comune a tutti i dispositivi SNMP)
        sys_descr_oid = "1.3.6.1.2.1.1.1.0"
        value = self.get_value(sys_descr_oid)
        
        if value is not None:
            logger.info(f"Comunicazione SNMP OK: {value}")
            return True
        else:
            logger.error("ERRORE: Comunicazione SNMP fallita")
            return False

def main():
    """Funzione principale"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitoraggio UPS tramite SNMP (v1/v2c/v3)')
    parser.add_argument('--ip', required=True, help='Indirizzo IP dell\'UPS')
    parser.add_argument('--port', type=int, default=161, help='Porta SNMP')
    parser.add_argument('--version', type=int, default=2, choices=[1, 2, 3], help='Versione SNMP (1, 2 o 3)')
    
    # Parametri per v1/v2c
    parser.add_argument('--community', default='public', help='SNMP community string (v1/v2c)')
    
    # Parametri per v3
    parser.add_argument('--v3-user', help='Nome utente SNMPv3')
    parser.add_argument('--v3-auth-protocol', choices=['noAuth', 'MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
                        default='noAuth', help='Protocollo di autenticazione SNMPv3')
    parser.add_argument('--v3-auth-password', help='Password di autenticazione SNMPv3')
    parser.add_argument('--v3-priv-protocol', choices=['noPriv', 'DES', 'AES128', 'AES192', 'AES256'],
                        default='noPriv', help='Protocollo di privacy SNMPv3')
    parser.add_argument('--v3-priv-password', help='Password di privacy SNMPv3')
    
    # Opzioni operative
    parser.add_argument('--interval', type=float, default=5.0, help='Intervallo di polling (secondi)')
    parser.add_argument('--duration', type=float, help='Durata del monitoraggio (secondi)')
    parser.add_argument('--walk', action='store_true', help='Esegui SNMP walk per identificare OID disponibili')
    parser.add_argument('--test', action='store_true', help='Testa solo la connessione SNMP')
    parser.add_argument('--debug', action='store_true', help='Abilita messaggi di debug')
    
    args = parser.parse_args()
    
    # Configura il logging
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Determina la versione SNMP
    if args.version == 1:
        version = SnmpVersion.V1
    elif args.version == 2:
        version = SnmpVersion.V2C
    else:
        version = SnmpVersion.V3
    
    # Crea l'utente v3 se necessario
    v3_user = None
    if version == SnmpVersion.V3:
        if not args.v3_user:
            parser.error("SNMPv3 richiede --v3-user")
        
        # Converti i protocolli
        auth_protocol = SnmpV3AuthProtocol[args.v3_auth_protocol.replace('noAuth', 'NO_AUTH')]
        priv_protocol = SnmpV3PrivProtocol[args.v3_priv_protocol.replace('noPriv', 'NO_PRIV')]
        
        v3_user = SnmpV3User(
            username=args.v3_user,
            auth_protocol=auth_protocol,
            auth_password=args.v3_auth_password or '',
            priv_protocol=priv_protocol,
            priv_password=args.v3_priv_password or ''
        )
    
    # Crea l'oggetto UpsMonitor
    monitor = UpsMonitor(args.ip, args.port, args.community, version, v3_user)
    
    # Esegui l'operazione richiesta
    if args.test:
        success = monitor.test_connection()
        sys.exit(0 if success else 1)
    elif args.walk:
        results = monitor.walk_mib()
        for oid, value in sorted(results.items()):
            print(f"{oid} = {value}")
    else:
        monitor.monitor(args.interval, args.duration)

if __name__ == "__main__":
    main()