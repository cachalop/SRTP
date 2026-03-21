from src.packet import Packet, PTYPE_DATA


# Vérifie qu’un paquet DATA simple s’encode et se décode correctement
def test_encode_decode():
    p = Packet(PTYPE_DATA, 3, 10, b"abc", 123)
    raw = p.encode()
    q = Packet.decode(raw)

    assert q is not None
    assert q.ptype == PTYPE_DATA
    assert q.window == 3
    assert q.seqnum == 10
    assert q.payload == b"abc"
    assert q.timestamp == 123


import zlib
from src.packet import Packet, PTYPE_DATA, PTYPE_ACK


# Vérifie le cas d’un ACK (pas de payload)
def test_ack_encode_decode():
    p = Packet(PTYPE_ACK, 8, 99, b"", 456)
    q = Packet.decode(p.encode())

    assert q is not None
    assert q.ptype == PTYPE_ACK
    assert q.window == 8
    assert q.seqnum == 99
    assert q.payload == b""
    assert q.timestamp == 456


# CRC1 corrompu → paquet rejeté
def test_bad_crc1_is_rejected():
    p = Packet(PTYPE_DATA, 1, 2, b"hello", 42)
    raw = bytearray(p.encode())
    raw[0] ^= 1

    assert Packet.decode(bytes(raw)) is None


# CRC2 corrompu → payload rejeté
def test_bad_crc2_is_rejected():
    p = Packet(PTYPE_DATA, 1, 2, b"hello", 42)
    raw = bytearray(p.encode())
    raw[-1] ^= 1

    assert Packet.decode(bytes(raw)) is None


# Paquet tronqué → rejeté
def test_truncated_packet_is_rejected():
    p = Packet(PTYPE_DATA, 1, 2, b"hello", 42)
    raw = p.encode()[:-2]

    assert Packet.decode(raw) is None


# Type invalide → paquet rejeté
def test_invalid_type_is_rejected():
    p = Packet(PTYPE_DATA, 1, 2, b"hello", 42)
    raw = bytearray(p.encode())

    first_word = int.from_bytes(raw[:4], "big")
    window = (first_word >> 24) & 0x3F
    length = (first_word >> 11) & 0x1FFF
    seqnum = first_word & 0x7FF

    invalid_word = (0 << 30) | (window << 24) | (length << 11) | seqnum
    raw[:4] = invalid_word.to_bytes(4, "big")

    crc1 = zlib.crc32(bytes(raw[:8])) & 0xFFFFFFFF
    raw[8:12] = crc1.to_bytes(4, "big")

    assert Packet.decode(bytes(raw)) is None


# DATA valide avec payload vide
def test_empty_data_packet_encode_decode():
    p = Packet(PTYPE_DATA, 4, 7, b"", 999)
    q = Packet.decode(p.encode())

    assert q is not None
    assert q.ptype == PTYPE_DATA
    assert q.window == 4
    assert q.seqnum == 7
    assert q.payload == b""
    assert q.timestamp == 999


# Longueur incohérente → paquet rejeté
def test_invalid_length_is_rejected():
    import zlib

    p = Packet(PTYPE_DATA, 1, 2, b"abc", 42)
    raw = bytearray(p.encode())

    first_word = int.from_bytes(raw[:4], "big")
    ptype = (first_word >> 30) & 0x3
    window = (first_word >> 24) & 0x3F
    seqnum = first_word & 0x7FF

    invalid_length = 1025
    bad_word = (ptype << 30) | (window << 24) | (invalid_length << 11) | seqnum
    raw[:4] = bad_word.to_bytes(4, "big")

    crc1 = zlib.crc32(bytes(raw[:8])) & 0xFFFFFFFF
    raw[8:12] = crc1.to_bytes(4, "big")

    assert Packet.decode(bytes(raw)) is None