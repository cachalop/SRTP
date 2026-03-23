import sys
import os
import struct
import zlib
import pytest


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))


from server import encode_header, decode_header, construire_paquet, lire_paquet_recu

def test_encodage_decodage_symetrique():
  
    p_type, p_win, p_len, p_seq, p_time = 1, 63, 1024, 2047, 123456789
    
    header_bytes = encode_header(p_type, p_win, p_len, p_seq, p_time)
    r_type, r_win, r_len, r_seq, r_time = decode_header(header_bytes)
    
    assert p_type == r_type
    assert p_win == r_win
    assert p_len == r_len
    assert p_seq == r_seq
    assert p_time == r_time

def test_erreur_crc1_entete_corrompu():
  
    header_bytes = bytearray(encode_header(1, 63, 1024, 0, 9999))
    
    
    header_bytes[0] ^= 0xFF 
    
    
    with pytest.raises(ValueError, match="Erreur CRC1"):
        decode_header(bytes(header_bytes))

def test_construction_paquet_complet():
    
    payload = b"Hello World!"
    paquet = construire_paquet(1, 30, 5, 1111, payload)
    

    taille_attendue = 12 + len(payload) + 4
    assert len(paquet) == taille_attendue

def test_erreur_crc2_donnees_corrompues():

    payload = b"Message secret"
    paquet_bytes = bytearray(construire_paquet(1, 30, 5, 1111, payload))
    

    paquet_bytes[15] = ord('X')
    
    with pytest.raises(ValueError, match="Erreur CRC2"):
        lire_paquet_recu(bytes(paquet_bytes))

def test_paquet_ack_sans_payload():

    ack_bytes = construire_paquet(2, 63, 10, 8888, b"")
    
    assert len(ack_bytes) == 12
    
    p_type, p_win, p_len, p_seq, p_time, payload = lire_paquet_recu(ack_bytes)
    
    assert p_type == 2
    assert p_len == 0
    assert payload == b""

def test_paquet_tronque():
  
    payload = b"Un texte assez long qui va etre coupe"
    paquet_bytes = construire_paquet(1, 30, 5, 1111, payload)
    
    paquet_tronque = paquet_bytes[:20]
    
    with pytest.raises(ValueError, match="tronqué"):
        lire_paquet_recu(paquet_tronque)
