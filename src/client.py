import socket
import struct
import zlib
import time
import argparse
import sys
from urllib.parse import urlparse

def print_err(msg):
    print(msg, file=sys.stderr)

def encode_header(packet_type, window, length, seqnum, timestamp):
    header_int = (packet_type << 30) | (window << 24) | (length << 11) | seqnum
    partial_header = struct.pack("!II", header_int, timestamp)
    crc1 = zlib.crc32(partial_header)
    return partial_header + struct.pack("!I", crc1)

def decode_header(header_bytes):
    if len(header_bytes) != 12:
        raise ValueError("L'entête ne fait pas 12 octets !")
    header_int, timestamp, crc1_recu = struct.unpack("!III", header_bytes)
    if zlib.crc32(header_bytes[:8]) != crc1_recu:
        raise ValueError("Erreur CRC1 : entête corrompu !")
    packet_type = (header_int >> 30) & 0x3
    window = (header_int >> 24) & 0x3F
    length = (header_int >> 11) & 0x1FFF
    seqnum = header_int & 0x7FF
    return packet_type, window, length, seqnum, timestamp

def lire_paquet_recu(paquet_bytes):
    if len(paquet_bytes) < 12:
        raise ValueError("Paquet trop court !")
    p_type, p_win, p_len, p_seq, p_time = decode_header(paquet_bytes[:12])
    
    if p_len == 0:
        return p_type, p_win, p_len, p_seq, p_time, b""
        
    taille_attendue = 12 + p_len + 4 
    if len(paquet_bytes) < taille_attendue:
        raise ValueError("Paquet tronqué par le réseau !")
        
    payload = paquet_bytes[12 : 12+p_len]
    crc2_recu = struct.unpack("!I", paquet_bytes[12+p_len : 12+p_len+4])[0]
    
    if zlib.crc32(payload) != crc2_recu:
        raise ValueError("Erreur CRC2 : payload corrompu !")
        
    return p_type, p_win, p_len, p_seq, p_time, payload

def envoyer_ack(sock, adresse_dest, prochain_seqnum_attendu, timestamp_recu, espaces_libres):
    window_client = min(63, max(0, espaces_libres))
    entete_ack = encode_header(2, window_client, 0, prochain_seqnum_attendu, timestamp_recu)
    sock.sendto(entete_ack, adresse_dest)






if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client SRTP C'Hokayy")
    parser.add_argument("servername", type=str, help="URL du serveur (ex: http://[::1]:8080/llm/small)")
    parser.add_argument("--save", type=str, default="11m.model", help="Chemin du fichier de sauvegarde")
    args = parser.parse_args()

    url_decodee = urlparse(args.servername)
    DEST_HOST = url_decodee.hostname 
    DEST_PORT = url_decodee.port if url_decodee.port else 8080
    CHEMIN_DEMANDE = url_decodee.path
    FICHIER_SORTIE = args.save

    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client_socket.settimeout(5.0) 

    
    requete_http = f"GET {CHEMIN_DEMANDE}".encode('ascii')
  
    entete_requete = encode_header(1, 63, len(requete_http), 0, int(time.time()))
    crc2_requete = struct.pack("!I", zlib.crc32(requete_http))
    client_socket.sendto(entete_requete + requete_http + crc2_requete, (DEST_HOST, DEST_PORT))
    print_err(f" Requête envoyée : GET {CHEMIN_DEMANDE} vers [{DEST_HOST}]:{DEST_PORT}")

 
    seqnum_attendu = 1 
    buffer_reception = {} 
    transfert_termine = False

    try:
        fichier = open(FICHIER_SORTIE, "wb")
        print_err(f" Attente du fichier (sauvegarde dans {FICHIER_SORTIE})...")

        while not transfert_termine:
            try:
                paquet, adresse_serveur = client_socket.recvfrom(2000)
            except socket.timeout:
                print_err(" Timeout critique : Le serveur ne répond plus.")
                break
            
            try:
                p_type, p_win, p_len, p_seq, p_time, payload = lire_paquet_recu(paquet)
                
                if p_type == 1: 
                    
                    if p_len == 0 and p_seq == seqnum_attendu: 
                        print_err("Paquet de fin (Length=0) reçu. Transfert terminé !")
                        envoyer_ack(client_socket, adresse_serveur, (p_seq + 1) % 2048, p_time, 63)
                        transfert_termine = True
                        break
                        
                    distance = (p_seq - seqnum_attendu) % 2048
                    
                    if p_seq == seqnum_attendu and p_len > 0:
           
                        fichier.write(payload)
                        seqnum_attendu = (seqnum_attendu + 1) % 2048
                        

                        while seqnum_attendu in buffer_reception:
                            fichier.write(buffer_reception.pop(seqnum_attendu))
                            seqnum_attendu = (seqnum_attendu + 1) % 2048
                            
                        places_restantes = 63 - len(buffer_reception)
                        envoyer_ack(client_socket, adresse_serveur, seqnum_attendu, p_time, places_restantes)
                        
                    elif 0 < distance < 64 and p_len > 0:
                    
                        buffer_reception[p_seq] = payload
                        places_restantes = 63 - len(buffer_reception)
                        envoyer_ack(client_socket, adresse_serveur, seqnum_attendu, p_time, places_restantes)
                    else:
     
                        places_restantes = 63 - len(buffer_reception)
                        envoyer_ack(client_socket, adresse_serveur, seqnum_attendu, p_time, places_restantes)
                        
            except ValueError:
                pass 

    finally:
        fichier.close()
        client_socket.close()
