import socket
import struct
import zlib
import time
import argparse
import sys
import math
from urllib.parse import urlparse


def print_err(msg):
    print(msg, file=sys.stderr)

# --- fonctions de décodage et de décodage ----------------------------------------------

"""Encode une en-tête SRTP (12 octets) : Header32 | Timestamp | CRC1"""
def encode_header(packet_type, window, length, seqnum, timestamp):
    header_int = (packet_type << 30) | (window << 24) | (length << 11) | seqnum
    partial_header = struct.pack("!II", header_int, timestamp)
    crc1 = zlib.crc32(partial_header) & 0xFFFFFFFF
    return partial_header + struct.pack("!I", crc1)

"""Décode un en-tête SRTP (12 octets). ValueError si CRC1 invalide."""
def decode_header(header_bytes):
    if len(header_bytes) != 12:
        raise ValueError("L'en-tête ne fait pas 12 octets")
    header_int, timestamp, crc1_recu = struct.unpack("!III", header_bytes)
    if (zlib.crc32(header_bytes[:8]) & 0xFFFFFFFF) != crc1_recu:
        raise ValueError("Erreur CRC1 : en-tête corrompu")
    packet_type = (header_int >> 30) & 0x3
    window = (header_int >> 24) & 0x3F
    length = (header_int >> 11) & 0x1FFF
    seqnum = header_int & 0x7FF
    return packet_type, window, length, seqnum, timestamp

"""Construit un paquet SRTP complet (en-tête + payload + CRC2)"""
def construire_paquet(packet_type, window, seqnum, timestamp, payload=b""):
    length = len(payload)
    entete = encode_header(packet_type, window, length, seqnum, timestamp)
    if length == 0:
        return entete
    crc2 = struct.pack("!I", zlib.crc32(payload) & 0xFFFFFFFF)
    return entete + payload + crc2

"""décode un paquet SRTP complet. Lève ValueError si le paqeut est invalide."""
def lire_paquet_recu(paquet_bytes):
    if len(paquet_bytes) < 12:
        raise ValueError("Paquet trop court")
    p_type, p_win, p_len, p_seq, p_time = decode_header(paquet_bytes[:12])

    # Ignorer les paquets avec Length > 1024 (spécification)
    if p_len > 1024:
        raise ValueError("Length > 1024 : paquet ignoré")

    if p_len == 0:
        return p_type, p_win, p_len, p_seq, p_time, b""

    taille_attendue = 12 + p_len + 4
    if len(paquet_bytes) < taille_attendue:
        raise ValueError("Paquet tronqué par le réseau")

    payload = paquet_bytes[12: 12 + p_len]
    crc2_recu = struct.unpack("!I", paquet_bytes[12 + p_len: 12 + p_len + 4])[0]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc2_recu:
        raise ValueError("Erreur CRC2 : payload corrompu")

    return p_type, p_win, p_len, p_seq, p_time, payload


"""Encode une liste de seqnums (11 bits chacun) en payload SACK, paddé à 4 octets."""
def encode_sack_payload(seqnums):
    if not seqnums:
        return b""
    total_bits = len(seqnums) * 11
    total_bytes = (total_bits + 7) // 8
    # Padding à un multiple de 4 octets
    padded_bytes = ((total_bytes + 3) // 4) * 4

    bitstream = 0
    for seq in seqnums:
        bitstream = (bitstream << 11) | (seq & 0x7FF)

    remaining_bits = padded_bytes * 8 - total_bits
    bitstream <<= remaining_bits

    return bitstream.to_bytes(padded_bytes, 'big')

    
    """ Si le buffer_reception contient des paquets hors-séquence, envoie un SACK 
    avec les seqnums reçus hors-séquence. Sinon il envoie un ACK classique """
def envoyer_ack(sock, adresse_dest, prochain_seqnum_attendu, timestamp_recu, espaces_libres, buffer_reception=None):
    window_client = min(63, max(0, espaces_libres))

    seqnums_hors_seq = []
    if buffer_reception:
        seqnums_hors_seq = sorted(buffer_reception.keys(),
                                  key=lambda s: (s - prochain_seqnum_attendu) % 2048)
        # Limiter à 744 seqnums maximum
    seqnums_hors_seq = seqnums_hors_seq[:744]

    if seqnums_hors_seq:
        # PTYPE_SACK = 3
        sack_payload = encode_sack_payload(seqnums_hors_seq)
        paquet = construire_paquet(3, window_client, prochain_seqnum_attendu,
                                   timestamp_recu, sack_payload)
    else:
        # PTYPE_ACK = 2
        entete_ack = encode_header(2, window_client, 0, prochain_seqnum_attendu,
                                   timestamp_recu)
        paquet = entete_ack

    sock.sendto(paquet, adresse_dest)


def seq_distance(a, b):
    return (a - b) % 2048


# --- programme main -------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client SRTP")
    parser.add_argument("servername", type=str, help="URL du serveur (ex: http://[::1]:8080/llm/small)")
    parser.add_argument("--save", type=str, default="llm.model", help="Chemin du fichier de sauvegarde (défaut: llm.model)")
    args = parser.parse_args()

    url_decodee = urlparse(args.servername)
    DEST_HOST = url_decodee.hostname
    DEST_PORT = url_decodee.port if url_decodee.port else 8080
    CHEMIN_DEMANDE = url_decodee.path
    FICHIER_SORTIE = args.save

    MAX_WINDOW = 63
    MAX_RETRIES_REQUETE = 10
    RECV_TIMEOUT = 5.0

    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client_socket.settimeout(RECV_TIMEOUT)

    # Envoi de la requete
    requete_http = f"GET {CHEMIN_DEMANDE}".encode('ascii')
    ts_requete = int(time.time() * 1000) & 0xFFFFFFFF
    paquet_requete = construire_paquet(1, MAX_WINDOW, 0, ts_requete, requete_http)

    dest_addr = (DEST_HOST, DEST_PORT)
    client_socket.sendto(paquet_requete, dest_addr)
    print_err(f"Requête envoyée : GET {CHEMIN_DEMANDE} vers [{DEST_HOST}]:{DEST_PORT}")

    # Boucle de réception
    seqnum_attendu = 1  # Le prochain seqnum attendu
    buffer_reception = {}
    transfert_termine = False
    nb_retries = 0

    try:
        fichier = open(FICHIER_SORTIE, "wb")
        print_err(f"Attente du fichier (sauvegarde dans {FICHIER_SORTIE})...")

        while not transfert_termine:
            try:
                paquet, adresse_serveur = client_socket.recvfrom(2000)
            except socket.timeout:
                # Retransmission de la requête si le serveur ne répond pas 
                nb_retries += 1
                if nb_retries > MAX_RETRIES_REQUETE:
                    print_err("Timeout critique : nombre maximal de retransmissions atteint.")
                    break
                print_err(f"Timeout — retransmission de la requête ({nb_retries}/{MAX_RETRIES_REQUETE})")
                ts_requete = int(time.time() * 1000) & 0xFFFFFFFF
                paquet_requete = construire_paquet(1, MAX_WINDOW, 0, ts_requete, requete_http)
                client_socket.sendto(paquet_requete, dest_addr)
                continue

            try:
                p_type, p_win, p_len, p_seq, p_time, payload = lire_paquet_recu(paquet)

                # on attends que du p_type = 1 du serveur
                if p_type != 1:
                    continue

                # Paquet de fin de transfert 
                if p_len == 0 and p_seq == seqnum_attendu:
                    print_err("Transfert terminé !")
                    envoyer_ack(client_socket, adresse_serveur, (p_seq + 1) % 2048, p_time, MAX_WINDOW)
                    transfert_termine = True
                    break

                # Paquet de données
                if p_len > 0:
                    distance = seq_distance(p_seq, seqnum_attendu)

                    # La fenêtre de réception = places vides dans le buffer
                    # Un paquet est dans la fenêtre si 0 <= distance < window_annoncee
                    places_restantes = MAX_WINDOW - len(buffer_reception)
                    fenetre_recep = max(1, places_restantes)  # au moins 1 pour le paquet en séquence
                    
                    # Paquet attendu
                    if distance == 0:  
                        fichier.write(payload)
                        seqnum_attendu = (seqnum_attendu + 1) % 2048

                        # Vider les paquets consécutifs du buffer
                        while seqnum_attendu in buffer_reception:
                            fichier.write(buffer_reception.pop(seqnum_attendu))
                            seqnum_attendu = (seqnum_attendu + 1) % 2048

                    elif 0 < distance < fenetre_recep:
                        # Paquet dans la fenêtre mais hors-séquence → buffer
                        if p_seq not in buffer_reception:
                            buffer_reception[p_seq] = payload

                    else:
                        pass

                    places_restantes = MAX_WINDOW - len(buffer_reception)
                    envoyer_ack(client_socket, adresse_serveur, seqnum_attendu,
                                p_time, places_restantes, buffer_reception)

                    # Réinitialiser le compteur de retries dès qu'on reçoit des données
                    nb_retries = 0

            except ValueError:
                # on ignore les paquets invalides
                pass

    finally:
        fichier.close()
        client_socket.close()
        print_err("Client terminé.")
