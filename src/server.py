import socket 
import struct # pack unpack donne binaire
import zlib # CRC32
import time # timestamp
import select #surveille socket sans bloquer
import os
import argparse 
import sys # pour print_err


def print_err(msg):
    print(msg, file=sys.stderr)

def encode_header(packet_type, window, length, seqnum, timestamp):
    
    header_int = (packet_type << 30) | (window << 24) | (length << 11) | seqnum
    
    partial_header = struct.pack("!II", header_int, timestamp)
    
    crc1 = zlib.crc32(partial_header)
    return partial_header + struct.pack("!I", crc1) #nombre de I = nbr d'entier de 32 bits

def decode_header(header_bytes):
    
    if len(header_bytes) != 12:
        raise ValueError("header != 12 octet")
        
    header_int, timestamp, crc1_recu = struct.unpack("!III", header_bytes)
    
    if zlib.crc32(header_bytes[:8]) != crc1_recu:
        raise ValueError("Erreur CRC1")
        
    packet_type = (header_int >> 30) & 0x3
    window = (header_int >> 24) & 0x3F
    length = (header_int >> 11) & 0x1FFF
    seqnum = header_int & 0x7FF
    
    return packet_type, window, length, seqnum, timestamp

def construire_paquet(packet_type, window, seqnum, timestamp, payload=b""):
    length = len(payload)
    entete = encode_header(packet_type, window, length, seqnum, timestamp)
    
    if length == 0:
        return entete
        
    crc2_bytes = struct.pack("!I", zlib.crc32(payload))
    return entete + payload + crc2_bytes

def lire_paquet_recu(paquet_bytes):
    if len(paquet_bytes) < 12:
        raise ValueError("Paquet trop court")
    p_type, p_win, p_len, p_seq, p_time = decode_header(paquet_bytes[:12])
    if p_len == 0:
        return p_type, p_win, p_len, p_seq, p_time, b""
    taille_attendue = 12 + p_len + 4
    if len(paquet_bytes) < taille_attendue:
        raise ValueError("Paquet tronqué")
    payload = paquet_bytes[12 : 12+p_len]
    crc2_recu = struct.unpack("!I", paquet_bytes[12+p_len : 12+p_len+4])[0]
    if zlib.crc32(payload) != crc2_recu:
        raise ValueError("Erreur CRC2")
    return p_type, p_win, p_len, p_seq, p_time, payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Serveur SRTP C'Hokayy")
    parser.add_argument("hostname", type=str, help="Adresse IPv6 ou nom de domaine")
    parser.add_argument("port", type=int, help="Port d'écoute du serveur")
    parser.add_argument("--root", type=str, default=".", help="Dossier racine pour les fichiers")
    args = parser.parse_args()

    HOST = args.hostname
    PORT = args.port
    RACINE = args.root
    TIMEOUT = 2.0
    MAX_PAYLOAD = 1024 

    serveur_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    serveur_socket.bind((HOST, PORT))

    print_err(f" Serveur SRTP en écoute sur [{HOST}]:{PORT} (Racine: {RACINE})")

    while True: 
        print_err("\nEn attente d'une requête HTTP 0.9...")
        
        while True:
            paquet_requete, adresse_client = serveur_socket.recvfrom(2000)
            try:
                p_type, p_win, p_len, p_seq, p_time, payload = lire_paquet_recu(paquet_requete)
                if p_type == 1 and payload:
                    requete_str = payload.decode('ascii')
                    if requete_str.startswith("GET "): 
                        chemin_demande = requete_str.split(" ")[1].lstrip('/')
                        chemin_complet = os.path.join(RACINE, chemin_demande) 
                        print_err(f"📞 Requête reçue de {adresse_client} : {requete_str}")
                        break 
            except ValueError:
                pass


        window_client = 1 
        
        morceaux_fichier = []
        if os.path.exists(chemin_complet) and os.path.isfile(chemin_complet):
            print_err(f"📂 Fichier trouvé. Découpage en cours...")
            with open(chemin_complet, "rb") as f:
                while True:
                    chunk = f.read(MAX_PAYLOAD)
                    if not chunk:
                        break
                    morceaux_fichier.append(chunk)
        else:
            print_err(f"Fichier introuvable ({chemin_complet}). Fin de connexion.")

        paquets_en_vol = {}
        prochain_index_a_envoyer = 0
        total_morceaux = len(morceaux_fichier)
        seqnum_actuel = (p_seq + 1) % 2048 
        transfert_fini = False

        print_err(f" Début de l'envoi ({total_morceaux} paquets)...")

        while not transfert_fini:
            
            ready = select.select([serveur_socket], [], [], 0.05)
            if ready[0]:
                ack_bytes, _ = serveur_socket.recvfrom(1024)
                try:
                    a_type, a_win, a_len, a_seq, a_time, _ = lire_paquet_recu(ack_bytes)
                    if a_type == 2: 
                        
                        window_client = a_win
                        
                        seqnums_en_vol = list(paquets_en_vol.keys())
                        for seq in seqnums_en_vol:
                            distance = (a_seq - seq) % 2048
                            if distance < 1024 and distance > 0: 
                                del paquets_en_vol[seq]
                except ValueError:
                    pass

           
            temps_actuel = time.time()
            for seq, infos in paquets_en_vol.items():
                if temps_actuel - infos['heure_envoi'] > TIMEOUT:
                    serveur_socket.sendto(infos['paquet_bytes'], adresse_client)
                    infos['heure_envoi'] = temps_actuel 

            
            while len(paquets_en_vol) < window_client and prochain_index_a_envoyer < total_morceaux:
                donnees = morceaux_fichier[prochain_index_a_envoyer]
                nouveau_paquet = construire_paquet(1, 0, seqnum_actuel, int(time.time()), donnees)
                
                paquets_en_vol[seqnum_actuel] = {
                    'paquet_bytes': nouveau_paquet,
                    'heure_envoi': time.time()
                }
                serveur_socket.sendto(nouveau_paquet, adresse_client)
                
                prochain_index_a_envoyer += 1
                seqnum_actuel = (seqnum_actuel + 1) % 2048 

            if prochain_index_a_envoyer == total_morceaux and len(paquets_en_vol) == 0:
                paquet_fin = construire_paquet(1, 0, seqnum_actuel, int(time.time()), b"")
                for _ in range(5): 
                    serveur_socket.sendto(paquet_fin, adresse_client)
                    time.sleep(0.05)
                print_err(" Tous les paquets ont été acquittés. Fin de la session.")
                transfert_fini = True
