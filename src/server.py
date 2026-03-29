import socket
import struct
import zlib
import time
import select
import os
import argparse
import sys
import math


def print_err(msg):
    print(msg, file=sys.stderr)


# Construction et lecture des paquets SRTP

def encode_header(type_pkt, fenetre, longueur, seq, timestamp):
    # Regroupe les champs dans un entier 32 bits
    header_int = (type_pkt << 30) | (fenetre << 24) | (longueur << 11) | seq
    
    # Encodage header + timestamp
    debut = struct.pack("!II", header_int, timestamp)
    
    # CRC sur ces 8 octets
    crc1 = zlib.crc32(debut) & 0xFFFFFFFF
    
    return debut + struct.pack("!I", crc1)


def decode_header(header_bytes):
    # Vérifie la taille
    if len(header_bytes) != 12:
        raise ValueError("L'en-tête ne fait pas 12 octets")

    # Décodage brut
    header_int, timestamp, crc1_recu = struct.unpack("!III", header_bytes)

    # Vérification CRC
    if (zlib.crc32(header_bytes[:8]) & 0xFFFFFFFF) != crc1_recu:
        raise ValueError("Erreur CRC1")

    # Extraction des champs
    type_pkt = (header_int >> 30) & 0x3
    fenetre = (header_int >> 24) & 0x3F
    longueur = (header_int >> 11) & 0x1FFF
    seq = header_int & 0x7FF

    return type_pkt, fenetre, longueur, seq, timestamp


def construire_paquet(type_pkt, fenetre, seq, timestamp, payload=b""):
    # Taille du payload
    longueur = len(payload)

    # Header
    entete = encode_header(type_pkt, fenetre, longueur, seq, timestamp)

    # Si pas de données alors juste header
    if longueur == 0:
        return entete

    # CRC sur payload
    crc2 = struct.pack("!I", zlib.crc32(payload) & 0xFFFFFFFF)

    return entete + payload + crc2


def lire_paquet_recu(paquet_bytes):
    # Vérifie taille minimale
    if len(paquet_bytes) < 12:
        raise ValueError("Paquet trop court")

    # Lecture header
    p_type, p_win, p_len, p_seq, p_time = decode_header(paquet_bytes[:12])

    # Ignore paquet trop gros
    if p_len > 1024:
        raise ValueError("Length > 1024 : paquet ignoré")

    # Paquet vide (fin)
    if p_len == 0:
        return p_type, p_win, p_len, p_seq, p_time, b""

    # Vérifie taille complète
    taille_attendue = 12 + p_len + 4
    if len(paquet_bytes) < taille_attendue:
        raise ValueError("Paquet tronqué")

    # Extraction du payload
    payload = paquet_bytes[12: 12 + p_len]

    # Vérification CRC2
    crc2_recu = struct.unpack("!I", paquet_bytes[12 + p_len: 12 + p_len + 4])[0]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc2_recu:
        raise ValueError("Erreur CRC2")

    return p_type, p_win, p_len, p_seq, p_time, payload


# Lecture du payload SACK

def lire_sack(payload):
    if not payload:
        return []

    # Nombre total de bits
    total_bits = len(payload) * 8

    # Nombre de seqnums (11 bits chacun)
    nb = total_bits // 11

    bits = int.from_bytes(payload, 'big')

    res = []
    for i in range(nb):
        # Découpe bloc de 11 bits
        shift = total_bits - (i + 1) * 11
        seq = (bits >> shift) & 0x7FF
        res.append(seq)

    return res


# Estimation du timeout

class RTT:
    def __init__(self, rto_initial=2.0):
        self.srtt = None
        self.rttvar = None
        self.rto = rto_initial
        self.alpha = 0.125
        self.beta = 0.25
        self.min_rto = 0.2
        self.max_rto = 5.0

    def update(self, val):
        # Exception
        if val <= 0:
            return

        # Premier échantillon
        if self.srtt is None:
            self.srtt = val
            self.rttvar = val / 2.0
        else:
            # Mise à jour 
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * abs(self.srtt - val)
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * val

        # Calcul du RTO
        self.rto = max(self.min_rto, min(self.max_rto, self.srtt + 4 * self.rttvar))


# Serveur principal

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Serveur SRTP")
    parser.add_argument("hostname", type=str, help="Adresse IPv6 ou nom de domaine")
    parser.add_argument("port", type=int, help="Port d'écoute du serveur")
    parser.add_argument("--root", type=str, default=".",
                        help="Dossier racine pour les fichiers")
    args = parser.parse_args()

    HOST = args.hostname
    PORT = args.port
    RACINE = args.root
    MAX_PAYLOAD = 1024

    # Socket UDP IPv6
    serveur_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    serveur_socket.bind((HOST, PORT))

    print_err(f"Serveur SRTP en écoute sur [{HOST}]:{PORT} (Racine: {RACINE})")

    while True:
        print_err("\nEn attente d'une requête HTTP 0.9...")

        # Attente d'un GET valide
        while True:
            paquet_requete, adresse_client = serveur_socket.recvfrom(2000)
            try:
                p_type, p_win, p_len, p_seq, p_time, payload = lire_paquet_recu(paquet_requete)
                if p_type == 1 and payload:
                    requete_str = payload.decode('ascii')
                    if requete_str.startswith("GET "):
                        chemin_demande = requete_str[4:].lstrip('/')
                        chemin_complet = os.path.join(RACINE, chemin_demande)
                        print_err(f"Requête reçue de {adresse_client} : {requete_str}")
                        break
            except (ValueError, UnicodeDecodeError):
                pass

        # Fenêtre annoncée par le client
        fenetre_client = p_win if p_win > 0 else 1

        # Lecture du fichier demandé
        blocs = []
        if os.path.exists(chemin_complet) and os.path.isfile(chemin_complet):
            print_err(f"Fichier trouvé : {chemin_complet}")
            with open(chemin_complet, "rb") as f:
                while True:
                    bloc = f.read(MAX_PAYLOAD)
                    if not bloc:
                        break
                    blocs.append(bloc)
        else:
            # Si fichier absent alors on envoie juste un paquet vide
            print_err(f"Fichier introuvable ({chemin_complet}). Envoi du paquet de fin.")

        total_blocs = len(blocs)
        print_err(f"Début de l'envoi ({total_blocs} paquets de données)...")

        en_vol = {}          
        sack_recus = set()   # seqnums déjà reçus (SACK)
        i_bloc = 0           # index du prochain bloc
        seq_courant = (p_seq + 1) % 2048
        base_seqnum = seq_courant
        rtt = RTT()
        transfert_fini = False
        fin_envoyee = False

        while not transfert_fini:

            # Lecture des ACK/SACK
            pret = select.select([serveur_socket], [], [], 0.01)
            if pret[0]:
                ack_bytes, ack_addr = serveur_socket.recvfrom(2000)
                try:
                    a_type, a_win, a_len, a_seq, a_time, a_payload = lire_paquet_recu(ack_bytes)

                    if a_type in (2, 3):
                        # Mise à jour fenêtre
                        fenetre_client = a_win

                        # Calcul RTT
                        ts_now = int(time.time() * 1000) & 0xFFFFFFFF
                        rtt_ms = (ts_now - a_time) & 0xFFFFFFFF

                        if rtt_ms < 10000:
                            ok = True
                            for seq in en_vol:
                                dist = (a_seq - seq) % 2048
                                if 0 < dist <= 1024:
                                    if en_vol[seq].get('retransmis', False):
                                        ok = False
                                        break
                            if ok:
                                rtt.update(rtt_ms / 1000.0)

                        # ACK cumulatif → on supprime
                        a_supprimer = []
                        for seq in en_vol:
                            dist = (a_seq - seq) % 2048
                            if 0 < dist <= 1024:
                                a_supprimer.append(seq)

                        for seq in a_supprimer:
                            del en_vol[seq]
                            sack_recus.discard(seq)

                        base_seqnum = a_seq

                        # Traitement SACK
                        if a_type == 3 and a_payload:
                            sack_list = lire_sack(a_payload)
                            for s in sack_list:
                                sack_recus.add(s)

                    elif a_type == 1:
                        # Ignore nouveau GET
                        pass

                except ValueError:
                    pass

            # 2. Retransmissions
            maintenant = time.time()
            delai = rtt.rto

            for seq, infos in list(en_vol.items()):
                if seq in sack_recus:
                    continue
                if maintenant - infos['heure_envoi'] > delai:
                    serveur_socket.sendto(infos['paquet_bytes'], adresse_client)
                    infos['heure_envoi'] = maintenant
                    infos['retransmis'] = True

            # 3. Envoi de nouveaux paquets
            if fenetre_client > 0:
                while len(en_vol) < fenetre_client and i_bloc < total_blocs:
                    donnees = blocs[i_bloc]
                    ts = int(time.time() * 1000) & 0xFFFFFFFF

                    paquet = construire_paquet(1, 0, seq_courant, ts, donnees)

                    en_vol[seq_courant] = {
                        'paquet_bytes': paquet,
                        'heure_envoi': time.time(),
                        'retransmis': False,
                    }

                    serveur_socket.sendto(paquet, adresse_client)

                    i_bloc += 1
                    seq_courant = (seq_courant + 1) % 2048

            # 4. Fin du transfert
            if i_bloc >= total_blocs and len(en_vol) == 0:

                # Envoi du paquet de fin
                if not fin_envoyee:
                    ts_fin = int(time.time() * 1000) & 0xFFFFFFFF
                    paquet_fin = construire_paquet(1, 0, seq_courant, ts_fin, b"")

                    serveur_socket.sendto(paquet_fin, adresse_client)

                    fin_envoyee = True
                    heure_fin = time.time()
                    nb_fin_retransmis = 0

                    print_err("Tous les DATA acquittés. Envoi du paquet de fin...")

                else:
                    # Retransmission si besoin
                    if time.time() - heure_fin > rtt.rto:
                        nb_fin_retransmis += 1

                        if nb_fin_retransmis > 10:
                            print_err("Fin : pas d'ACK après 10 retransmissions. Abandon.")
                            transfert_fini = True
                            break

                        ts_fin = int(time.time() * 1000) & 0xFFFFFFFF
                        paquet_fin = construire_paquet(1, 0, seq_courant, ts_fin, b"")

                        serveur_socket.sendto(paquet_fin, adresse_client)
                        heure_fin = time.time()

                # Attente ACK final
                if fin_envoyee:
                    pret2 = select.select([serveur_socket], [], [], 0.05)
                    if pret2[0]:
                        try:
                            ack_fin, _ = serveur_socket.recvfrom(1024)
                            a_type, a_win, a_len, a_seq, a_time, _ = lire_paquet_recu(ack_fin)

                            if a_type in (2, 3):
                                fin_ack_seq = (seq_courant + 1) % 2048
                                if a_seq == fin_ack_seq:
                                    print_err("ACK du paquet de fin reçu. Session terminée.")
                                    transfert_fini = True

                        except ValueError:
                            pass

        print_err(f"Transfert terminé pour {adresse_client}.\n")
