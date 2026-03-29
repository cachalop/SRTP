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


#  Encodage / décodage des paquets SRTP

def encode_header(packet_type, window, length, seqnum, timestamp):
    """Encode un en-tête SRTP (12 octets) : Header32 | Timestamp | CRC1."""
    header_int = (packet_type << 30) | (window << 24) | (length << 11) | seqnum
    partial_header = struct.pack("!II", header_int, timestamp)
    crc1 = zlib.crc32(partial_header) & 0xFFFFFFFF
    return partial_header + struct.pack("!I", crc1)


def decode_header(header_bytes):
    """Décode un en-tête SRTP de 12 octets. Lève ValueError si CRC1 invalide."""
    if len(header_bytes) != 12:
        raise ValueError("L'en-tête ne fait pas 12 octets")
    header_int, timestamp, crc1_recu = struct.unpack("!III", header_bytes)
    if (zlib.crc32(header_bytes[:8]) & 0xFFFFFFFF) != crc1_recu:
        raise ValueError("Erreur CRC1")
    packet_type = (header_int >> 30) & 0x3
    window = (header_int >> 24) & 0x3F
    length = (header_int >> 11) & 0x1FFF
    seqnum = header_int & 0x7FF
    return packet_type, window, length, seqnum, timestamp


def construire_paquet(packet_type, window, seqnum, timestamp, payload=b""):
    """Construit un paquet SRTP complet (en-tête + payload + CRC2)."""
    length = len(payload)
    entete = encode_header(packet_type, window, length, seqnum, timestamp)
    if length == 0:
        return entete
    crc2 = struct.pack("!I", zlib.crc32(payload) & 0xFFFFFFFF)
    return entete + payload + crc2


def lire_paquet_recu(paquet_bytes):
    """Valide et décode un paquet SRTP complet. Lève ValueError si invalide."""
    if len(paquet_bytes) < 12:
        raise ValueError("Paquet trop court")
    p_type, p_win, p_len, p_seq, p_time = decode_header(paquet_bytes[:12])

    # Ignorer les paquets avec Length > 1024
    if p_len > 1024:
        raise ValueError("Length > 1024 : paquet ignoré")

    if p_len == 0:
        return p_type, p_win, p_len, p_seq, p_time, b""

    taille_attendue = 12 + p_len + 4
    if len(paquet_bytes) < taille_attendue:
        raise ValueError("Paquet tronqué")

    payload = paquet_bytes[12: 12 + p_len]
    crc2_recu = struct.unpack("!I", paquet_bytes[12 + p_len: 12 + p_len + 4])[0]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc2_recu:
        raise ValueError("Erreur CRC2")

    return p_type, p_win, p_len, p_seq, p_time, payload

#  SACK (acquittements sélectifs) — décodage côté serveur

def decode_sack_payload(payload):
    """Décode les seqnums 11 bits d'un payload SACK."""
    if not payload:
        return []
    total_bits = len(payload) * 8
    num_seqnums = total_bits // 11
    bitstream = int.from_bytes(payload, 'big')

    seqnums = []
    for i in range(num_seqnums):
        shift = total_bits - (i + 1) * 11
        seq = (bitstream >> shift) & 0x7FF
        seqnums.append(seq)

    return seqnums

#  Estimation du RTT (algorithme de Jacobson/Karels simplifié)

class RTTEstimator:
    """Estime le RTO à partir des timestamps échantillonnés."""

    def __init__(self, rto_initial=2.0):
        self.srtt = None       # Smoothed RTT
        self.rttvar = None     # RTT variance
        self.rto = rto_initial # Retransmission timeout
        self.alpha = 0.125
        self.beta = 0.25
        self.min_rto = 0.2
        self.max_rto = 5.0

    def update(self, rtt_sample):
        """Met à jour le RTO à partir d'un nouvel échantillon RTT (en secondes)."""
        if rtt_sample <= 0:
            return
        if self.srtt is None:
            self.srtt = rtt_sample
            self.rttvar = rtt_sample / 2.0
        else:
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * abs(self.srtt - rtt_sample)
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * rtt_sample
        self.rto = max(self.min_rto, min(self.max_rto, self.srtt + 4 * self.rttvar))

#  Programme principal : Serveur SRTP

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

    serveur_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    serveur_socket.bind((HOST, PORT))

    print_err(f"Serveur SRTP en écoute sur [{HOST}]:{PORT} (Racine: {RACINE})")

    while True:
        print_err("\nEn attente d'une requête HTTP 0.9...")

        # Attente d'une requête GET valide 
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

        # ── Fenêtre initiale du client ──
        # La spec dit : "l'émetteur initiant la connexion DOIT considérer que
        # le destinataire avait annoncé une valeur initiale de Window valant 1."
        # Le client est l'initiateur, le serveur est le destinataire.
        # Le serveur utilise la Window annoncée par le client dans sa requête.
        window_client = p_win if p_win > 0 else 1

        #Découpage du fichier en morceaux
        morceaux_fichier = []
        if os.path.exists(chemin_complet) and os.path.isfile(chemin_complet):
            print_err(f"Fichier trouvé : {chemin_complet}")
            with open(chemin_complet, "rb") as f:
                while True:
                    chunk = f.read(MAX_PAYLOAD)
                    if not chunk:
                        break
                    morceaux_fichier.append(chunk)
        else:
            print_err(f"Fichier introuvable ({chemin_complet}). Envoi du paquet de fin.")

        total_morceaux = len(morceaux_fichier)
        print_err(f"Début de l'envoi ({total_morceaux} paquets de données)...")

        # État de la transmission 
        paquets_en_vol = {}       # seqnum → {'paquet_bytes', 'heure_envoi', 'retransmis'}
        seqnums_sack = set()      # seqnums confirmés par SACK (hors cumul)
        prochain_index = 0        # Index du prochain morceau à envoyer
        seqnum_actuel = (p_seq + 1) % 2048  # Premier seqnum DATA
        base_seqnum = seqnum_actuel          # Seqnum de base (plus ancien non-acquitté)
        rtt_estimator = RTTEstimator()
        transfert_fini = False
        fin_envoyee = False

        while not transfert_fini:
            # ── 1. Recevoir les ACK/SACK du client ──
            ready = select.select([serveur_socket], [], [], 0.01)
            if ready[0]:
                ack_bytes, ack_addr = serveur_socket.recvfrom(2000)
                try:
                    a_type, a_win, a_len, a_seq, a_time, a_payload = lire_paquet_recu(ack_bytes)

                    # Traiter ACK (type 2) et SACK (type 3)
                    if a_type in (2, 3):
                        window_client = a_win

                        # Calcul RTT (algorithme de Karn : ignorer les retransmis)
                        # On vérifie si le paquet acquitté était retransmis
                        ts_now = int(time.time() * 1000) & 0xFFFFFFFF
                        rtt_ms = (ts_now - a_time) & 0xFFFFFFFF
                        if rtt_ms < 10000:  # Échantillon plausible (< 10s)
                            # Vérifier qu'aucun paquet acquitté n'était retransmis
                            ack_is_clean = True
                            for seq in paquets_en_vol:
                                dist = (a_seq - seq) % 2048
                                if 0 < dist <= 1024:
                                    if paquets_en_vol[seq].get('retransmis', False):
                                        ack_is_clean = False
                                        break
                            if ack_is_clean:
                                rtt_estimator.update(rtt_ms / 1000.0)

                        # ACK cumulatif : supprimer tous les paquets acquittés
                        seqnums_a_supprimer = []
                        for seq in paquets_en_vol:
                            dist = (a_seq - seq) % 2048
                            if 0 < dist <= 1024:
                                seqnums_a_supprimer.append(seq)
                        for seq in seqnums_a_supprimer:
                            del paquets_en_vol[seq]
                            seqnums_sack.discard(seq)

                        base_seqnum = a_seq

                        # Traiter les SACK sélectifs
                        if a_type == 3 and a_payload:
                            sack_seqnums = decode_sack_payload(a_payload)
                            for sseq in sack_seqnums:
                                seqnums_sack.add(sseq)

                    # Ignorer requêtes GET répétées si déjà en transfert
                    elif a_type == 1:
                        pass

                except ValueError:
                    pass

            # ── 2. Retransmission des paquets expirés (sauf ceux confirmés par SACK) ──
            temps_actuel = time.time()
            rto = rtt_estimator.rto
            for seq, infos in list(paquets_en_vol.items()):
                if seq in seqnums_sack:
                    continue  # Le client a confirmé la réception via SACK
                if temps_actuel - infos['heure_envoi'] > rto:
                    serveur_socket.sendto(infos['paquet_bytes'], adresse_client)
                    infos['heure_envoi'] = temps_actuel
                    infos['retransmis'] = True

            # ── 3. Envoi de nouveaux paquets (respecter la fenêtre du client) ──
            # Gestion du cas Window = 0 : ne pas envoyer de nouvelles données
            if window_client > 0:
                while (len(paquets_en_vol) < window_client
                       and prochain_index < total_morceaux):
                    donnees = morceaux_fichier[prochain_index]
                    ts = int(time.time() * 1000) & 0xFFFFFFFF
                    nouveau_paquet = construire_paquet(1, 0, seqnum_actuel, ts, donnees)

                    paquets_en_vol[seqnum_actuel] = {
                        'paquet_bytes': nouveau_paquet,
                        'heure_envoi': time.time(),
                        'retransmis': False,
                    }
                    serveur_socket.sendto(nouveau_paquet, adresse_client)

                    prochain_index += 1
                    seqnum_actuel = (seqnum_actuel + 1) % 2048

            # ── 4. Fin de transfert ──
            if prochain_index >= total_morceaux and len(paquets_en_vol) == 0:
                if not fin_envoyee:
                    # Envoyer le paquet de fin (Length = 0)
                    ts_fin = int(time.time() * 1000) & 0xFFFFFFFF
                    paquet_fin = construire_paquet(1, 0, seqnum_actuel, ts_fin, b"")
                    serveur_socket.sendto(paquet_fin, adresse_client)
                    fin_envoyee = True
                    heure_fin = time.time()
                    nb_fin_retransmis = 0
                    print_err("Tous les DATA acquittés. Envoi du paquet de fin...")
                else:
                    # Retransmettre le paquet de fin si pas d'ACK
                    if time.time() - heure_fin > rtt_estimator.rto:
                        nb_fin_retransmis += 1
                        if nb_fin_retransmis > 10:
                            print_err("Fin : pas d'ACK après 10 retransmissions. Abandon.")
                            transfert_fini = True
                            break
                        ts_fin = int(time.time() * 1000) & 0xFFFFFFFF
                        paquet_fin = construire_paquet(1, 0, seqnum_actuel, ts_fin, b"")
                        serveur_socket.sendto(paquet_fin, adresse_client)
                        heure_fin = time.time()

                # Vérifier si le client a acquitté le paquet de fin
                if fin_envoyee:
                    ready2 = select.select([serveur_socket], [], [], 0.05)
                    if ready2[0]:
                        try:
                            ack_fin, _ = serveur_socket.recvfrom(1024)
                            a_type, a_win, a_len, a_seq, a_time, _ = lire_paquet_recu(ack_fin)
                            if a_type in (2, 3):
                                fin_ack_seq = (seqnum_actuel + 1) % 2048
                                if a_seq == fin_ack_seq:
                                    print_err("ACK du paquet de fin reçu. Session terminée.")
                                    transfert_fini = True
                        except ValueError:
                            pass

        print_err(f"Transfert terminé pour {adresse_client}.\n")
