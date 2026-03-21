import argparse
import os
import socket
import sys
import time

from packet import Packet, PTYPE_DATA, PTYPE_ACK, PTYPE_SACK, MAX_PAYLOAD, SEQ_MOD


# Paramètres du protocole côté serveur
SOCKET_TIMEOUT = 0.05
SEND_WINDOW_CAP = 31
INITIAL_RTO = 0.5


# Log sur stderr (imposé)
def log(msg):
    print(msg, file=sys.stderr)


# Timestamp utilisé pour RTT / retransmissions
def now_ts():
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


# Différence circulaire de seqnum
def seq_diff(a, b):
    return (a - b) % SEQ_MOD


# Parse la requête HTTP 0.9 (GET /path)
def parse_request(payload):
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        return None

    if not text.startswith("GET "):
        return None

    path = text[4:].strip()
    if not path.startswith("/"):
        return None

    return path


# Sécurise l'accès au système de fichiers (évite ../)
def safe_join(root, request_path):
    relative = os.path.normpath(request_path.lstrip("/"))

    if relative.startswith(".."):
        return None

    full = os.path.abspath(os.path.join(root, relative))
    root_abs = os.path.abspath(root)

    if os.path.commonpath([full, root_abs]) != root_abs:
        return None

    return full


# Découpe le fichier en paquets DATA + paquet final vide
def build_packets(file_path):
    packets = []
    seq = 0

    # Si fichier inexistant → paquet vide
    if not os.path.isfile(file_path):
        packets.append(Packet(PTYPE_DATA, 0, 0, b"", now_ts()))
        return packets

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(MAX_PAYLOAD)
            if not chunk:
                break

            packets.append(Packet(PTYPE_DATA, 0, seq, chunk, now_ts()))
            seq = (seq + 1) % SEQ_MOD

    # Paquet de fin
    packets.append(Packet(PTYPE_DATA, 0, seq, b"", now_ts()))
    return packets


# Attend une requête valide du client
def wait_request(sock):
    while True:
        try:
            raw, client_addr = sock.recvfrom(2048)
        except socket.timeout:
            continue

        pkt = Packet.decode(raw)

        if pkt is None:
            continue
        if pkt.ptype != PTYPE_DATA:
            continue
        if pkt.seqnum != 0:
            continue

        path = parse_request(pkt.payload)
        if path is None:
            continue

        return client_addr, path


# Gestion du transfert fiable (fenêtre + retransmissions)
def run_transfer(sock, client_addr, packets):
    base = 0
    next_to_send = 0
    peer_window = 1
    rto = INITIAL_RTO
    in_flight = {}

    while base < len(packets):
        # Nombre de paquets autorisés à envoyer
        allowed = min(SEND_WINDOW_CAP, max(1, peer_window))

        # Envoi des nouveaux paquets dans la fenêtre
        while next_to_send < len(packets) and (next_to_send - base) < allowed:
            pkt = packets[next_to_send]
            pkt.window = 0
            pkt.timestamp = now_ts()
            sock.sendto(pkt.encode(), client_addr)
            in_flight[pkt.seqnum] = (next_to_send, time.monotonic(), pkt.timestamp)
            next_to_send += 1

        now = time.monotonic()

        # Retransmission des paquets expirés (timeout)
        for seqnum, (idx, sent_at, sent_ts) in list(in_flight.items()):
            if now - sent_at >= rto:
                pkt = packets[idx]
                pkt.window = 0
                pkt.timestamp = now_ts()
                sock.sendto(pkt.encode(), client_addr)
                in_flight[seqnum] = (idx, time.monotonic(), pkt.timestamp)

        try:
            raw, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue

        if addr != client_addr:
            continue

        ack = Packet.decode(raw)

        # Ignore paquets invalides ou non ACK
        if ack is None:
            continue
        if ack.ptype not in (PTYPE_ACK, PTYPE_SACK):
            continue

        peer_window = ack.window
        ack_seq = ack.seqnum

        # Avance la base (ACK cumulatif)
        while base < len(packets) and packets[base].seqnum != ack_seq:
            seq = packets[base].seqnum

            if seq in in_flight:
                idx, sent_at, sent_ts = in_flight[seq]

                # Estimation simple du RTT → mise à jour du RTO
                if sent_ts == ack.timestamp:
                    sample = time.monotonic() - sent_at
                    rto = max(0.2, min(2.0, 2.0 * sample))

                del in_flight[seq]

            base += 1

        # Cas particulier : fenêtre du client à 0 → renvoyer périodiquement
        if peer_window == 0 and base < len(packets):
            seq = packets[base].seqnum
            if seq in in_flight:
                idx, sent_at, sent_ts = in_flight[seq]
                if time.monotonic() - sent_at >= rto:
                    pkt = packets[idx]
                    pkt.window = 0
                    pkt.timestamp = now_ts()
                    sock.sendto(pkt.encode(), client_addr)
                    in_flight[seq] = (idx, time.monotonic(), pkt.timestamp)

    log("Transfer complete")


def run_server(hostname, port, root):
    # Socket UDP IPv6
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.bind((hostname, port))

    root = os.path.abspath(root)
    log(f"Listening on [{hostname}]:{port}")

    while True:
        # Attente d'une requête
        client_addr, request_path = wait_request(sock)
        log(f"Request from {client_addr[0]}:{client_addr[1]} for {request_path}")

        file_path = safe_join(root, request_path)

        # Construction des paquets à envoyer
        if file_path is None:
            packets = [Packet(PTYPE_DATA, 0, 0, b"", now_ts())]
        else:
            packets = build_packets(file_path)

        # Lancement du transfert
        run_transfer(sock, client_addr, packets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname")
    parser.add_argument("port", type=int)
    parser.add_argument("--root", default=".", help="server root directory")
    args = parser.parse_args()

    try:
        run_server(args.hostname, args.port, args.root)
    except Exception as exc:
        log(f"error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()