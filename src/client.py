import argparse
import os
import socket
import sys
import time
from urllib.parse import urlparse

from packet import Packet, PTYPE_DATA, PTYPE_ACK, MAX_WINDOW, SEQ_MOD


# Paramètres principaux
RECV_BUFFER_SIZE = 63
SOCKET_TIMEOUT = 0.2
REQUEST_RETRY = 0.8


# Log sur stderr (imposé par les consignes)
def log(msg):
    print(msg, file=sys.stderr)


# Timestamp simple basé sur le temps courant
def now_ts():
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


# Différence circulaire entre numéros de séquence
def seq_diff(a, b):
    return (a - b) % SEQ_MOD


# Vérifie si un seqnum est dans la fenêtre de réception
def in_window(seq, base, size):
    return seq_diff(seq, base) < size


# Parse l'URL HTTP fournie au client
def parse_server_url(url):
    parsed = urlparse(url)

    if parsed.scheme != "http":
        raise ValueError("URL must start with http://")
    if parsed.hostname is None:
        raise ValueError("missing hostname")
    if parsed.port is None:
        raise ValueError("missing port")

    path = parsed.path or "/"
    return parsed.hostname, parsed.port, path


# Nombre de places libres dans le buffer de réception
def free_slots(buffered_count):
    return max(0, min(MAX_WINDOW, RECV_BUFFER_SIZE - buffered_count))


# Envoie un ACK cumulatif au serveur
def send_ack(sock, addr, next_expected, window_value, timestamp):
    pkt = Packet(
        ptype=PTYPE_ACK,
        window=window_value,
        seqnum=next_expected,
        payload=b"",
        timestamp=timestamp,
    )
    sock.sendto(pkt.encode(), addr)


def run_client(servername, save_path):
    # Résolution de l'adresse serveur
    host, port, path = parse_server_url(servername)
    server_addr = socket.getaddrinfo(
        host, port, socket.AF_INET6, socket.SOCK_DGRAM
    )[0][4]

    # Construction de la requête HTTP 0.9
    request_payload = f"GET {path}".encode("ascii")
    request_packet = Packet(
        ptype=PTYPE_DATA,
        window=1,
        seqnum=0,
        payload=request_payload,
        timestamp=now_ts(),
    )

    # Socket UDP IPv6
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    # État de réception
    expected_seq = 0
    recv_buffer = {}
    last_data_timestamp = 0
    first_data_received = False
    request_last_sent = 0.0

    # Prépare le fichier de sortie
    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)

    with open(save_path, "wb") as f:
        log(f"Receiving {path} into {save_path}")

        while True:
            now = time.monotonic()

            # Retransmission périodique de la requête GET si aucune réponse
            if not first_data_received and now - request_last_sent >= REQUEST_RETRY:
                request_packet.timestamp = now_ts()
                sock.sendto(request_packet.encode(), server_addr)
                request_last_sent = now

            try:
                raw, addr = sock.recvfrom(2048)
            except socket.timeout:
                # En cas de timeout, on renvoie un ACK si on a déjà reçu des données
                if first_data_received:
                    current_window = free_slots(len(recv_buffer))
                    send_ack(sock, server_addr, expected_seq, current_window, last_data_timestamp)
                continue

            # Ignore les paquets venant d'autres sources
            if addr[:2] != server_addr[:2]:
                continue

            pkt = Packet.decode(raw)

            # Ignore paquets invalides
            if pkt is None:
                if first_data_received:
                    current_window = free_slots(len(recv_buffer))
                    send_ack(sock, server_addr, expected_seq, current_window, last_data_timestamp)
                continue

            # On ne traite que les DATA
            if pkt.ptype != PTYPE_DATA:
                continue

            # Ignore paquets hors fenêtre
            if not in_window(pkt.seqnum, expected_seq, RECV_BUFFER_SIZE):
                current_window = free_slots(len(recv_buffer))
                send_ack(sock, server_addr, expected_seq, current_window, last_data_timestamp)
                continue

            first_data_received = True
            last_data_timestamp = pkt.timestamp

            # Paquet attendu
            if pkt.seqnum == expected_seq:
                # Fin de transfert (DATA vide)
                if pkt.length == 0:
                    expected_seq = (expected_seq + 1) % SEQ_MOD
                    current_window = free_slots(len(recv_buffer))
                    send_ack(sock, server_addr, expected_seq, current_window, last_data_timestamp)
                    break

                # Écriture directe
                f.write(pkt.payload)
                expected_seq = (expected_seq + 1) % SEQ_MOD

                # Consomme les paquets déjà reçus en avance
                while expected_seq in recv_buffer:
                    buffered_pkt = recv_buffer.pop(expected_seq)

                    if buffered_pkt.length == 0:
                        expected_seq = (expected_seq + 1) % SEQ_MOD
                        current_window = free_slots(len(recv_buffer))
                        send_ack(sock, server_addr, expected_seq, current_window, buffered_pkt.timestamp)
                        sock.close()
                        log("Transfer complete")
                        return

                    f.write(buffered_pkt.payload)
                    expected_seq = (expected_seq + 1) % SEQ_MOD

            else:
                # Paquet hors ordre → stockage
                if pkt.seqnum not in recv_buffer:
                    recv_buffer[pkt.seqnum] = pkt

            # Envoi ACK cumulatif
            current_window = free_slots(len(recv_buffer))
            send_ack(sock, server_addr, expected_seq, current_window, last_data_timestamp)

    sock.close()
    log("Transfer complete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("servername", help="http://hostname:port/path/to/file")
    parser.add_argument("--save", default="./llm.model", help="destination file")
    args = parser.parse_args()

    try:
        run_client(args.servername, args.save)
    except Exception as exc:
        log(f"error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()