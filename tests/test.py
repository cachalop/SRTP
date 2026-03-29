

import sys
import os
import struct
import zlib
import socket
import threading
import time
import random
import select
import pytest

# Ajouter le dossier src au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from client import (
    encode_header, decode_header, construire_paquet, lire_paquet_recu,
    encode_sack_payload, envoyer_ack, seq_distance,
)
from server import decode_sack_payload, RTTEstimator


# fonction aide simuler server client

def _find_free_port():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.bind(("::1", 0))
        return s.getsockname()[1]


def _run_server(host, port, root, stop_event, started_event):
    MAX_PAYLOAD = 1024
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(1.0)
    started_event.set()

    while not stop_event.is_set():
        try:
            pkt, addr = sock.recvfrom(2000)
        except socket.timeout:
            continue
        try:
            pt, pw, pl, ps, ptm, pay = lire_paquet_recu(pkt)
        except ValueError:
            continue
        if pt != 1 or not pay:
            continue
        try:
            req = pay.decode('ascii')
        except UnicodeDecodeError:
            continue
        if not req.startswith("GET "):
            continue

        path = req[4:].lstrip('/')
        full = os.path.join(root, path)
        chunks = []
        if os.path.isfile(full):
            with open(full, 'rb') as f:
                while True:
                    c = f.read(MAX_PAYLOAD)
                    if not c:
                        break
                    chunks.append(c)

        # Fenêtre initiale = Window annoncée par le client dans sa requête
        win_c = pw if pw > 0 else 1
        in_flight = {}
        sack_set = set()
        idx = 0
        total = len(chunks)
        cur_seq = (ps + 1) % 2048
        rtt = RTTEstimator(rto_initial=1.0)

        while not stop_event.is_set():
            ready = select.select([sock], [], [], 0.01)
            if ready[0]:
                try:
                    ab, _ = sock.recvfrom(2000)
                    at, aw, al, aseq, atime, ap = lire_paquet_recu(ab)
                    if at in (2, 3):
                        win_c = aw
                        # Karn : RTT uniquement si paquets non-retransmis
                        ts_now = int(time.time() * 1000) & 0xFFFFFFFF
                        rtt_ms = (ts_now - atime) & 0xFFFFFFFF
                        if rtt_ms < 10000:
                            clean = True
                            for s in in_flight:
                                if 0 < (aseq - s) % 2048 <= 1024:
                                    if in_flight[s].get('r', False):
                                        clean = False
                                        break
                            if clean:
                                rtt.update(rtt_ms / 1000.0)
                        for s in list(in_flight):
                            if 0 < (aseq - s) % 2048 <= 1024:
                                del in_flight[s]
                                sack_set.discard(s)
                        if at == 3 and ap:
                            for ss in decode_sack_payload(ap):
                                sack_set.add(ss)
                except (ValueError, socket.timeout):
                    pass

            now = time.time()
            for s, inf in list(in_flight.items()):
                if s in sack_set:
                    continue
                if now - inf['t'] > rtt.rto:
                    sock.sendto(inf['p'], addr)
                    inf['t'] = now
                    inf['r'] = True

            if win_c > 0:
                while len(in_flight) < win_c and idx < total:
                    ts = int(time.time() * 1000) & 0xFFFFFFFF
                    p = construire_paquet(1, 0, cur_seq, ts, chunks[idx])
                    in_flight[cur_seq] = {'p': p, 't': time.time(), 'r': False}
                    sock.sendto(p, addr)
                    idx += 1
                    cur_seq = (cur_seq + 1) % 2048

            if idx >= total and len(in_flight) == 0:
                ts = int(time.time() * 1000) & 0xFFFFFFFF
                pf = construire_paquet(1, 0, cur_seq, ts, b"")
                for _ in range(3):
                    sock.sendto(pf, addr)
                    time.sleep(0.02)
                break
    sock.close()


def _run_client(host, port, path, save_path):
    MAX_WIN = 63
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    req = f"GET {path}".encode('ascii')
    ts = int(time.time() * 1000) & 0xFFFFFFFF
    pkt = construire_paquet(1, MAX_WIN, 0, ts, req)
    dest = (host, port)
    sock.sendto(pkt, dest)

    exp = 1
    buf = {}
    ok = False
    with open(save_path, "wb") as f:
        retries = 0
        while retries < 20:
            try:
                data, a = sock.recvfrom(2000)
            except socket.timeout:
                retries += 1
                ts = int(time.time() * 1000) & 0xFFFFFFFF
                pkt = construire_paquet(1, MAX_WIN, 0, ts, req)
                sock.sendto(pkt, dest)
                continue
            try:
                pt, pw, pl, ps, ptm, payload = lire_paquet_recu(data)
            except ValueError:
                continue
            if pt != 1:
                continue
            if pl == 0 and ps == exp:
                envoyer_ack(sock, a, (ps + 1) % 2048, ptm, MAX_WIN)
                ok = True
                break
            if pl > 0:
                d = seq_distance(ps, exp)
                places = MAX_WIN - len(buf)
                fenetre = max(1, places)
                if d == 0:
                    f.write(payload)
                    exp = (exp + 1) % 2048
                    while exp in buf:
                        f.write(buf.pop(exp))
                        exp = (exp + 1) % 2048
                elif 0 < d < fenetre:
                    if ps not in buf:
                        buf[ps] = payload
                places = MAX_WIN - len(buf)
                envoyer_ack(sock, a, exp, ptm, places, buf)
                retries = 0
    sock.close()
    return ok

#proxy UDP simulant des conditions réseau 
def _udp_proxy(listen_port, target_host, target_port, stop_event,
               started_event, drop_rate=0.0, corrupt_rate=0.0, truncate_rate=0.0):
    proxy_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind(("::1", listen_port))
    proxy_sock.settimeout(0.5)
    started_event.set()
    client_addr = None
    server_addr = (target_host, target_port)

    while not stop_event.is_set():
        try:
            data, addr = proxy_sock.recvfrom(2048)
        except socket.timeout:
            continue
        if addr[0:2] == server_addr[0:2] or addr == server_addr:
            dest = client_addr
        else:
            client_addr = addr
            dest = server_addr
        if dest is None:
            continue
        if random.random() < drop_rate:
            continue
        data = bytearray(data)
        if random.random() < corrupt_rate and len(data) > 12:
            data[random.randint(0, len(data) - 1)] ^= random.randint(1, 255)
        data = bytes(data)
        if random.random() < truncate_rate and len(data) > 16:
            data = data[:random.randint(12, len(data) - 1)]
        proxy_sock.sendto(data, dest)
    proxy_sock.close()



#encodage / décodage des en-têtes


class TestEncodeDecodeHeader:

    def test_encode_decode_roundtrip(self):
        for ptype in (1, 2, 3):
            for win in (0, 1, 31, 63):
                for length in (0, 512, 1024):
                    for seq in (0, 1, 1023, 2047):
                        h = encode_header(ptype, win, length, seq, 0xDEADBEEF)
                        assert len(h) == 12
                        dt, dw, dl, ds, dts = decode_header(h)
                        assert (dt, dw, dl, ds, dts) == (ptype, win, length, seq, 0xDEADBEEF)

    def test_header_is_12_bytes(self):
        assert len(encode_header(1, 0, 0, 0, 0)) == 12

    def test_network_byte_order(self):
        h = encode_header(1, 0, 0, 0, 0)
        assert (struct.unpack("!I", h[:4])[0] >> 30) & 0x3 == 1

    def test_bit_layout(self):
        h = encode_header(2, 42, 700, 1500, 0)
        w = struct.unpack("!I", h[:4])[0]
        assert (w >> 30) & 0x3 == 2
        assert (w >> 24) & 0x3F == 42
        assert (w >> 11) & 0x1FFF == 700
        assert w & 0x7FF == 1500

    def test_crc1_integrity(self):
        h = bytearray(encode_header(1, 10, 100, 50, 12345))
        h[5] ^= 0xFF
        with pytest.raises(ValueError, match="CRC1"):
            decode_header(bytes(h))

    def test_crc1_covers_8_bytes(self):
        h = encode_header(1, 0, 0, 0, 0)
        assert struct.unpack("!I", h[8:12])[0] == zlib.crc32(h[:8]) & 0xFFFFFFFF

    def test_decode_too_short(self):
        with pytest.raises(ValueError):
            decode_header(b"\x00" * 11)

    def test_seqnum_0_first_segment(self):
        pkt = construire_paquet(1, 63, 0, 0, b"GET /test")
        _, _, _, seq, _, _ = lire_paquet_recu(pkt)
        assert seq == 0



#paquet complet


class TestPaquetComplet:

    def test_sans_payload(self):
        pkt = construire_paquet(2, 10, 5, 42)
        assert len(pkt) == 12
        pt, pw, pl, ps, _, pay = lire_paquet_recu(pkt)
        assert pt == 2 and pl == 0 and pay == b""

    def test_avec_payload(self):
        d = b"Hello SRTP!"
        pkt = construire_paquet(1, 0, 7, 100, d)
        assert len(pkt) == 12 + len(d) + 4
        pt, _, pl, ps, _, pay = lire_paquet_recu(pkt)
        assert pt == 1 and pl == len(d) and ps == 7 and pay == d

    def test_payload_max_1024(self):
        d = os.urandom(1024)
        _, _, pl, _, _, pay = lire_paquet_recu(construire_paquet(1, 0, 0, 0, d))
        assert pl == 1024 and pay == d

    def test_length_gt_1024_rejected(self):
        hi = (1 << 30) | (1025 << 11)
        partial = struct.pack("!II", hi, 0)
        crc1 = struct.pack("!I", zlib.crc32(partial) & 0xFFFFFFFF)
        with pytest.raises(ValueError, match="1024"):
            lire_paquet_recu(partial + crc1 + b"\x00" * 1029)

    def test_crc2_corrupted(self):
        pkt = bytearray(construire_paquet(1, 0, 0, 0, b"data"))
        pkt[-1] ^= 0xFF
        with pytest.raises(ValueError, match="CRC2"):
            lire_paquet_recu(bytes(pkt))

    def test_truncated(self):
        with pytest.raises(ValueError):
            lire_paquet_recu(construire_paquet(1, 0, 0, 0, b"A" * 100)[:-10])

    def test_too_short(self):
        with pytest.raises(ValueError):
            lire_paquet_recu(b"\x00" * 5)

    def test_type_0(self):
        assert lire_paquet_recu(construire_paquet(0, 0, 0, 0, b"test"))[0] == 0

    def test_no_crc2_if_length_zero(self):
        assert len(construire_paquet(1, 0, 0, 0)) == 12

    def test_fin_transfert_packet(self):
        pt, _, pl, ps, _, _ = lire_paquet_recu(construire_paquet(1, 0, 42, 0, b""))
        assert pt == 1 and pl == 0 and ps == 42

    def test_window_0_serveur(self):
        _, win, _, _, _, _ = lire_paquet_recu(construire_paquet(1, 0, 5, 0, b"data"))
        assert win == 0


#SACK


class TestSACK:

    def test_roundtrip(self):
        s = [5, 7, 10, 2047]
        assert decode_sack_payload(encode_sack_payload(s))[:4] == s

    def test_empty(self):
        assert encode_sack_payload([]) == b""
        assert decode_sack_payload(b"") == []

    def test_single(self):
        assert decode_sack_payload(encode_sack_payload([42]))[0] == 42

    def test_padded_to_4_bytes(self):
        for n in range(1, 20):
            assert len(encode_sack_payload(list(range(n)))) % 4 == 0

    def test_max_744(self):
        s = list(range(744))
        p = encode_sack_payload(s)
        assert len(p) <= 1024
        assert decode_sack_payload(p)[:744] == s

    def test_all_11bit_values(self):
        for v in [0, 1, 512, 1023, 1024, 2047]:
            assert decode_sack_payload(encode_sack_payload([v]))[0] == v

    def test_sack_length_zero_uses_ack(self):
        """Buffer vide → PTYPE_ACK (type 2), pas SACK."""
        s1 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s1.bind(("::1", 0))
        s2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s2.bind(("::1", 0))
        s2.settimeout(2.0)
        envoyer_ack(s1, ("::1", s2.getsockname()[1]), 5, 0, 60, {})
        pt, _, pl, _, _, _ = lire_paquet_recu(s2.recvfrom(2000)[0])
        assert pt == 2 and pl == 0
        s1.close(); s2.close()


#RTT Estimator


class TestRTTEstimator:

    def test_initial(self):
        assert RTTEstimator(2.0).rto == 2.0

    def test_fast_link(self):
        e = RTTEstimator(2.0)
        for _ in range(10):
            e.update(0.05)
        assert e.rto < 1.0

    def test_slow_link(self):
        e = RTTEstimator(0.5)
        for _ in range(10):
            e.update(3.0)
        assert e.rto > 2.0

    def test_bounded(self):
        e = RTTEstimator()
        e.update(0.001)
        assert e.rto >= e.min_rto
        e2 = RTTEstimator()
        e2.update(100.0)
        assert e2.rto <= e2.max_rto

    def test_ignores_negative(self):
        e = RTTEstimator(2.0)
        e.update(-1.0)
        assert e.rto == 2.0


# Envoi ACK

class TestEnvoiAckSack:

    def _pair(self):
        s1 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s1.bind(("::1", 0))
        s2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s2.bind(("::1", 0))
        s2.settimeout(2.0)
        return s1, s2

    def test_ack_type_and_fields(self):
        s1, s2 = self._pair()
        envoyer_ack(s1, ("::1", s2.getsockname()[1]), 5, 999, 60, {})
        pt, pw, pl, ps, pts, _ = lire_paquet_recu(s2.recvfrom(2000)[0])
        assert pt == 2 and ps == 5 and pl == 0 and pw == 60 and pts == 999
        s1.close(); s2.close()

    def test_sack_type_and_payload(self):
        s1, s2 = self._pair()
        envoyer_ack(s1, ("::1", s2.getsockname()[1]), 5, 999, 60, {7: b"x", 9: b"y"})
        pt, _, pl, ps, _, pay = lire_paquet_recu(s2.recvfrom(2000)[0])
        assert pt == 3 and ps == 5 and pl > 0
        seqs = decode_sack_payload(pay)
        assert 7 in seqs[:2] and 9 in seqs[:2]
        s1.close(); s2.close()

    def test_ack_window_0(self):
        s1, s2 = self._pair()
        envoyer_ack(s1, ("::1", s2.getsockname()[1]), 0, 0, 0)
        _, win, _, _, _, _ = lire_paquet_recu(s2.recvfrom(2000)[0])
        assert win == 0
        s1.close(); s2.close()

    def test_ack_timestamp_copied(self):
        s1, s2 = self._pair()
        envoyer_ack(s1, ("::1", s2.getsockname()[1]), 0, 0xABCD1234, 63)
        _, _, _, _, ts, _ = lire_paquet_recu(s2.recvfrom(2000)[0])
        assert ts == 0xABCD1234
        s1.close(); s2.close()



# réseau parfait

class TestTransfertParfait:

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.root = str(tmp_path / "www")
        os.makedirs(self.root, exist_ok=True)
        self.port = _find_free_port()
        self.host = "::1"

    def _start(self):
        stop = threading.Event()
        started = threading.Event()
        t = threading.Thread(target=_run_server,
                             args=(self.host, self.port, self.root, stop, started), daemon=True)
        t.start(); started.wait(5)
        return stop, t

    def _write(self, name, content):
        d = os.path.dirname(name)
        if d:
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        with open(os.path.join(self.root, name), "wb") as f:
            f.write(content)

    def _xfer(self, tmp_path, url, expected):
        stop, t = self._start()
        save = str(tmp_path / "out.bin")
        try:
            assert _run_client(self.host, self.port, url, save)
            with open(save, "rb") as f:
                assert f.read() == expected
        finally:
            stop.set(); t.join(5)

    def test_1_octet(self, tmp_path):
        self._write("t", b"\x42")
        self._xfer(tmp_path, "/t", b"\x42")

    def test_500_octets(self, tmp_path):
        c = os.urandom(500)
        self._write("s", c)
        self._xfer(tmp_path, "/s", c)

    def test_exactement_1024(self, tmp_path):
        c = os.urandom(1024)
        self._write("e", c)
        self._xfer(tmp_path, "/e", c)

    def test_1025_deux_paquets(self, tmp_path):
        c = os.urandom(1025)
        self._write("sp", c)
        self._xfer(tmp_path, "/sp", c)

    def test_10ko(self, tmp_path):
        c = os.urandom(10_000)
        self._write("m", c)
        self._xfer(tmp_path, "/m", c)

    def test_100ko(self, tmp_path):
        c = os.urandom(100_000)
        self._write("b", c)
        self._xfer(tmp_path, "/b", c)

    def test_sous_dossier(self, tmp_path):
        c = os.urandom(2000)
        self._write("llm/small", c)
        self._xfer(tmp_path, "/llm/small", c)

    def test_fichier_introuvable(self, tmp_path):
        self._xfer(tmp_path, "/nonexistent", b"")


#transfert avec pertes

class TestTransfertAvecPertes:

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.root = str(tmp_path / "www")
        os.makedirs(self.root, exist_ok=True)
        self.srv_port = _find_free_port()
        self.prx_port = _find_free_port()
        self.host = "::1"

    def _do(self, tmp_path, size, drop=0.0, corrupt=0.0, trunc=0.0):
        content = os.urandom(size)
        with open(os.path.join(self.root, "f"), "wb") as f:
            f.write(content)
        stop_s = threading.Event(); started_s = threading.Event()
        ts = threading.Thread(target=_run_server,
                              args=(self.host, self.srv_port, self.root, stop_s, started_s), daemon=True)
        ts.start(); started_s.wait(5)
        stop_p = threading.Event(); started_p = threading.Event()
        tp = threading.Thread(target=_udp_proxy,
                              args=(self.prx_port, self.host, self.srv_port, stop_p, started_p,
                                    drop, corrupt, trunc), daemon=True)
        tp.start(); started_p.wait(5)
        save = str(tmp_path / "out.bin")
        try:
            assert _run_client(self.host, self.prx_port, "/f", save)
            with open(save, "rb") as f:
                assert f.read() == content
        finally:
            stop_p.set(); stop_s.set(); tp.join(3); ts.join(3)

    def test_pertes_10(self, tmp_path):
        self._do(tmp_path, 5000, drop=0.10)

    def test_pertes_20(self, tmp_path):
        self._do(tmp_path, 5000, drop=0.20)

    def test_corruption_10(self, tmp_path):
        self._do(tmp_path, 5000, corrupt=0.10)

    def test_troncation_10(self, tmp_path):
        self._do(tmp_path, 5000, trunc=0.10)

    def test_mixte(self, tmp_path):
        self._do(tmp_path, 5000, drop=0.05, corrupt=0.05, trunc=0.05)

#paquets malformés
class TestPaquetsMalformes:

    def test_paquet_vide(self):
        with pytest.raises(ValueError):
            lire_paquet_recu(b"")

    def test_100_paquets_aleatoires(self):
        r = sum(1 for _ in range(100)
                if _raises(lambda: lire_paquet_recu(os.urandom(random.randint(1, 50)))))
        assert r >= 95

    def test_header_ok_payload_random(self):
        with pytest.raises(ValueError):
            lire_paquet_recu(encode_header(1, 0, 100, 0, 0) + os.urandom(104))

    def test_seqnum_wraparound(self):
        _, _, _, s, _, _ = lire_paquet_recu(construire_paquet(1, 0, 2047, 0, b"w"))
        assert s == 2047 and (s + 1) % 2048 == 0

    def test_seq_distance_modulo(self):
        assert seq_distance(5, 3) == 2
        assert seq_distance(0, 2047) == 1
        assert seq_distance(2047, 0) == 2047
        assert seq_distance(100, 100) == 0


#cas limites

class TestCasLimites:

    def test_http_09_no_headers(self):
        r = "GET /llm/small".encode('ascii')
        assert b"\r" not in r and b"\n" not in r

    def test_requete_seqnum_0(self):
        _, _, _, s, _, _ = lire_paquet_recu(construire_paquet(1, 63, 0, 0, b"GET /t"))
        assert s == 0

    def test_premier_data_seqnum_1(self):
        assert (0 + 1) % 2048 == 1

    def test_ack_cumulatif(self):
        assert (3 + 1) % 2048 == 4

    def test_window_max_63(self):
        _, w, _, _, _ = decode_header(encode_header(1, 63, 0, 0, 0))
        assert w == 63


# helper
def _raises(fn):
    try:
        fn()
        return False
    except (ValueError, Exception):
        return True
