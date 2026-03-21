import struct
import zlib


# Types de paquets SRTP
PTYPE_DATA = 1
PTYPE_ACK = 2
PTYPE_SACK = 3

# Contraintes du protocole
MAX_PAYLOAD = 1024
MAX_WINDOW = 63
SEQ_MOD = 2048

HEADER_NO_CRC_SIZE = 8
HEADER_SIZE = 12


class Packet:
    def __init__(self, ptype, window, seqnum, payload=b"", timestamp=0):
        self.ptype = ptype
        self.window = window
        self.seqnum = seqnum
        self.payload = payload or b""
        self.length = len(self.payload)
        self.timestamp = timestamp & 0xFFFFFFFF

    # Vérifie que les champs respectent les bornes du protocole
    def valid(self):
        return (
            self.ptype in (PTYPE_DATA, PTYPE_ACK, PTYPE_SACK)
            and 0 <= self.window <= MAX_WINDOW
            and 0 <= self.seqnum < SEQ_MOD
            and 0 <= self.length <= MAX_PAYLOAD
        )

    # Encode le paquet en bytes (format réseau)
    def encode(self):
        if not self.valid():
            raise ValueError("invalid packet")

        # Compacte les champs dans un mot de 32 bits
        first_word = (
            ((self.ptype & 0x3) << 30)
            | ((self.window & 0x3F) << 24)
            | ((self.length & 0x1FFF) << 11)
            | (self.seqnum & 0x7FF)
        )

        # Header + CRC1
        header = struct.pack("!II", first_word, self.timestamp)
        crc1 = zlib.crc32(header) & 0xFFFFFFFF
        raw = header + struct.pack("!I", crc1)

        # Ajout du payload + CRC2 si nécessaire
        if self.length > 0:
            crc2 = zlib.crc32(self.payload) & 0xFFFFFFFF
            raw += self.payload + struct.pack("!I", crc2)

        return raw

    @classmethod
    def decode(cls, data):
        # Vérifie taille minimale
        if len(data) < HEADER_SIZE:
            return None

        # Lecture du header
        first_word, timestamp = struct.unpack("!II", data[:8])
        recv_crc1 = struct.unpack("!I", data[8:12])[0]
        calc_crc1 = zlib.crc32(data[:8]) & 0xFFFFFFFF

        # Vérification CRC1
        if recv_crc1 != calc_crc1:
            return None

        # Extraction des champs
        ptype = (first_word >> 30) & 0x3
        window = (first_word >> 24) & 0x3F
        length = (first_word >> 11) & 0x1FFF
        seqnum = first_word & 0x7FF

        # Validation des champs
        if ptype not in (PTYPE_DATA, PTYPE_ACK, PTYPE_SACK):
            return None
        if length > MAX_PAYLOAD:
            return None

        # Cas paquet sans payload
        if length == 0:
            if len(data) != HEADER_SIZE:
                return None
            return cls(ptype, window, seqnum, b"", timestamp)

        # Vérifie taille totale attendue
        needed = HEADER_SIZE + length + 4
        if len(data) != needed:
            return None

        # Lecture du payload + CRC2
        payload = data[12:12 + length]
        recv_crc2 = struct.unpack("!I", data[12 + length:16 + length])[0]
        calc_crc2 = zlib.crc32(payload) & 0xFFFFFFFF

        # Vérification CRC2
        if recv_crc2 != calc_crc2:
            return None

        return cls(ptype, window, seqnum, payload, timestamp)