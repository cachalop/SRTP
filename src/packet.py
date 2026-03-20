import struct
import zlib

class Packet:
    def __init__(self, p_type=0, window=0, seqnum=0, payload=b"", timestamp=0):
        self.p_type = p_type       # 2 bits
        self.window = window       # 6 bits
        self.seqnum = seqnum       # 11 bits
        self.length = len(payload) # 13 bits    
        self.timestamp = timestamp # 4 octets
        self.payload = payload     # Max 1024 octets
        


    """créer la suite de bytes a partir des infos"""
    def pack(self):
        # compacte les valeurs pour créer l'entête
        header_0 = (self.p_type << 30) | (self.window << 24) | (self.length << 11) | self.seqnum
        
        # mise au format NBO
        header_NBO = struct.pack('!I', header_0) + struct.pack('!I', self.timestamp)
        
        # rajout du CRC1 
        crc1 = zlib.crc32(header_NBO) & 0xffffffff
        packet_NBO = header_NBO + struct.pack('!I', crc1)
        
        # on ajoute le contenu du fichier apres CRC1
        packet_NBO += self.payload

        # ajout du CRC2 si on a un contenu
        if self.length > 0:
            crc2 = zlib.crc32(self.payload) & 0xffffffff
            packet_NBO += struct.pack('!I', crc2)
            
        return packet_NBO
    
    """déchiffre la suite de bytes pour nous donner des variables"""
    def unpack():
        return None
