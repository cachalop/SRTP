import struct
import zlib

class Packet:
    def __init__(self, p_type=0, window=0, seqnum=0, payload=b"", timestamp=0):
        self.p_type = p_type       # 2 bits
        self.window = window       # 6 bits
        self.length = len(payload) # 13 bits    
        self.seqnum = seqnum       # 11 bits
        self.timestamp = timestamp # 4 octets
        self.payload = payload     # Max 1024 octets
        


    """créer la suite de bytes a partir des infos"""
    def coder(self):
        # compacte les valeurs pour créer l'entête
        # p_type   +   window   +   Length   +   seqnum
        #  [0-1]        [2-7]       [8-20]       [21-31]          
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
    
    """déchiffre la suite de bytes pour nous donner un objet packet"""
    @classmethod
    def decoder(cls, data):

        if len(data) < 12:
            return None
        
        # p_type   +   window   +   Length   +   seqnum
        #  [0-1]        [2-7]       [8-20]       [21-31]   
        header = struct.unpack('!I', data[0:4])[0] # [0] car .unpack() renvoie un tuple 
        timestamp = struct.unpack('!I', data[4:8])[0]
        crc1 = struct.unpack('!I', data[8:12])[0]
        
        if (zlib.crc32(data[:8]) & 0xffffffff) != crc1:
            return None

        # On reprend header et on pousse vers la droite pour retrouver les morceaux
        # p_type   +   window   +   Length   +   seqnum
        #  [0-1]        [2-7]       [8-20]       [21-31]  
        #  [31-30]     [29-24]      [23-11]      [11-0]
        p_type = (header >> 30) & 0x3
        window = (header >> 24) & 0x3F
        length = (header >> 11) & 0x1FFF
        seqnum = header & 0x7FF

        payload = b""
        if length > 0:
            payload = data[12:12+length]
            crc2 = struct.unpack('!I', data[12+length:16+length])[0] 
            if (zlib.crc32(payload) & 0xffffffff) != crc2:
                return None

        return cls(p_type, window, seqnum, payload, timestamp)
