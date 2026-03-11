#!/usr/bin/env python3
"""DNS protocol — packet parser and builder for DNS messages.

One file. Zero deps. Does one thing well.

Parse and construct DNS query/response packets per RFC 1035.
Supports A, AAAA, CNAME, MX, TXT, NS record types.
"""
import struct, sys, socket

# Record types
TYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}
RTYPES = {v: k for k, v in TYPES.items()}
CLASSES = {1: "IN"}

class DNSHeader:
    SIZE = 12
    def __init__(self, id=0, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, rcode=0,
                 qdcount=0, ancount=0, nscount=0, arcount=0):
        self.id = id
        self.qr = qr; self.opcode = opcode; self.aa = aa; self.tc = tc
        self.rd = rd; self.ra = ra; self.rcode = rcode
        self.qdcount = qdcount; self.ancount = ancount
        self.nscount = nscount; self.arcount = arcount

    def encode(self):
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | self.rcode
        return struct.pack('>HHHHHH', self.id, flags, self.qdcount,
                          self.ancount, self.nscount, self.arcount)

    @classmethod
    def decode(cls, data):
        id, flags, qd, an, ns, ar = struct.unpack_from('>HHHHHH', data)
        return cls(id=id, qr=(flags>>15)&1, opcode=(flags>>11)&0xF,
                  aa=(flags>>10)&1, tc=(flags>>9)&1, rd=(flags>>8)&1,
                  ra=(flags>>7)&1, rcode=flags&0xF,
                  qdcount=qd, ancount=an, nscount=ns, arcount=ar)

def encode_name(name):
    parts = name.rstrip('.').split('.')
    result = b''
    for part in parts:
        result += bytes([len(part)]) + part.encode()
    return result + b'\x00'

def decode_name(data, offset):
    labels = []
    jumped = False
    orig_offset = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # Pointer
            if not jumped:
                orig_offset = offset + 2
            pointer = struct.unpack_from('>H', data, offset)[0] & 0x3FFF
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset+length].decode())
        offset += length
    return '.'.join(labels), orig_offset if jumped else offset

class DNSQuestion:
    def __init__(self, name, qtype="A", qclass="IN"):
        self.name = name
        self.qtype = RTYPES.get(qtype, 1) if isinstance(qtype, str) else qtype
        self.qclass = 1

    def encode(self):
        return encode_name(self.name) + struct.pack('>HH', self.qtype, self.qclass)

    @classmethod
    def decode(cls, data, offset):
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack_from('>HH', data, offset)
        return cls(name, qtype, qclass), offset + 4

class DNSRecord:
    def __init__(self, name, rtype, rclass, ttl, rdata):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    @classmethod
    def decode(cls, data, offset):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack_from('>HHIH', data, offset)
        offset += 10
        rdata = data[offset:offset+rdlen]
        offset += rdlen
        return cls(name, rtype, rclass, ttl, rdata), offset

    def rdata_str(self):
        t = TYPES.get(self.rtype, str(self.rtype))
        if t == "A" and len(self.rdata) == 4:
            return socket.inet_ntoa(self.rdata)
        if t == "AAAA" and len(self.rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, self.rdata)
        if t == "CNAME" or t == "NS":
            name, _ = decode_name(self.rdata + b'\x00' * 10, 0)
            return name
        if t == "MX" and len(self.rdata) >= 4:
            pref = struct.unpack_from('>H', self.rdata)[0]
            name, _ = decode_name(self.rdata, 2)
            return f"{pref} {name}"
        if t == "TXT":
            parts = []
            i = 0
            while i < len(self.rdata):
                l = self.rdata[i]; i += 1
                parts.append(self.rdata[i:i+l].decode(errors='replace')); i += l
            return ' '.join(parts)
        return self.rdata.hex()

    def __repr__(self):
        t = TYPES.get(self.rtype, str(self.rtype))
        return f"{self.name} {self.ttl} IN {t} {self.rdata_str()}"

def build_query(name, qtype="A"):
    import os
    header = DNSHeader(id=struct.unpack('>H', os.urandom(2))[0], rd=1, qdcount=1)
    question = DNSQuestion(name, qtype)
    return header.encode() + question.encode()

def parse_response(data):
    header = DNSHeader.decode(data)
    offset = DNSHeader.SIZE
    questions = []
    for _ in range(header.qdcount):
        q, offset = DNSQuestion.decode(data, offset)
        questions.append(q)
    answers = []
    for _ in range(header.ancount):
        r, offset = DNSRecord.decode(data, offset)
        answers.append(r)
    return header, questions, answers

def main():
    print("=== DNS Protocol ===\n")
    # Build a query
    query = build_query("example.com", "A")
    print(f"Query packet: {len(query)} bytes")
    print(f"  Hex: {query.hex()[:60]}...")

    # Parse it back
    header = DNSHeader.decode(query)
    print(f"  ID: 0x{header.id:04x}, RD={header.rd}, Questions={header.qdcount}")

    q, _ = DNSQuestion.decode(query, DNSHeader.SIZE)
    print(f"  Question: {q.name} {TYPES.get(q.qtype, q.qtype)}")

    # Build a fake response
    print("\n--- Simulated Response ---")
    resp_header = DNSHeader(id=header.id, qr=1, ra=1, qdcount=1, ancount=2)
    q_bytes = DNSQuestion("example.com", "A").encode()
    # A record: 93.184.216.34
    a_record = encode_name("example.com") + struct.pack('>HHIH', 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")
    a_record2 = encode_name("example.com") + struct.pack('>HHIH', 1, 1, 300, 4) + socket.inet_aton("93.184.216.35")
    resp = resp_header.encode() + q_bytes + a_record + a_record2

    _, _, answers = parse_response(resp)
    for a in answers:
        print(f"  {a}")

if __name__ == "__main__":
    main()
