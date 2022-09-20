import dns.rdtypes.txtbase
import struct

class LUA(dns.rdata.Rdata):
    """PowerDNS LUA record"""

    __slots__ = ['qtype', 'script']

    def __init__(self, rdclass, rdtype, qtype, script):
        super().__init__(rdclass, rdtype)
        object.__setattr__(self, 'qtype', qtype)
        object.__setattr__(self, 'script', script)

    def to_text(self, origin=None, relativize=True, **kw):
        lua = '"{}" '.format(dns.rdata._escapify(self.qtype))
        prefix = ''
        for s in self.script:
            lua += '{}"{}"'.format(prefix, dns.rdata._escapify(s))
            prefix = ' '
        return lua

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True,
                  relativize_to=None):
        qtype = tok.get().unescape_to_bytes()
        if not (qtype.is_quoted_string() or
                qtype.is_identifier()):
            raise dns.exception.SyntaxError("expected a string (LUA query type)")

        script = []
        for token in tok.get_remaining():
            token = token.unescape_to_bytes()
            if not (token.is_quoted_string() or token.is_identifier()):
                raise dns.exception.SyntaxError("expected a string (LUA script)")
            if len(token.value) > 255:
                raise dns.exception.SyntaxError("string too long (LUA script)")
            script.append(token.value)
        if len(script) == 0:
            raise dns.exception.UnexpectedEnd

        return cls(rdclass, rdtype, qtype.value, script)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        file.write(struct.pack("!B", len(self.qtype)))
        file.write(self.qtype)

        for s in self.script:
            l = len(s)
            assert l < 256
            file.write(struct.pack('!B', l))
            file.write(s)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        qtype = parser.get_counted_bytes()
        script = []
        while parser.remaining() > 0:
            s = parser.get_counted_bytes()
            script.append(s)
        return cls(rdclass, rdtype, qtype, script)
