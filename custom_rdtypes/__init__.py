import dns.rdatatype
import dns.rdata

import dns.rdataclass
import dns.rdata
from custom_rdtypes.ANY import LUA

def register_custom_types():
    dns.rdata.register_type(LUA, 32800, 'LUA', rdclass=dns.rdataclass.ANY)
