#!/usr/bin/env python3

from math import floor
import sys
import re
import pynetbox
import click
import netaddr
import jinja2
import dotenv
from datetime import datetime
import dns.name
import dns.reversename
import dns.rrset
import dns.zone


dotenv.load_dotenv()

def filter_address(ip_address):
    return str(netaddr.IPNetwork(ip_address.address).ip)

def filter_address_type(ip_address):
    return "A" if netaddr.IPNetwork(ip_address.address).version == 4 else "AAAA"

def filter_fqdn(name, origin=dns.name.from_text(".")):
    return dns.name.from_text(str(name), origin)

def filter_reverse_name(address):
    return dns.reversename.from_address(address)

def get_reverse_origin(prefix):
    # align the reverse prefix with word size, strip leading (zero) words from the origin
    _prefix = netaddr.IPNetwork(prefix)
    _word_bits = 4 if _prefix.version == 6 else 8
    _address_bits = 128 if _prefix.version == 6 else 32
    _aligned_prefixlen = _prefix.prefixlen - (_prefix.prefixlen % _word_bits)
    if _aligned_prefixlen != _prefix.prefixlen: 
        _prefix = _prefix.supernet(_aligned_prefixlen)[0]
    _reverse_name = dns.reversename.from_address(str(_prefix.network)).to_text()
    _leading_words = floor((_address_bits - _prefix.prefixlen) / _word_bits)
    return dns.name.from_text(re.sub(f'^(0\.){{1,{_leading_words}}}', '', _reverse_name))

def validate_prefix(ctx, param, value):
    if isinstance(value, tuple):
        for _value in value:
            validate_prefix(ctx, param, _value)
    elif value:
        try:
            netaddr.IPNetwork(value)
        except BaseException as err:
            raise click.BadParameter(err)
    return value

def validate_dns_name(ctx, param, value):
    if isinstance(value, tuple):
        for _value in value:
            validate_dns_name(ctx, param, _value)
    elif value:
        try:
            name = dns.name.from_text(value)
            
            # This should catch labels that might be valid by the book, but really not 
            # recommended to use.
            for label in name.labels:
                if label != b'' and not re.match(b'^(?!-)[a-zA-Z0-9-]*(?<!-)$', label): 
                    raise ValueError(f'Bad label: {label} in DNS name: {name}')
        except BaseException as err:
            raise click.BadParameter(err)
    return value

@click.command
@click.option('--url', envvar='NETBOX_URL', show_default='$NETBOX_URL', required=True, help='Netbox base URL')
@click.option('--token', envvar='NETBOX_TOKEN', show_default='$NETBOX_TOKEN', required=True, help='Netbox API Token')
@click.option('--parent-prefix', 'parent_prefixes', metavar='CIDR', multiple=True, show_default=True, default=('0.0.0.0/0', '::/0'),
    callback=validate_prefix, help='Limit IP Adresses to the specified prefixes (can be specified multiple times)')
@click.option('--nameserver', 'nameservers', metavar='DNSNAME', multiple=True, required=True, callback=validate_dns_name,
    help='Nameserver names of the zone (can be specified multiple times)')
@click.option('--zone', metavar='DNSNAME', callback=validate_dns_name, required=True, help='Zone name')
@click.option('--serial', show_default='current timestamp', default=int(datetime.utcnow().timestamp()), help='SOA Serial')
@click.option('--refresh', type=int, show_default=True, default=86400, help='SOA Refresh')
@click.option('--retry', type=int, show_default=True, default=7200, help='SOA Retry')
@click.option('--expire', type=int, show_default=True, default=3600000, help='SOA Expire')
@click.option('--ttl', type=int, show_default=True, default=3600, help='SOA and records TTL')
@click.option('--relativize/--no-relativize', show_default=True, default=True,
    help='Make names relative to origin')
@click.option('--reverse-prefix', metavar='CIDR', callback=validate_prefix, help='Generate reverse zone for the specified prefix')
@click.option('--validate/--no-validate', show_default=True, default=True,
    help='Perform basic validation of the generated zone')
@click.option('--template-path', default='./templates', show_default=True, 
    help='Template search path')
def main(url, token, parent_prefixes, nameservers, 
    zone, serial, refresh, retry, expire, ttl, relativize, reverse_prefix, validate, template_path):

    origin = dns.name.from_text(zone)
    reverse_origin = get_reverse_origin(reverse_prefix) if reverse_prefix else None
    
    def filter_relativize(name):
        _origin = origin if not reverse_prefix else reverse_origin
        _name = dns.name.from_text(str(name), _origin)
        return _name.relativize(_origin) if relativize else _name

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_path),
        autoescape=jinja2.select_autoescape(),
    )
    env.filters['address'] = filter_address
    env.filters['address_type'] = filter_address_type
    env.filters['fqdn'] = filter_fqdn
    env.filters['relativize'] = filter_relativize
    env.filters['reverse_name'] = filter_reverse_name

    nb = pynetbox.api(url, token)
    ip_addresses = list(nb.ipam.ip_addresses.filter(parent=(reverse_prefix or parent_prefixes)))
    if not reverse_prefix:
        ip_addresses = list(filter(lambda addr: not addr['dns_name'] or dns.name.from_text(addr['dns_name']).is_subdomain(origin), ip_addresses))

    # Ensure nameservers are qualified
    _nameservers = list(map(lambda name: dns.name.from_text(name, origin), nameservers))

    zone_template = env.get_template('zone.j2' if not reverse_prefix else 'zone-reverse.j2')
    rendered_zone = zone_template.render(
        nameservers=_nameservers,
        addresses=ip_addresses,
        origin=origin,
        reverse_origin=reverse_origin,
        serial=serial,
        refresh=refresh,
        retry=retry,
        expire=expire,
        ttl=ttl,
        timestamp=datetime.utcnow().isoformat(timespec='seconds')
    )

    if validate:
        try: dns.zone.from_text(rendered_zone, origin=(reverse_origin or origin))
        except BaseException as err:
            print(f'Zone validation failed: {err}', file=sys.stderr)
            exit(-1)
    
    print(rendered_zone)

if __name__ == '__main__':
    main()