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
import hashlib
import dns.name
import dns.reversename
import dns.rrset
import dns.rdata
import dns.rdataset
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes
import dns.zone

import custom_rdtypes

dotenv.load_dotenv()

custom_rdtypes.register_custom_types()

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

def generate_zone_hash(zone, remove_txt_attributes, reset_serial):
    def clean_rdata(rdata: dns.rdata.Rdata):
        if isinstance(rdata, dns.rdtypes.ANY.SOA.SOA) and reset_serial:
            return rdata.replace(serial=0)
        if isinstance(rdata, dns.rdtypes.ANY.TXT.TXT):
            _attribute = rdata.to_text().strip('"').split('=')
            if _attribute and _attribute[0] in remove_txt_attributes:
                return rdata.replace(strings=f'{_attribute[0]}=removed')
        return rdata

    try: 
        rdset: dns.rdataset.Rdataset
        for name, rdset in zone.iterate_rdatasets():
            updated_rdata = []
            for rdata in rdset.items:
                _rdata = clean_rdata(rdata)
                if _rdata: updated_rdata.append(_rdata)
            
            rdset.clear()
            for rdata in updated_rdata: rdset.add(rdata)

        zone_text: str = zone.to_text(sorted=True, relativize=False, nl='\n', want_comments=False, want_origin=False)
        return hashlib.sha1(zone_text.encode('utf-8')).hexdigest()
        
    except BaseException as err:
        print(f'Zone hash failed: {err}', file=sys.stderr)
        exit(-1)

def output(name, text: str, file=sys.stdout, github_actions=False):
    if github_actions:
        escaped_text = text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print(f'::set-output name={name}::{escaped_text}', file=sys.stdout)
    else:
        print(text, file=file)
       
@click.group()
def cli():
    pass

@cli.command()
@click.argument('zone-file', metavar='<zone file>', required=False, type=click.File('w'))
@click.option('--url', envvar='NETBOX_URL', show_default='$NETBOX_URL', required=True, help='Netbox base URL')
@click.option('--token', envvar='NETBOX_TOKEN', show_default='$NETBOX_TOKEN', required=True, help='Netbox API Token')
@click.option('--parent-prefix', 'parent_prefixes', metavar='CIDR', multiple=True, show_default=True, default=('0.0.0.0/0', '::/0'),
    callback=validate_prefix, help='Limit IP Adresses to the specified prefixes (can be specified multiple times)')
@click.option('--nameserver', 'nameservers', metavar='DNSNAME', multiple=True, required=True, callback=validate_dns_name,
    help='Nameserver names of the zone (can be specified multiple times)')
@click.option('--include', 'includes', metavar='FILE', multiple=True, default=[], type=click.File('r'),
    help='Files to include at the end of the generated zone file (can be specified multiple times)')
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
@click.option('--template-path', envvar='DNS_ZONE_TEMPLATE_PATH', default='./templates', show_default=True, 
    help='Template search path')
@click.option('--hash-remove-txt-attribute', 'hash_remove_txt_attributes', multiple=True, default=['generated-at'])
@click.option('--hash-reset-serial/--no-hash-reset-serial', default=True)
@click.option('--hash-only', is_flag=True)
@click.option('--github-actions', is_flag=True, envvar='GITHUB_ACTIONS')
def generate(zone_file, url, token, parent_prefixes, nameservers, includes,
    zone, serial, refresh, retry, expire, ttl, relativize, reverse_prefix, validate, template_path,
    hash_remove_txt_attributes, hash_reset_serial, hash_only, github_actions):
    """
    Generates a zone file. Use '-' for stdout.
    """

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
        ip_addresses = list(filter(lambda addr: not addr['dns_name'] or dns.name.from_text(addr['dns_name'], origin=origin).is_subdomain(origin), ip_addresses))

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
        timestamp=datetime.utcnow().isoformat(timespec='seconds'),
        includes=includes
    )

    if validate or hash_only:
        try: 
            parsed_zone = dns.zone.from_text(rendered_zone, relativize=False, allow_include=True)
            zone_hash = generate_zone_hash(parsed_zone, hash_remove_txt_attributes, hash_reset_serial)
            if hash_only or github_actions: 
                output('zone_hash', zone_hash, file=sys.stdout, github_actions=github_actions)
        except BaseException as err:
            print(f'Zone validation failed: {err}', file=sys.stderr)
            exit(-1)
    
    if (not hash_only) or github_actions: 
        output('rendered_zone', rendered_zone, file=zone_file or sys.stdout, github_actions=github_actions)

@cli.command()
@click.argument('zone-file', metavar='<zone file>', type=click.File())
@click.option('--hash-remove-txt-attribute', 'remove_txt_attributes', multiple=True, default=['generated-at'])
@click.option('--hash-reset-serial/--no-hash-reset-serial', 'reset_serial', default=True)
@click.option('--github-actions', is_flag=True, envvar='GITHUB_ACTIONS')
def zone_hash(zone_file, remove_txt_attributes, reset_serial, github_actions):
    """
    Prints the hash of a zone file. Use '-' for stdin.

    The hash is calculated over all records in the zone,
    ignoring some dynamic values (e.g. SOA serial, certain TXT
    attributes).

    It can be used in conjunction with 'generate --hash-only ...'
    to check if a zone file needs to be updated.
    """

    def map_rdata(rdata: dns.rdata.Rdata):
        if isinstance(rdata, dns.rdtypes.ANY.SOA.SOA) and reset_serial:
            return rdata.replace(serial=0)
        if isinstance(rdata, dns.rdtypes.ANY.TXT.TXT):
            _attribute = rdata.to_text().strip('"').split('=')
            if _attribute and _attribute[0] in remove_txt_attributes:
                return rdata.replace(strings=f'{_attribute[0]}=removed')
            
        return rdata

    try: 
        zone = dns.zone.from_file(zone_file, relativize=False, allow_include=True)
        hash = generate_zone_hash(zone, remove_txt_attributes, reset_serial)
        output('zone_hash', hash, file=sys.stdout, github_actions=github_actions)
    except BaseException as err:
        print(f'Zone hash failed: {err}', file=sys.stderr)
        exit(-1)

if __name__ == '__main__':
    cli()