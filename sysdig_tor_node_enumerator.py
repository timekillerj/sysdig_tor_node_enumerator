#!/usr/bin/env python

# Tor Node collection code Adapted from PHP script at
# https://gitlab.com/fissionrelays/lists/-/blob/master/tor.php

import logging
import json
import datetime
import re
from ipaddress import ip_address, IPv4Address
import sys

import requests
from requests.exceptions import RequestException

logging.basicConfig(level=logging.INFO)

##### Configuration #####
RULE_PATH = "/etc/falco/rules.d"
BASE_URL = "https://onionoo.torproject.org";
BASE_HEADERS = {
}

# Relay must be seen within the last 3 hours.
LAST_SEEN_WINDOW = 10800;

# Falco metadata
TOR_IPV4_ALL_NODES = {
    "write_rule": True,
    "list_name": "tor_ipv4_nodes",
    "rule_name": "Connection to Any TOR IPv4 Network Node",
    "file_name": f'{RULE_PATH}/tor_ipv4_all_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": True
}
TOR_IPV4_ENTRY_NODES = {
    "write_rule": True,
    "list_name": "tor_ipv4_entry_nodes",
    "rule_name": "Connection to TOR IPv4 Network Entry Node",
    "file_name": f'{RULE_PATH}/tor_ipv4_entry_nodes_rules.yaml',
    "ingress_rule": False,
    "egress_rule": True
}
TOR_IPV4_EXIT_NODES = {
    "write_rule": True,
    "list_name": "tor_ipv4_exit_nodes",
    "rule_name": "Connection to TOR IPv4 Network Exit Node",
    "file_name": f'{RULE_PATH}/tor_ipv4_exit_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": False
}
TOR_IPV6_ALL_NODES = {
    "write_rule": True,
    "list_name": "tor_ipv6_nodes",
    "rule_name": "Connection to Any TOR IPv6 Network Node",
    "file_name": f'{RULE_PATH}/tor_ipv6_all_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": True
}
TOR_IPV6_ENTRY_NODES = {
    "write_rule": True,
    "list_name": "tor_ipv6_entry_nodes",
    "rule_name": "Connection to TOR IPv6 Network Entry Node",
    "file_name": f'{RULE_PATH}/tor_ipv6_entry_nodes_rules.yaml',
    "ingress_rule": False,
    "egress_rule": True
}
TOR_IPV6_EXIT_NODES = {
    "write_rule": True,
    "list_name": "tor_ipv6_exit_nodes",
    "rule_name": "Connection to TOR IPv6 Network Exit Node",
    "file_name": f'{RULE_PATH}/tor_ipv6_exit_nodes_rules.yaml',
    "ingress_rule": True,
    "egress_rule": False
}
#########################


def pretty_print_request(req):
    logging.debug('{}\n{}\n{}\n\n'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
    ))


def is_good_response(resp):
    content_type = resp.headers['Content-Type'].lower()
    return(resp.status_code == 200 and content_type is not None)


def simple_get(url):
    logging.debug(f'URL: {url}')
    logging.debug('Fetching {}'.format(url))
    logging.debug(f'dict: {BASE_HEADERS}')
    try:
        req = requests.Request('GET', url, headers=BASE_HEADERS)
        prepared = req.prepare()
        pretty_print_request(prepared)

        session = requests.Session()
        resp = session.send(prepared)
        if is_good_response(resp):
            return resp.content
        else:
            return None
    except RequestException as e:
        logging.error('Error during requests to {}: {}'.format(url, str(e)))


def validIPAddress(ip):
    try:
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
    except ValueError:
        return None


def fetch_relays():
    logging.info('Fetching TOR Nodes')
    response_raw = simple_get(f'{BASE_URL}/details')
    try:
        response = json.loads(response_raw.decode())
    except TypeError as e:
        logging.error('Error loading json data: e')
        return None
    f = open("relays.txt", "w")
    f.write(json.dumps(response.get('relays'), indent=2))
    f.close()

    return response.get('relays')


def parse_addresses(relays, last_seen_window):
    logging.info('Parsing addresses out of node results')
    now = int(datetime.datetime.now().timestamp())
    addresses = {
        "ipv4_all": [],
        "ipv6_all": [],
        "ipv4_entry": [],
        "ipv6_entry": [],
        "ipv4_exit": [],
        "ipv6_exit": [],
    }

    logging.info(f'relays found: {len(relays)}')
    for relay in relays:
        is_entry = False
        is_exit = False

        # Check if it's still up
        last_seen = int(datetime.datetime.strptime(relay.get('last_seen'), "%Y-%m-%d %H:%M:%S").timestamp())
        
        if (last_seen < now - last_seen_window):
            logging.debug('Skipping old relay last seen: {}'.format(relay.get('last_seen')))
            continue

        if "Guard" in relay.get('flags', []):
            is_entry = True
        if "Exit" in relay.get('flags', []):
            is_exit = True

        for or_address in relay.get('or_addresses', []):
            or_address_matches= re.findall('^\[?([0-9a-f:.]*)]?:\d+$', or_address)
            logging.debug(f'or_address_matches: {or_address_matches}')
            for address in or_address_matches:
                ip_type = validIPAddress(address)
                if not ip_type:
                    logging.error(f"NOT A VALID IP: {address}")
                    break
                if ip_type == "IPv4" and address not in addresses['ipv4_all']:
                    addresses['ipv4_all'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv4_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv4_exit'].append(f"'{address}'")
                if ip_type == "IPv6" and address not in addresses['ipv6_all']:
                    addresses['ipv6_all'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv6_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv6_exit'].append(f"'{address}'")

        if relay.get('exit_addresses'):
            exit_addresses = relay.get('exit_addresses')
            for address in exit_addresses:
                ip_type = validIPAddress(address)
                if not ip_type:
                    break
                if ip_type == "IPv4" and address not in addresses['ipv4_all']:
                    addresses['ipv4_all'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv4_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv4_exit'].append(f"'{address}'")
                if ip_type == "IPv6" and address not in addresses['ipv6_all']:
                    addresses['ipv6_all'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv6_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv6_exit'].append(f"'{address}'")
    # Remove duplicates
    addresses['ipv4_all'] = list(set(addresses['ipv4_all']))
    addresses['ipv4_entry'] = list(set(addresses['ipv4_entry']))
    addresses['ipv4_exit'] = list(set(addresses['ipv4_exit']))
    addresses['ipv6_all'] = list(set(addresses['ipv6_all']))
    addresses['ipv6_entry'] = list(set(addresses['ipv6_entry']))
    addresses['ipv6_exit'] = list(set(addresses['ipv6_exit']))
    return addresses

def write_falco_rule(rule, addresses):
    logging.info(f'Writing Falco rule {rule["file_name"]}')
    file_text = build_falco_rule(rule,addresses)
    try:
        fh = open(rule["file_name"], "w")
        fh.write(file_text)
        fh.close()
    except PermissionError as e:
        logging.error(f'Error writing file {rule["file_name"]}: {e}')

def build_falco_rule(rule, addresses):
    description = """
#########################
# TOR Node Rule
#########################
    
# This rule is auto-generated and should not be edited manually!
# Rule checks for communication with known TOR relay nodes.

---"""
    list = f"""
- list: "{rule['list_name']}"
  items:
"""
    for address in addresses:
        list = list + f"- {address}\n"
    list = list + "append: false\n"

    if not rule['ingress_rule']:
        ingress_rule = ""
    else:
        ingress_rule = f"""
- rule: {rule['rule_name']}
  desc: "Connections detected in pod or host. The rule was triggered by addresses known to be TOR Nodes"
  condition: "evt.type = connect and evt.dir = < and fd.cip in ({rule['list_name']})"
  output: "Connections to addresses detected in pod or host that are known TOR Nodes. %proc.cmdline %evt.args"
  priority: "WARNING"
  tags:
    - "ioc"
  source: "syscall"
  append: false
"""

    if not rule['egress_rule']:
        egress_rule = ""
    else:
        egress_rule = f"""
- rule: {rule['rule_name']}
  desc: "Connections detected in pod or host. The rule was triggered by addresses known to be TOR Nodes"
  condition: "evt.type = connect and evt.dir = < and fd.sip in ({rule['list_name']})"
  output: "Connections to addresses detected in pod or host that are known TOR Nodes. %proc.cmdline %evt.args"
  priority: "WARNING"
  tags:
    - "ioc"
  source: "syscall"
  append: false
        """
    file_text = description + list + ingress_rule + egress_rule
    return file_text    


if __name__ == "__main__":
    # Fetch TOR Nodes
    relays = fetch_relays();
    if not relays:
        logging.error('No relays found, trying again in 60 seconds')
        sys.exit(1)

    # Parse out the addresses
    addresses = parse_addresses(relays, LAST_SEEN_WINDOW)
    logging.info(f' IPv4: {len(addresses["ipv4_all"])}')
    logging.info(f' IPv4 Entry: {len(addresses["ipv4_entry"])}')
    logging.info(f' IPv4 Exit: {len(addresses["ipv4_exit"])}')

    logging.info(f' IPv6: {len(addresses["ipv6_all"])}')
    logging.info(f' IPv6 Entry: {len(addresses["ipv6_entry"])}')
    logging.info(f' IPv6 Exit: {len(addresses["ipv6_exit"])}')
    
    # Write Rules files
    if TOR_IPV4_ALL_NODES['write_rule']:
        write_falco_rule(TOR_IPV4_ALL_NODES, addresses['ipv4_all'])
    if TOR_IPV4_ENTRY_NODES['write_rule']:
        write_falco_rule(TOR_IPV4_ENTRY_NODES, addresses['ipv4_entry'])
    if TOR_IPV4_EXIT_NODES['write_rule']:
        write_falco_rule(TOR_IPV4_EXIT_NODES, addresses['ipv4_exit'])

    if TOR_IPV6_ALL_NODES['write_rule']:
        write_falco_rule(TOR_IPV6_ALL_NODES, addresses['ipv6_all'])
    if TOR_IPV6_ENTRY_NODES['write_rule']:
        write_falco_rule(TOR_IPV6_ENTRY_NODES, addresses['ipv6_entry'])
    if TOR_IPV6_EXIT_NODES['write_rule']:
        write_falco_rule(TOR_IPV6_EXIT_NODES, addresses['ipv6_exit'])
