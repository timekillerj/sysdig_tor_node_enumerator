#!/usr/bin/env python

# Tor Node collection code Adapted from PHP script at
# https://gitlab.com/fissionrelays/lists/-/blob/master/tor.php

import logging
import json
import datetime
import re
from ipaddress import ip_address, IPv4Address
import os
import time

import requests
from requests.exceptions import RequestException
from sdcclient import SdSecureClient

logging.basicConfig(level=logging.INFO)

SYSDIG_TOKEN = os.environ.get('SECURE_API_TOKEN')
SYSDIG_URL = os.environ.get('SECURE_URL')

BASE_URL = "https://onionoo.torproject.org";
BASE_HEADERS = {
}

# Relay must be seen within the last 3 hours.
LAST_SEEN_WINDOW = 10800;

# Falco metadata
TOR_IPV4_NODES = {
    "list_name": "tor_ipv4_nodes",
    "rule_name": "Connection to TOR IPv4 Network Node"
}
TOR_IPV4_ENTRY_NODES = {
    "list_name": "tor_ipv4_entry_nodes",
    "rule_name": "Connection to TOR IPv4 Network Entry Node"
}
TOR_IPV4_EXIT_NODES = {
    "list_name": "tor_ipv4_exit_nodes",
    "rule_name": "Connection to TOR IPv4 Network Exit Node"
}
TOR_IPV6_NODES = {
    "list_name": "tor_ipv6_nodes",
    "rule_name": "Connection to TOR IPv6 Network Node"
}
TOR_IPV6_ENTRY_NODES = {
    "list_name": "tor_ipv6_entry_nodes",
    "rule_name": "Connection to TOR IPv6 Network Entry Node"
}
TOR_IPV6_EXIT_NODES = {
    "list_name": "tor_ipv6_exit_nodes",
    "rule_name": "Connection to TOR IPv6 Network Exit Node"
}


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
        "ipv4": [],
        "ipv6": [],
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
                if ip_type == "IPv4" and address not in addresses['ipv4']:
                    addresses['ipv4'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv4_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv4_exit'].append(f"'{address}'")
                if ip_type == "IPv6" and address not in addresses['ipv6']:
                    addresses['ipv6'].append(f"'{address}'")
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
                if ip_type == "IPv4" and address not in addresses['ipv4']:
                    addresses['ipv4'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv4_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv4_exit'].append(f"'{address}'")
                if ip_type == "IPv6" and address not in addresses['ipv6']:
                    addresses['ipv6'].append(f"'{address}'")
                    if is_entry:
                        addresses['ipv6_entry'].append(f"'{address}'")
                    if is_exit:
                        addresses['ipv6_exit'].append(f"'{address}'")
    # Remove duplicates
    addresses['ipv4'] = list(set(addresses['ipv4']))
    addresses['ipv4_entry'] = list(set(addresses['ipv4_entry']))
    addresses['ipv4_exit'] = list(set(addresses['ipv4_exit']))
    addresses['ipv6'] = list(set(addresses['ipv6']))
    addresses['ipv6_entry'] = list(set(addresses['ipv6_entry']))
    addresses['ipv6_exit'] = list(set(addresses['ipv6_exit']))
    return addresses

def create_falco_list(falco_list, addresses):
    logging.info('Creating Falco list')
    ok, res = sdclient.add_falco_list(falco_list, addresses)
    if not ok:
        logging.error(f'Error creating Falco list: {res}')
        return False
    return True

def update_falco_list(id, addresses):
    logging.info('Updating Falco list')
    ok, res = sdclient.update_falco_list(id, addresses)
    if not ok:
        logging.error(f'Error updating Falco List: {res}')
        return False
    return True

def send_falco_list_addresses(falco_list, addresses):
    # First get Falco List
    logging.info(f'Looking for Falco list: {falco_list}')
    ok, res = sdclient.get_falco_lists_group(falco_list)
    if not ok:
        logging.error(f'Could not get Falco Lists: {res}')
        return None

    if not res:
        # Create the Falco list
        ok = create_falco_list(falco_list, addresses)
    else:
        # Update existing list
        # TODO: Assuming only one result here, what if we get two?
        list_id = res[0].get('id')
        ok = update_falco_list(list_id, addresses)
    if not ok:
        return False
    
    return True


def build_rule(rule):
    list_name = rule['list_name']
    falco_rule = {
        "details": {
            "append": False,
            "ruleType": "FALCO",
            "source": "syscall",
            "output": "Connections to addresses detected in pod or host that are known TOR Nodes. %proc.cmdline %evt.args",
            "condition": {
                "condition": f'evt.type = connect and evt.dir = < and fd.sip in ({list_name})\n',
                "components": []
            },
            "priority": "warning"
        },
        "description": "Connections detected in pod or host. The rule was triggered by addresses known to be TOR Nodes",
        "tags": ["ioc"]
    }
    return falco_rule


def send_falco_rule(rule):
    # First See if rule exists
    rule_name = rule['rule_name']
    logging.info(f'Looking for Falco rule: {rule_name}')
    ok, res = sdclient.get_rules_group(rule['rule_name'])
    if not ok:
        logging.error(f'Could not get Falco rules: {res}')
        return None

    falco_rule = build_rule(rule)

    if not res:
        # Create Falco rule
        falco_rule['name'] = rule['rule_name']
        logging.info('Creating Falco rule')
        ok, res = sdclient.add_rule(**falco_rule)
        if not ok:
            logging.error(f'Could not create rule: {res}')
    else:
        # Update Falco Rule
        # TODO: Assuming only one result here, what if we get two?
        falco_rule['id'] = res[0]['id']
        logging.info('Updating Falco rule')
        ok, res = sdclient.update_rule(**falco_rule)
        if not ok:
            logging.error(f'Could not update rule: {res}')

if __name__ == "__main__":
    while True:
        # Fetch TOR Nodes
        relays = fetch_relays();
        if not relays:
            logging.error('No relays found, trying again in 60 seconds')
            time.sleep(60)
            continue

        # Parse out the addresses
        addresses = parse_addresses(relays, LAST_SEEN_WINDOW)
        logging.info(f' IPv4: {len(addresses["ipv4"])}')
        logging.info(f' IPv4 Entry: {len(addresses["ipv4_entry"])}')
        logging.info(f' IPv4 Exit: {len(addresses["ipv4_exit"])}')

        logging.info(f' IPv6: {len(addresses["ipv6"])}')
        logging.info(f' IPv6 Entry: {len(addresses["ipv6_entry"])}')
        logging.info(f' IPv6 Exit: {len(addresses["ipv6_exit"])}')
        
        # Connect to Sysdig Secure
        sdclient = SdSecureClient(SYSDIG_TOKEN, SYSDIG_URL)

        # Insert / Update TOR IP4V Nodes
        send_falco_list_addresses(TOR_IPV4_NODES['list_name'], addresses['ipv4'])
        send_falco_list_addresses(TOR_IPV4_ENTRY_NODES['list_name'], addresses['ipv4_entry'])
        send_falco_list_addresses(TOR_IPV4_EXIT_NODES['list_name'], addresses['ipv4_exit'])

        send_falco_list_addresses(TOR_IPV6_NODES['list_name'], addresses['ipv6'])
        send_falco_list_addresses(TOR_IPV6_ENTRY_NODES['list_name'], addresses['ipv6_entry'])
        send_falco_list_addresses(TOR_IPV6_EXIT_NODES['list_name'], addresses['ipv6_exit'])

        # Insert / Update Falco Rules
        send_falco_rule(TOR_IPV4_NODES)
        send_falco_rule(TOR_IPV4_ENTRY_NODES)
        send_falco_rule(TOR_IPV4_EXIT_NODES)

        send_falco_rule(TOR_IPV6_NODES)
        send_falco_rule(TOR_IPV6_ENTRY_NODES)
        send_falco_rule(TOR_IPV6_EXIT_NODES)
        time.sleep(1800)