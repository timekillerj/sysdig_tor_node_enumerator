#!/usr/bin/env python

# Tor Node collection code Adapted from PHP script at
# https://gitlab.com/fissionrelays/lists/-/blob/master/tor.php

import logging
import json
import datetime
import re
from ipaddress import ip_address, IPv4Address
import os

import requests
from requests.exceptions import RequestException
from sdcclient import SdSecureClient

SYSDIG_TOKEN = os.environ.get('SECURE_API_TOKEN')
SYSDIG_URL = os.environ.get('SECURE_URL')

BASE_URL = "https://onionoo.torproject.org";
BASE_HEADERS = {
}

# Falco Lists
TOR_IPV4_NODES = "tor_ipv4_nodes"
TOR_IPV4_ENTRY_NODES = "tor_ipv4_entry_nodes"
TOR_IPV4_EXIT_NODES = "tor_ipv4_exit_nodes"
TOR_IPV6_NODES = "tor_ipv6_nodes"
TOR_IPV6_ENTRY_NODES = "tor_ipv6_entry_nodes"
TOR_IPV6_EXIT_NODES = "tor_ipv6_exit_nodes"

# Relay must be seen within the last 3 hours.
LAST_SEEN_WINDOW = 10800;

logging.basicConfig(level=logging.INFO)


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
    response_raw = simple_get(f'{BASE_URL}/details')
    # logging.info(f'response_raw: {response_raw}')
    try:
        response = json.loads(response_raw.decode())
    except TypeError as e:
        logging.error('Error loading json data: e')
        return None
    # logging.info(f'response: {response}')
    return response.get('relays')


def parse_addresses(relays, last_seen_window):
    now = int(datetime.datetime.now().timestamp())
    addresses = {
        "ipv4": [],
        "ipv6": [],
        "ipv4_entry": [],
        "ipv6_entry": [],
        "ipv4_exit": [],
        "ipv6_exit": []
    }

    for relay in relays:
        is_entry = False
        is_exit = False

        # Check if it's still up
        last_seen = int(datetime.datetime.strptime(relay.get('last_seen'), "%Y-%m-%d %H:%M:%S").timestamp())
        if (last_seen < now - last_seen_window):
            continue

        if "Guard" in relay.get('flags', []):
            is_entry = True
        if "Exit" in relay.get('flags', []):
            is_exit = True

        for or_address in relay.get('or_addresses', []):
            or_address_matches= re.findall('^\[?([0-9a-f:.]*)]?:\d+$', or_address)
            # logging.info(f'or_address_matches: {or_address_matches}')
            address = or_address_matches[0]
            ip_type = validIPAddress(address)
            if not ip_type:
                break
            if ip_type == "IPv4" and address not in addresses['ipv4']:
                addresses['ipv4'].append(address)
                if is_entry:
                    addresses['ipv4_entry'].append(address)
                if is_exit:
                    addresses['ipv4_exit'].append(address)
            if ip_type == "IPv6" and address not in addresses['ipv6']:
                addresses['ipv6'].append(address)
                if is_entry:
                    addresses['ipv6_entry'].append(address)
                if is_exit:
                    addresses['ipv6_exit'].append(address)

        if relay.get('exit_addresses'):
            exit_addresses = relay.get('exit_addresses')
            for address in exit_addresses:
                ip_type = validIPAddress(address)
                if not ip_type:
                    break
                if ip_type == "IPv4" and address not in addresses['ipv4']:
                    addresses['ipv4'].append(address)
                    if is_entry:
                        addresses['ipv4_entry'].append(address)
                    if is_exit:
                        addresses['ipv4_exit'].append(address)
                if ip_type == "IPv6" and address not in addresses['ipv6']:
                    addresses['ipv6'].append(address)
                    if is_entry:
                        addresses['ipv6_entry'].append(address)
                    if is_exit:
                        addresses['ipv6_exit'].append(address)
    return addresses

def create_falco_list(falco_list, addresses):
    ok, res = sdclient.add_falco_list(falco_list, addresses)
    if not ok:
        logging.error(f'Error creating Falco list: {res}')
        return False
    return True

def update_falco_list(id, addresses):
    ok, res = sdclient.update_falco_list(id, addresses)
    if not ok:
        logging.error(f'Error updating Falco List: {res}')
        return False
    return True

def send_falco_list_addresses(falco_list, addresses):
    # First get Falco List
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


if __name__ == "__main__":
    # Fetch TOR Nodes
    relays = fetch_relays();
    if not relays:
        sys.exit(1)

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
    send_falco_list_addresses(TOR_IPV4_NODES, addresses['ipv4'])
    send_falco_list_addresses(TOR_IPV4_ENTRY_NODES, addresses['ipv4_entry'])
    send_falco_list_addresses(TOR_IPV4_EXIT_NODES, addresses['ipv4_exit'])

    send_falco_list_addresses(TOR_IPV6_NODES, addresses['ipv6'])
    send_falco_list_addresses(TOR_IPV6_ENTRY_NODES, addresses['ipv6_entry'])
    send_falco_list_addresses(TOR_IPV6_EXIT_NODES, addresses['ipv6_exit'])

    # Insert / Update Falco Rules