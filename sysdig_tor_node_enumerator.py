#!/usr/bin/env python

# Tor Node collection code Adapted from PHP script at
# https://gitlab.com/fissionrelays/lists/-/blob/master/tor.php

import logging
import json
import datetime
import re
from ipaddress import ip_address, IPv4Address

import requests
from requests.exceptions import RequestException


BASE_URL = "https://onionoo.torproject.org";
BASE_HEADERS = {
}

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


if __name__ == "__main__":
    relays = fetch_relays();
    if relays:
        addresses = parse_addresses(relays, LAST_SEEN_WINDOW)
        logging.info(f' IPv4: {len(addresses["ipv4"])}')
        logging.info(f' IPv4 Entry: {len(addresses["ipv4_entry"])}')
        logging.info(f' IPv4 Exit: {len(addresses["ipv4_exit"])}')

        logging.info(f' IPv6: {len(addresses["ipv6"])}')
        logging.info(f' IPv6 Entry: {len(addresses["ipv6_entry"])}')
        logging.info(f' IPv6 Exit: {len(addresses["ipv6_exit"])}')
        