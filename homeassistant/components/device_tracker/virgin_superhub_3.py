"""
Support for Virgin Superhub 3 routers.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.virgin_superhub_3/
"""
import logging
import re
import threading
import random
import base64
from datetime import timedelta

import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD
from homeassistant.util import Throttle

# Return cached results if last scan was less then this time ago.
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

_LOGGER = logging.getLogger(__name__)

_ONLINE_IPADDRESS_REGEX = re.compile(
    r'^1\.3\.6\.1\.4\.1\.4115\.1\.20\.1\.1\.2\.4\.2\.1\.14\.200\.1\.4\.(.*)$')

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string
})


# pylint: disable=unused-argument
def get_scanner(hass, config):
    """Validate the configuration and return a Virgin Superhub 3 scanner."""
    try:
        return VirginSuperhub3DeviceScanner(config[DOMAIN])
    except ConnectionError:
        return None


class VirginSuperhub3DeviceScanner(DeviceScanner):
    """This class queries a Virgin Superhub 3."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config.get(CONF_HOST, "192.168.0.1")

        auth = "admin:{}".format(config[CONF_PASSWORD])
        self.auth_base64 = str(base64.b64encode(bytes(auth, "utf-8")), "utf-8")

        _LOGGER.info('Initialising Virgin Superhub 3 scanner at %s', self.host)

        self.lock = threading.Lock()

        self.last_results = {}

        # Login
        if not self._authenticate():
            raise ConnectionError('Cannot connect to Virgin Superhub 3')

    def _authenticate(self):
        """Login and obtain credential. Boolean return for success."""
        # A random salt for the session
        salt = int(random.random() * 10000)
        # We have to be careful here and not use a dictionary or the request
        # will go with % encoding and the router won't like it
        params = 'arg={}&_n={}'.format(self.auth_base64, salt)
        url = 'http://{}/login'.format(self.host)

        try:
            _LOGGER.info("Authenticating...")
            response = requests.get(
                url,
                params=params,
                timeout=5)
        except requests.exceptions.Timeout:
            _LOGGER.exception('Connection to the router timed out')
            return False
        if response.status_code == 200:
            if response.text == "":
                # Authentication error
                _LOGGER.exception(
                    'Failed to authenticate, '
                    'please check your username and password')
                return False
            # Store successful authentication salt
            self.salt = salt
            self.credential = response.text
            return True
        else:
            _LOGGER.error('Invalid response from Virgin Superhub 3: %s',
                          response)
            return False

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        return (device for device in self.last_results)

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        with self.lock:
            # If not initialised and not already scanned and not found.
            if device not in self.last_results:
                self._update_info()

                if not self.last_results:
                    return None

            return self.last_results.get(device)

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """Ensure the information from the Virgin Superhub 3 is up to date.

        Return boolean if scanning successful.
        """
        with self.lock:
            _LOGGER.info('Scanning')

            unparsed_json = self._get_snmp_lan_client_table()
            data = _parse_snmp_table_response(unparsed_json)

            if not data:
                _LOGGER.warning('Error scanning devices')
                return False

            self.last_results = data

            return True

    def _get_snmp_lan_client_table(self, retrying=False):
        """Retrieve data from Virgin Superhub 3 and return parsed result."""
        _LOGGER.info("Getting lan client table")
        try:
            params = {"oids": "1.3.6.1.4.1.4115.1.20.1.1.2.4.2",
                      "_n": self.salt}
            credential_cookie = {"credential": self.credential}

            response = requests.get(
                "http://{}/walk".format(self.host),
                params=params,
                cookies=credential_cookie,
                timeout=60)
        except requests.exceptions.Timeout:
            _LOGGER.exception('Connection to the router timed out')
            return

        if response.status_code == 200:
            _LOGGER.info("Successfully retreived lan client table, parsing...")
            return response.json()
        elif response.status_code == 401:
            _LOGGER.info("Oops, unauthenticated, try authenticating again...")
            # Let's try authenticating again
            if not retrying and self._authenticate():
                return self._get_snmp_lan_client_table(retrying=True)

            # Authentication error
            _LOGGER.exception(
                'Failed to authenticate, '
                'please check your username and password')
            return
        else:
            _LOGGER.error('Invalid response from Virgin Superhub 3: %s',
                          response)


def _parse_snmp_table_response(json):
    """Parse the Virgin Superhub 3 SNMP data format."""
    online_clients = {}

    online_ipaddresses = [m.group(1) for oid in json.keys()
                          for m in [_ONLINE_IPADDRESS_REGEX.search(oid)]
                          if m and json.get(oid, '0') == '1']

    # Find MAC and hostname
    for online_ip in online_ipaddresses:
        mac_key = \
            "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.4.200.1.4.{}".format(online_ip)
        mac = _pretty_mac(json.get(mac_key))
        hostname_key = \
            "1.3.6.1.4.1.4115.1.20.1.1.2.4.2.1.3.200.1.4.{}".format(online_ip)
        hostname = json.get(hostname_key)

        online_clients[mac] = hostname

    return online_clients


def _pretty_mac(ugly_mac):
    return ":".join(re.findall('.{1,2}', ugly_mac[1:].upper()))
