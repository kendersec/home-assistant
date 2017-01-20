"""The tests for the Virgin Superhub 3 device tracker platform."""
import os
import unittest
from unittest import mock
import logging
import requests
import requests_mock

from homeassistant import config
from homeassistant.bootstrap import setup_component
from homeassistant.components import device_tracker
from homeassistant.const import (
    CONF_PLATFORM, CONF_HOST, CONF_PASSWORD)
from homeassistant.components.device_tracker import DOMAIN

from tests.common import (
    get_test_home_assistant, assert_setup_component, load_fixture)

TEST_HOST = '127.0.0.1'
_LOGGER = logging.getLogger(__name__)

_TEST_ONLINE_DATA = {
    '0E:03:E3:41:7F:24': 'pc',
    'CE:EE:FB:24:34:BB': 'android-d0923989',
    'C4:CE:F6:9D:58:85': 'android-d00ab233',
    '4C:CF:85:CA:5D:DF': 'android-ea09233b',
    '5F:1A:C5:BB:7D:AF': 'iPad',
    '88:4A:4A:D4:A8:C0': 'unknown',
    'A0:56:41:BE:A1:49': 'SmartHub',
    'EA:F8:47:02:E3:32': 'machine',
    '65:7A:BA:BF:53:F1': 'iPodtouch'
    }

_TEST_OFFLINE_DATA = {
    'C4:E6:6C:A5:91:00': 'LGwebOSTV',
    'B2:2F:EB:14:99:AE': 'Media'
    }


def _get_snmp_lan_client_table(retrying=False):
    """Return mock homehub data."""
    return load_fixture('virgin_superhub_3_snmp_response.json')


class TestVirginSuperhub3DeviceTracker(unittest.TestCase):
    """Test Virgin Superhub 3 device tracker platform."""

    hass = None

    def setup_method(self, _):
        """Setup things to be run when tests are started."""
        self.hass = get_test_home_assistant()
        self.hass.config.components = ['zone']

    def teardown_method(self, _):
        """Stop everything that was started."""
        self.hass.stop()
        try:
            os.remove(self.hass.config.path(device_tracker.YAML_DEVICES))
        except FileNotFoundError:
            pass

    @mock.patch('homeassistant.components.device_tracker.'
                'virgin_superhub_3._LOGGER.error')
    def test_login_failed(self, mock_error):
        """Create a Virgin Superhub 3 scanner with wrong credentials."""
        with requests_mock.Mocker() as mock_request:
            # Empty response to login
            mock_request.register_uri(
                'GET', r'http://%s/login' % TEST_HOST,
                status_code=200)
            with assert_setup_component(1):
                assert setup_component(
                    self.hass, DOMAIN, {DOMAIN: {
                        CONF_PLATFORM: 'virgin_superhub_3',
                        CONF_HOST: TEST_HOST,
                        CONF_PASSWORD: '0'
                    }})

                self.assertTrue(
                    'Failed to authenticate' in
                    str(mock_error.call_args_list[-1]))

    @mock.patch('homeassistant.components.device_tracker.'
                'virgin_superhub_3._LOGGER.error')
    def test_invalid_response(self, mock_error):
        """Test error handling when response has an error status."""
        with requests_mock.Mocker() as mock_request:
            mock_request.register_uri(
                'GET', r'http://%s/login' % TEST_HOST,
                status_code=444)
            with assert_setup_component(1):
                assert setup_component(
                    self.hass, DOMAIN, {DOMAIN: {
                        CONF_PLATFORM: 'virgin_superhub_3',
                        CONF_HOST: TEST_HOST,
                        CONF_PASSWORD: '0'
                    }})

                self.assertTrue(
                    'Invalid response from Virgin Superhub 3' in
                    str(mock_error.call_args_list[-1]))

    @mock.patch('homeassistant.components.device_tracker.'
                'virgin_superhub_3.requests.get',
                side_effect=requests.exceptions.Timeout)
    @mock.patch('homeassistant.components.device_tracker.'
                'virgin_superhub_3._LOGGER.error')
    def test_get_timeout(self, mock_error, mock_request):
        """Test get Virgin Superhub 3 data with request time out."""
        with assert_setup_component(1):
            assert setup_component(
                self.hass, DOMAIN, {DOMAIN: {
                    CONF_PLATFORM: 'virgin_superhub_3',
                    CONF_HOST: TEST_HOST,
                    CONF_PASSWORD: '0'
                }})

            self.assertTrue(
                'Connection to the router timed out' in
                str(mock_error.call_args_list[-1]))

    def test_scan_devices(self):
        """Test creating device info (MAC, name) from response.

        The created known_devices.yaml device info is compared
        to the Virgin Superhub 3 SNMP request response fixture.
        This effectively checks the data parsing functions.
        """
        with requests_mock.Mocker() as mock_request:
            mock_request.register_uri(
                'GET', r'http://%s/login' % TEST_HOST,
                text="someRandomCredential")
            mock_request.register_uri(
                'GET', r'http://%s/walk' % TEST_HOST,
                text=_get_snmp_lan_client_table())

            with assert_setup_component(1):
                assert setup_component(
                    self.hass, DOMAIN, {DOMAIN: {
                        CONF_PLATFORM: 'virgin_superhub_3',
                        CONF_HOST: TEST_HOST,
                        CONF_PASSWORD: '0'
                    }})
                self.hass.block_till_done()

            path = self.hass.config.path(device_tracker.YAML_DEVICES)
            devices = config.load_yaml_config_file(path)
            for device in devices:
                self.assertIn(
                    devices[device]['mac'],
                    _TEST_ONLINE_DATA.keys())
                self.assertEquals(
                    devices[device]['name'],
                    _TEST_ONLINE_DATA[devices[device]['mac']])

            for device_offline in _TEST_OFFLINE_DATA:
                self.assertEquals(
                    devices.get(device_offline),
                    None)

    def test_with_logout(self):
        """Test error handling of logout when active devices checked.

        The created known_devices.yaml device info is compared
        to the Virgin Superhub 3 SNMP request response fixture.
        This effectively checks the data parsing functions.
        """
        with requests_mock.Mocker() as mock_request:
            mock_request.register_uri(
                'GET', r'http://%s/login' % TEST_HOST,
                text="someRandomCredential")
            mock_request.register_uri(
                'GET', r'http://%s/walk' % TEST_HOST,
                # First we get an unauth because the credentials have expired
                [{"status_code": 401},
                 # Then we try to authenticate again and it works
                 {"text": _get_snmp_lan_client_table()}])

            with assert_setup_component(1):
                assert setup_component(
                    self.hass, DOMAIN, {DOMAIN: {
                        CONF_PLATFORM: 'virgin_superhub_3',
                        CONF_HOST: TEST_HOST,
                        CONF_PASSWORD: '0'
                    }})
                self.hass.block_till_done()

            path = self.hass.config.path(device_tracker.YAML_DEVICES)
            devices = config.load_yaml_config_file(path)
            for device in devices:
                self.assertIn(
                    devices[device]['mac'],
                    _TEST_ONLINE_DATA.keys())
                self.assertEquals(
                    devices[device]['name'],
                    _TEST_ONLINE_DATA[devices[device]['mac']])

            for device_offline in _TEST_OFFLINE_DATA:
                self.assertEquals(
                    devices.get(device_offline),
                    None)

    @mock.patch('homeassistant.components.device_tracker.'
                'virgin_superhub_3._LOGGER.error')
    def test_with_logout_and_auth_fail(self, mock_error):
        """Test error handling of logout when active devices checked."""
        with requests_mock.Mocker() as mock_request:
            mock_request.register_uri(
                'GET', r'http://%s/login' % TEST_HOST,
                # First authenticate fine
                [{"text": "someRandomCredential"},
                 # Then fail to reauthenticate
                 {"text": ""}])
            mock_request.register_uri(
                'GET', r'http://%s/walk' % TEST_HOST,
                # First we get an unauth because the credentials have expired
                [{"status_code": 401},
                 # Then we try to authenticate again and it works
                 # We never reach here
                 {"text": _get_snmp_lan_client_table()}])

            with assert_setup_component(1):
                assert setup_component(
                    self.hass, DOMAIN, {DOMAIN: {
                        CONF_PLATFORM: 'virgin_superhub_3',
                        CONF_HOST: TEST_HOST,
                        CONF_PASSWORD: '0'
                    }})

                self.assertTrue(
                    'Failed to authenticate' in
                    str(mock_error.call_args_list[-1]))

    @mock.patch('homeassistant.components.device_tracker.'
                'virgin_superhub_3._LOGGER.error')
    def test_with_logout_and_client_table_error(self, mock_error):
        """Test error handling of logout when active devices checked."""
        with requests_mock.Mocker() as mock_request:
            mock_request.register_uri(
                'GET', r'http://%s/login' % TEST_HOST,
                text="someRandomCredential")
            mock_request.register_uri(
                'GET', r'http://%s/walk' % TEST_HOST,
                # First we get an unauth because the credentials have expired
                # Then we try to authenticate again and it still fails
                # Make sure we don't get in an infinite loop
                status_code=401)

            with assert_setup_component(1):
                assert setup_component(
                    self.hass, DOMAIN, {DOMAIN: {
                        CONF_PLATFORM: 'virgin_superhub_3',
                        CONF_HOST: TEST_HOST,
                        CONF_PASSWORD: '0'
                    }})

                self.assertTrue(
                    'Failed to authenticate' in
                    str(mock_error.call_args_list[-1]))
