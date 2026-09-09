"""Проверки настоящими движками; пути задаются SINGBOX_BINARY и MIHOMO_BINARY."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from ruleset_builder import FileProcessor, RulesetGenerator


SINGBOX = os.environ.get('SINGBOX_BINARY')
MIHOMO = os.environ.get('MIHOMO_BINARY')


@unittest.skipUnless(SINGBOX, 'Укажите SINGBOX_BINARY для проверки Sing-box')
class SingboxIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ruleset test .json ')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def command(self, *args):
        result = subprocess.run([SINGBOX, '--disable-color', 'rule-set', *args],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout + result.stderr

    def test_source_and_binary_matching(self):
        data = {
            'domain': ['EXACT.test', 'пример.рф'],
            'domain_suffix': ['inclusive.test', '.subonly.test'],
            'domain_keyword': ['needle'],
            'domain_regex': [r'^regex[0-9]+\p{L}\.test$'],
            'ip_cidr': ['192.0.2.123/24', '2001:db8::123/32'],
        }
        success, messages = RulesetGenerator.export(data, str(self.directory / 'rules'), ['srs'], SINGBOX)
        self.assertTrue(success, messages)
        cases = {
            'exact.test': True, 'a.exact.test': False, 'notexact.test': False,
            'xn--e1afmkfd.xn--p1ai': True, 'other.xn--p1ai': False,
            'inclusive.test': True, 'a.inclusive.test': True, 'a.b.inclusive.test': True,
            'notinclusive.test': False, 'inclusive.test.evil': False,
            'subonly.test': False, 'a.subonly.test': True, 'a.b.subonly.test': True,
            'notsubonly.test': False, 'subonly.test.evil': False,
            'hayneedlehay.test': True, 'haystack.test': False,
            'regex12x.test': True, 'regexx.test': False, 'regex12x.test.evil': False,
            '192.0.2.0': True, '192.0.2.255': True, '192.0.1.255': False, '192.0.3.0': False,
            '2001:db8::': True, '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff': True,
            '2001:db9::': False, '::1': False,
        }
        for format, extension in [('source', 'json'), ('binary', 'srs')]:
            for address, expected in cases.items():
                with self.subTest(format=format, address=address):
                    output = self.command('match', '--format', format, str(self.directory / ('rules.' + extension)), address)
                    self.assertEqual('match rules.' in output, expected, output)

    def test_all_supported_fields_survive_binary_round_trip(self):
        data = {
            'domain': ['example.com'], 'domain_suffix': ['example.net', '.example.org'],
            'domain_keyword': ['ads'], 'domain_regex': [r'^stun\..+'],
            'ip_cidr': ['192.0.2.0/24'], 'source_ip_cidr': ['2001:db8::/32'],
            'process_path_regex': [r'^/usr/bin/firefox$'], 'package_name': ['org.example.app'],
            'network_type': ['wifi', 'cellular'], 'network_is_expensive': True, 'network_is_constrained': True,
            'network_interface_address': {'wifi': ['192.168.0.0/16'], 'cellular': ['2001:db8::/32']},
            'default_interface_address': ['10.0.0.0/8', 'fc00::/7'],
        }
        success, messages = RulesetGenerator.export(data, str(self.directory / 'all'), ['srs'], SINGBOX)
        self.assertTrue(success, messages)
        output = self.directory / 'decompiled.json'
        self.command('decompile', '--output', str(output), str(self.directory / 'all.srs'))
        actual = {key: value for rule in json.loads(output.read_text())['rules'] for key, value in rule.items()}
        expected = FileProcessor.normalize_data(data)
        # Sing-box может сериализовать единственное значение без массива.
        for key, value in expected.items():
            with self.subTest(field=key):
                self.assertIn(key, actual)
                result = actual[key]
                if isinstance(value, list) and not isinstance(result, list):
                    result = [result]
                if isinstance(value, dict):
                    result = {name: addresses if isinstance(addresses, list) else [addresses] for name, addresses in result.items()}
                if isinstance(value, list):
                    self.assertCountEqual(result, value)
                else:
                    self.assertEqual(result, value)

    def test_invalid_go_regex_does_not_replace_previous_json(self):
        output = self.directory / 'rules.json'
        output.write_text('previous rules')
        for pattern in ['[', '(?=ads)', r'(a)\1', 'a{1001}']:
            with self.subTest(pattern=pattern):
                success, _, _ = RulesetGenerator.generate_singbox_json({'domain_regex': [pattern]}, str(output), SINGBOX)
                self.assertFalse(success)
                self.assertEqual(output.read_text(), 'previous rules')

    def test_source_and_destination_conditions_route_independently(self):
        data = {'domain': ['exact.test'], 'source_ip_cidr': ['127.0.0.2/32'],
                'ip_cidr': ['192.0.2.0/24', '2001:db8::/32']}
        success, messages = RulesetGenerator.export(data, str(self.directory / 'routing'), ['srs'], SINGBOX)
        self.assertTrue(success, messages)
        with origin_server() as origin_port:
            for format, extension in [('source', 'json'), ('binary', 'srs')]:
                provider = self.directory / ('routing.' + extension)
                with singbox_proxy(self.directory, provider, format, origin_port) as port:
                    for source, destination, expected in [
                        ('127.0.0.1', 'exact.test', True),
                        ('127.0.0.1', 'outside.test', False),
                        ('127.0.0.2', 'outside.test', True),
                        ('127.0.0.1', '192.0.2.0', True),
                        ('127.0.0.1', '192.0.2.255', True),
                        ('127.0.0.1', '192.0.3.0', False),
                        ('127.0.0.1', '2001:db8::123', True),
                        ('127.0.0.1', '2001:db9::', False),
                    ]:
                        with self.subTest(format=format, source=source, destination=destination):
                            self.assertEqual(proxy_status(port, destination, origin_port, source) == 200, expected)


class OriginHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        # Локальный HTTP-прокси принимает любой адрес назначения, включая IPv6.
        # Сокет к самому адресу не открывается: проверяется выбор маршрута Mihomo.
        self.send_response(200)
        self.end_headers()
        self.close_connection = False

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, *args):
        pass


@contextmanager
def origin_server(address='127.0.0.1'):
    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ':' in address else socket.AF_INET
    server = Server((address, 0), OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def mihomo_proxy(directory, provider, behavior, format, origin_port, hosts=None):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        api_port = listener.getsockname()[1]
    config = {
        'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False,
        'mode': 'rule', 'log-level': 'info', 'ipv6': True, 'hosts': hosts or {},
        'dns': {'enable': False}, 'geo-auto-update': False,
        'external-controller': f'127.0.0.1:{api_port}',
        'proxies': [{'name': 'TEST-ORIGIN', 'type': 'http', 'server': '127.0.0.1', 'port': origin_port}],
        'rule-providers': {'test': {'type': 'file', 'behavior': behavior, 'format': format, 'path': str(provider)}},
        'rules': ['DOMAIN,ready.ruleset.test,TEST-ORIGIN', 'RULE-SET,test,TEST-ORIGIN', 'MATCH,REJECT'],
    }
    config_path = directory / 'config.yaml'
    config_path.write_text(json.dumps(config), encoding='utf-8')
    with (directory / 'mihomo.log').open('w+') as log:
        process = subprocess.Popen([MIHOMO, '-d', str(directory), '-f', str(config_path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None or time.monotonic() > deadline:
                    log.seek(0)
                    raise AssertionError('Mihomo не запустился: ' + log.read())
                try:
                    connection = HTTPConnection('127.0.0.1', api_port, timeout=0.2)
                    connection.request('GET', '/providers/rules')
                    response = json.loads(connection.getresponse().read())
                    connection.close()
                    provider_ready = (response.get('providers') or {}).get('test', {}).get('ruleCount', 0) > 0
                    # API и provider могут быть готовы раньше самого прокси.
                    # Контрольный маршрут не использует проверяемый ruleset.
                    if provider_ready and proxy_status(port, 'ready.ruleset.test', origin_port) == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@contextmanager
def singbox_proxy(directory, provider, format, origin_port):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config = {
        'log': {'level': 'warn'},
        'inbounds': [{'type': 'http', 'listen': '127.0.0.1', 'listen_port': port}],
        'outbounds': [{'type': 'http', 'tag': 'TEST-ORIGIN', 'server': '127.0.0.1', 'server_port': origin_port}],
        'route': {
            'rule_set': [{'tag': 'test', 'type': 'local', 'format': format, 'path': str(provider)}],
            'rules': [{'rule_set': ['test'], 'action': 'route', 'outbound': 'TEST-ORIGIN'}, {'action': 'reject'}],
        },
    }
    config_path = directory / 'singbox-config.json'
    config_path.write_text(json.dumps(config), encoding='utf-8')
    with (directory / 'singbox.log').open('w+') as log:
        process = subprocess.Popen([SINGBOX, '--disable-color', 'run', '--config', str(config_path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None or time.monotonic() > deadline:
                    log.seek(0)
                    raise AssertionError('Sing-box не запустился: ' + log.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def proxy_status(port, host, origin_port, source='127.0.0.1'):
    authority = f'[{host}]' if ':' in host else host
    with socket.create_connection(('127.0.0.1', port), timeout=3, source_address=(source, 0)) as connection:
        connection.settimeout(3)
        request = f'GET http://{authority}:{origin_port}/ HTTP/1.1\r\nHost: {authority}:{origin_port}\r\nConnection: close\r\n\r\n'
        connection.sendall(request.encode('ascii'))
        response = b''
        while b'\r\n' not in response:
            data = connection.recv(4096)
            if not data:
                break
            response += data
        return int(response.split(b' ', 2)[1]) if response else 0


@unittest.skipUnless(MIHOMO, 'Укажите MIHOMO_BINARY для проверки Mihomo')
class MihomoIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mihomo rules .json ')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def export(self, data):
        success, messages = RulesetGenerator.export(data, str(self.directory / 'rules'), ['mrs'], mihomo_path=MIHOMO)
        self.assertTrue(success, messages)

    def test_yaml_and_mrs_route_domain_requests(self):
        self.export({'domain': ['exact.test', '*.one.test', 'part.*.mask.test', 'пример.рф', 'true'],
                     'domain_suffix': ['inclusive.test', '.subonly.test']})
        cases = {
            'exact.test': True, 'a.exact.test': False, 'notexact.test': False,
            'inclusive.test': True, 'a.inclusive.test': True, 'a.b.inclusive.test': True,
            'notinclusive.test': False, 'inclusive.test.evil': False,
            'subonly.test': False, 'a.subonly.test': True, 'a.b.subonly.test': True,
            'notsubonly.test': False, 'subonly.test.evil': False,
            'one.test': False, 'a.one.test': True, 'a.b.one.test': False,
            'part.a.mask.test': True, 'part.a.b.mask.test': False, 'other.a.mask.test': False,
            'xn--e1afmkfd.xn--p1ai': True, 'other.xn--p1ai': False, 'true': True,
        }
        with origin_server() as origin_port:
            for format, filename in [('yaml', 'rules_mihomo.yaml'), ('mrs', 'rules.mrs')]:
                with mihomo_proxy(self.directory, self.directory / filename, 'domain', format, origin_port,
                                  {host: '127.0.0.1' for host in cases}) as port:
                    for host, expected in cases.items():
                        with self.subTest(format=format, host=host):
                            status = proxy_status(port, host, origin_port)
                            self.assertEqual(status == 200, expected,
                                             f'HTTP {status}\n{(self.directory / "mihomo.log").read_text()}')

    def test_yaml_and_mrs_route_ipv4_and_ipv6_requests(self):
        self.export({'ip_cidr': ['127.0.0.1', '::1']})
        with origin_server() as origin_port:
            for format, filename in [('yaml', 'rules_mihomo.yaml'), ('mrs', 'rules.mrs')]:
                with mihomo_proxy(self.directory, self.directory / filename, 'ipcidr', format, origin_port) as port:
                    for host, expected in [('127.0.0.1', True), ('127.0.0.2', False), ('::1', True), ('2001:db8::', False)]:
                        with self.subTest(format=format, host=host):
                            self.assertEqual(proxy_status(port, host, origin_port) == 200, expected)

    def test_mrs_cidr_round_trip_boundaries(self):
        self.export({'ip_cidr': ['192.0.2.123/24', '2001:db8::123/32', '::1']})
        target = self.directory / 'decoded.txt'
        subprocess.run([MIHOMO, 'convert-ruleset', 'ipcidr', 'mrs', str(self.directory / 'rules.mrs'), str(target)],
                       check=True, capture_output=True, timeout=20)
        networks = [ipaddress.ip_network(line) for line in target.read_text().splitlines()]
        for value, expected in [('192.0.2.0', True), ('192.0.2.255', True), ('192.0.3.0', False),
                                ('2001:db8::', True), ('2001:db8:ffff::', True), ('2001:db9::', False), ('::1', True)]:
            with self.subTest(address=value):
                address = ipaddress.ip_address(value)
                self.assertEqual(any(address in network for network in networks if address.version == network.version), expected)

    def test_failed_real_compile_keeps_existing_mrs(self):
        self.export({'domain': ['example.com']})
        output = self.directory / 'rules.mrs'
        previous = output.read_bytes()
        bad_yaml = self.directory / 'bad.yaml'
        bad_yaml.write_text('payload:\n  - *.example.com\n')
        success, _ = RulesetGenerator.compile_mrs(MIHOMO, str(bad_yaml), str(output))
        self.assertFalse(success)
        self.assertEqual(output.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
