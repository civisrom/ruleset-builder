import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ruleset_builder import FileProcessor, RulesetGenerator


class RulesetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_missing_input_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            FileProcessor.read_large_file(str(self.directory / 'missing.txt'))

    def test_utf8_bom_and_comments(self):
        source = self.directory / 'domains.txt'
        source.write_text('# comment\nexample.com\n\n', encoding='utf-8-sig')
        self.assertEqual(FileProcessor.read_large_file(str(source)), ['example.com'])

    def test_invalid_encoding_is_not_silently_discarded(self):
        source = self.directory / 'domains.txt'
        source.write_bytes(b'bad\xff.com\n')
        with self.assertRaises(UnicodeDecodeError):
            FileProcessor.read_large_file(str(source))

    def test_ipv6_and_invalid_prefixes(self):
        for value in ['2001:db8::/32', '::1', '192.0.2.1', '192.0.2.0/24']:
            with self.subTest(value=value):
                self.assertTrue(FileProcessor.validate_ip_cidr(value))
        for value in ['300.1.2.3', '::/129', '192.0.2.0/33', 'example.com']:
            with self.subTest(value=value):
                self.assertFalse(FileProcessor.validate_ip_cidr(value))

    def test_international_domains(self):
        self.assertTrue(FileProcessor.validate_domain('пример.рф'))
        self.assertFalse(FileProcessor.validate_domain('..example.com'))
        self.assertFalse(FileProcessor.validate_domain('a' * 254))

    def test_singbox_network_rules_use_supported_version(self):
        output = self.directory / 'rules.json'
        success, message, _ = RulesetGenerator.generate_singbox_json(
            {'network_type': 'wifi', 'network_is_expensive': True}, str(output))
        self.assertTrue(success, message)
        content = json.loads(output.read_text())
        self.assertEqual(content['version'], 3)
        self.assertTrue(any(rule.get('network_is_expensive') is True for rule in content['rules']))

    def test_singbox_interface_address_schema(self):
        output = self.directory / 'rules.json'
        success, message, _ = RulesetGenerator.generate_singbox_json(
            {'network_interface_address': {'wifi': ['2001:db8::/32']}}, str(output))
        self.assertTrue(success, message)
        self.assertEqual(json.loads(output.read_text())['version'], 4)

    def test_empty_rules_are_rejected(self):
        output = self.directory / 'empty.json'
        success, _, _ = RulesetGenerator.generate_singbox_json({}, str(output))
        self.assertFalse(success)
        self.assertFalse(output.exists())

    def test_mrs_rejects_unrepresentable_rules_without_writing(self):
        output = self.directory / 'rules.yaml'
        for data in [
            {'domain': ['example.com'], 'ip_cidr': ['192.0.2.0/24']},
            {'domain_keyword': ['ads']},
            {'domain': ['example.com'], 'domain_regex': ['.*example']},
            {'source_ip_cidr': ['192.0.2.0/24']},
            {'domain': ['example.com'], 'package_name': ['com.example.app']},
        ]:
            with self.subTest(data=data):
                success, _, _ = RulesetGenerator.generate_mihomo_yaml(data, str(output))
                self.assertFalse(success)
                self.assertFalse(output.exists())

    def test_mihomo_yaml_quotes_wildcards_and_boolean_names(self):
        output = self.directory / 'rules.yaml'
        success, message, _ = RulesetGenerator.generate_mihomo_yaml(
            {'domain': ['*.example.com', 'true']}, str(output))
        self.assertTrue(success, message)
        self.assertIn('  - "*.example.com"\n', output.read_text())
        self.assertIn('  - "true"\n', output.read_text())

    def test_mihomo_suffix_preserves_apex_semantics(self):
        output = self.directory / 'rules.yaml'
        success, message, _ = RulesetGenerator.generate_mihomo_yaml(
            {'domain_suffix': ['example.com', '.example.net']}, str(output))
        self.assertTrue(success, message)
        self.assertIn('  - "+.example.com"\n', output.read_text())
        self.assertIn('  - ".example.net"\n', output.read_text())

    def test_failed_compiler_keeps_existing_output(self):
        source = self.directory / 'rules.json'
        source.write_text('{"version": 1, "rules": []}')
        output = source.with_suffix('.srs')
        output.write_bytes(b'previous rules')
        with patch('ruleset_builder.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'failed')):
            success, _ = RulesetGenerator.compile_srs(sys.executable, str(source))
        self.assertFalse(success)
        self.assertEqual(output.read_bytes(), b'previous rules')

    def test_compiler_success_without_new_output_is_failure(self):
        source = self.directory / 'rules.json'
        source.write_text('{"version": 1, "rules": []}')
        source.with_suffix('.srs').write_bytes(b'stale')
        with patch('ruleset_builder.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            success, _ = RulesetGenerator.compile_srs(sys.executable, str(source))
        self.assertFalse(success)

    def test_invalid_schema_is_rejected(self):
        for data in [{'network_is_expensive': 1}, {'network_type': ['invalid']},
                     {'network_interface_address': ['192.0.2.0/24']}, {'unknown': ['example.com']},
                     {'domain': 'example.com'}, {'domain': ['.example.com']},
                     {'domain_suffix': ['..example.com']}]:
            with self.subTest(data=data):
                success, _, _ = RulesetGenerator.generate_singbox_json(data, str(self.directory / 'invalid.json'))
                self.assertFalse(success)

    def test_mihomo_rejects_invalid_masks_and_forced_behavior(self):
        for domain in ['a*b.example.com', 'example.+.com', '*.', '..example.com']:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    RulesetGenerator.build_mihomo_yaml({'domain': [domain]})
        with self.assertRaises(ValueError):
            RulesetGenerator.build_mihomo_yaml({'domain': ['example.com']}, 'ipcidr')

    def test_regex_requires_real_singbox_validation(self):
        success, message, _ = RulesetGenerator.generate_singbox_json(
            {'domain_regex': [r'\p{L}+']}, str(self.directory / 'regex.json'))
        self.assertFalse(success)
        self.assertIn('Sing-box', message)
        self.assertFalse((self.directory / 'regex.json').exists())

    def test_output_extension_and_missing_directories(self):
        output = self.directory / 'new directory' / 'rules.JSON'
        success, messages = RulesetGenerator.export({'domain': ['EXAMPLE.COM', 'example.com']}, str(output), ['json'])
        self.assertTrue(success, messages)
        actual = output.with_suffix('.json')
        self.assertTrue(actual.exists())
        self.assertFalse(Path(str(output) + '.json').exists())
        self.assertEqual(json.loads(actual.read_text())['rules'], [{'domain': ['example.com']}])

    def test_incompatible_extra_format_does_not_write_partial_json(self):
        output = self.directory / 'rules'
        success, _ = RulesetGenerator.export({'domain_keyword': ['ads']}, str(output), ['json', 'mrs'])
        self.assertFalse(success)
        self.assertFalse(output.with_suffix('.json').exists())

    def test_mrs_does_not_overwrite_same_named_source_in_output_directory(self):
        source_dir = self.directory / 'input'
        source_dir.mkdir()
        source = source_dir / 'rules.yaml'
        source.write_text('payload:\n  - "example.com"\n')
        unrelated = self.directory / 'rules.yaml'
        unrelated.write_text('keep this file')
        with patch('ruleset_builder.subprocess.run', side_effect=subprocess.TimeoutExpired('compiler', 60)):
            success, _ = RulesetGenerator.compile_mrs(sys.executable, str(source), str(self.directory / 'rules.mrs'))
        self.assertFalse(success)
        self.assertEqual(unrelated.read_text(), 'keep this file')
        self.assertTrue(source.exists())


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / 'main.py'), *args],
                              capture_output=True, text=True)

    def test_missing_compiler_returns_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_cli('-o', os.path.join(directory, 'rules'), '-f', 'srs')
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_input_returns_failure_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.txt'
            source.write_text('not a domain\n')
            output = Path(directory) / 'rules'
            result = self.run_cli('--domain', str(source), '-o', str(output), '--validate')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.with_suffix('.json').exists())


if __name__ == '__main__':
    unittest.main()
