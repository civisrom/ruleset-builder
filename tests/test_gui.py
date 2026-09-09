import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ruleset_builder import FileProcessor, RulesetBuilderGUI, RulesetGenerator, tk


@unittest.skipIf(tk is None or (sys.platform.startswith('linux') and not os.environ.get('DISPLAY')),
                 'GUI требует Tkinter и дисплей (xvfb-run)')
class GUITests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = RulesetBuilderGUI(self.root)
        self.addCleanup(self.close)
        self.errors = []
        self.root.report_callback_exception = lambda *error: self.errors.append(error)
        self.dialogs = {}
        for name in ('showinfo', 'showerror', 'showwarning', 'askyesno'):
            self.dialogs[name] = self.enterContext(patch('ruleset_builder.messagebox.' + name, return_value=True))
        self.root.update()

    def close(self):
        self.pump()
        if not self.app._closed:
            self.app.on_close()
        self.assertFalse(self.errors, self.errors)

    def pump(self):
        deadline = time.monotonic() + 5
        while self.app._busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.root.update()
        self.assertFalse(self.app._busy, 'Операция GUI не завершилась')

    def test_initial_examples_do_not_become_rules(self):
        self.assertEqual(FileProcessor.normalize_data(self.app.collect_data()), {})
        for widget in self.app.domain_widgets.values():
            self.assertEqual(widget['count'].cget('text'), 'Строк: 0')

    def test_counters_follow_insert_delete_and_file_load(self):
        widget = self.app.domain_widgets['domain']
        widget['text'].delete('1.0', tk.END)
        widget['text'].insert('1.0', '# comment\nexample.com\nexample.net\n')
        self.root.update()
        self.assertEqual(widget['count'].cget('text'), 'Строк: 2')
        self.app.clear_widget(widget['text'])
        self.root.update()
        self.assertEqual(widget['count'].cget('text'), 'Строк: 0')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.txt'
            source.write_text('example.org\n', encoding='utf-8-sig')
            self.app.load_into_widget(str(source), widget['text'])
            self.pump()
        self.assertEqual(widget['count'].cget('text'), 'Строк: 1')

    def test_template_round_trip_restores_process_and_network_fields(self):
        data = {'domain': ['example.com'], 'process_path_regex': [r'^/usr/bin/firefox$'],
                'package_name': ['org.example.app'], 'network_type': ['wifi', 'cellular'],
                'network_is_expensive': True, 'network_interface_address': {'wifi': ['192.0.2.0/24']},
                'default_interface_address': ['2001:db8::/32']}
        self.app.apply_template(data)
        self.root.update()
        self.assertEqual(self.dialogs['askyesno'].call_count, 1)
        self.assertEqual(FileProcessor.normalize_data(self.app.collect_data()), data)

    def test_invalid_or_cancelled_template_preserves_edits(self):
        self.app.domain_widgets['domain']['text'].insert(tk.END, '\nkeep.test')
        before = self.app.collect_data()
        self.app.apply_template({'domain': 'invalid type'})
        self.assertEqual(self.app.collect_data(), before)
        self.dialogs['askyesno'].return_value = False
        self.app.apply_template({'domain': ['replacement.test']})
        self.assertEqual(self.app.collect_data(), before)

    def test_preview_equals_full_export_structure(self):
        self.app.apply_template({'domain': [f'host{i}.test' for i in range(9)],
                                 'package_name': ['org.example.app'], 'network_is_constrained': True})
        self.app.update_preview()
        preview = json.loads(self.app.preview_text.get('1.0', tk.END))
        self.assertEqual(preview, RulesetGenerator.build_singbox_ruleset(self.app.collect_data())[0])

    def test_selected_output_format_is_used_off_main_thread(self):
        main_thread = threading.get_ident()
        threads = []
        def export(*args):
            threads.append(threading.get_ident())
            return True, ['Создан файл']
        with patch.object(RulesetGenerator, 'export', side_effect=export) as mock:
            self.app.output_format.set('srs')
            self.app.generate_ruleset()
            self.pump()
            self.assertEqual(mock.call_args.args[2], {'srs'})
        self.assertNotEqual(threads, [main_thread])
        self.dialogs['showinfo'].assert_called_once()

    def test_failed_export_never_shows_success(self):
        with patch.object(RulesetGenerator, 'export', return_value=(False, ['Ошибка компиляции'])):
            self.app.generate_ruleset()
            self.pump()
        self.dialogs['showinfo'].assert_not_called()
        self.dialogs['showerror'].assert_called_once()
        self.assertEqual(self.app.status_text.get(), 'Ошибка экспорта')

    def test_worker_exception_restores_controls(self):
        with patch.object(FileProcessor, 'read_large_file', side_effect=OSError('Нет доступа')):
            self.app.load_into_widget('input.txt', self.app.domain_widgets['domain']['text'])
            self.pump()
        self.dialogs['showerror'].assert_called_once()
        self.assertEqual(self.app.domain_widgets['domain']['text'].cget('state'), 'normal')

    def test_mihomo_mixed_data_cannot_be_previewed_as_mrs(self):
        self.app.mihomo_domain_widget.insert(tk.END, '\nexample.com')
        self.app.mihomo_ip_widget.insert(tk.END, '\n192.0.2.0/24')
        self.app.preview_mihomo_yaml()
        self.dialogs['showerror'].assert_called_once()

    def test_clear_all_clears_mihomo_and_counters(self):
        self.app.mihomo_domain_widget.insert(tk.END, '\nexample.com')
        self.app.clear_all(confirm=False)
        self.root.update()
        self.assertEqual(self.app.collect_mihomo_data(), {'domain': [], 'ip_cidr': []})
        self.assertEqual(FileProcessor.normalize_data(self.app.collect_data()), {})

    def test_status_and_scrollbars_remain_accessible_at_minimum_size(self):
        self.root.geometry('900x650')
        self.root.update()
        self.assertTrue(self.app.progress.winfo_ismapped())
        bottom = self.app.progress.winfo_rooty() - self.root.winfo_rooty() + self.app.progress.winfo_height()
        self.assertLessEqual(bottom, 650)
        for widget in self.app.domain_widgets.values():
            counter = widget['count']
            self.assertTrue(counter.winfo_ismapped())
            field = counter.master.master
            self.assertLessEqual(counter.winfo_rootx() + counter.winfo_width(),
                                 field.winfo_rootx() + field.winfo_width())
        canvas = next(child for child in self.app.domain_frame.winfo_children() if isinstance(child, tk.Canvas))
        self.assertLess(canvas.yview()[1], 1.0)
        canvas.yview_moveto(1)
        self.root.update()
        self.assertAlmostEqual(canvas.yview()[1], 1.0)


if __name__ == '__main__':
    unittest.main()
