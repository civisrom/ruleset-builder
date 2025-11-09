import json
import argparse
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# === УТИЛИТЫ ===
def read_list_from_file(file_path):
    if not file_path or not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

def parse_multiline_text(text_widget):
    content = text_widget.get('1.0', tk.END).strip()
    if not content:
        return []
    return [line.strip() for line in content.split('\n') if line.strip()]

def generate_ruleset(data, output_path):
    rules = []

    # Основные группы
    domain_rule = {}
    ip_rule = {}
    process_rule = {}
    android_rule = {}
    network_rule = {}

    # --- Domain ---
    for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
        if data.get(key):
            domain_rule[key] = data[key]

    # --- IP ---
    for key in ['ip_cidr', 'source_ip_cidr']:
        if data.get(key):
            ip_rule[key] = data[key]

    # --- Process & Package ---
    if data.get('process_path_regex'):
        process_rule['process_path_regex'] = data['process_path_regex']
    if data.get('package_name'):
        process_rule['package_name'] = data['package_name']

    # --- Network ---
    network_fields = [
        'network_type', 'network_is_expensive', 'network_is_constrained',
        'network_interface_address', 'default_interface_address'
    ]
    for key in network_fields:
        if data.get(key):
            # Приводим булевы значения
            if key in ['network_is_expensive', 'network_is_constrained']:
                network_rule[key] = data[key].lower() == 'true'
            else:
                network_rule[key] = data[key]

    # Добавляем только непустые правила
    if domain_rule: rules.append(domain_rule)
    if ip_rule: rules.append(ip_rule)
    if process_rule: rules.append(process_rule)
    if android_rule: rules.append(android_rule)
    if network_rule: rules.append(network_rule)

    ruleset = {"version": 1, "rules": rules}

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(ruleset, f, indent=2, ensure_ascii=False)

    total = sum(len(v) if isinstance(v, list) else 1 for r in rules for v in r.values())
    return f"Ruleset сохранён: {output_path}\nДобавлено записей: {total}"

# === GUI ===
class SingBoxRulesetGUI:
    def __init__(self, master):
        self.master = master
        master.title("Sing-Box Ruleset Builder v2.0")
        master.geometry("900x700")
        master.minsize(700, 500)

        self.singbox_path = tk.StringVar()
        self.output_filename = tk.StringVar(value="kakdusheugodno.json")
        self.output_dir = tk.StringVar(value=os.getcwd())

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # === Sing-box путь ===
        singbox_frame = ttk.LabelFrame(main_frame, text="Путь к sing-box.exe", padding=5)
        singbox_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(singbox_frame, textvariable=self.singbox_path, width=60).grid(row=0, column=0, padx=5)
        ttk.Button(singbox_frame, text="Выбрать", command=self.browse_singbox).grid(row=0, column=1)

        # === Выходной файл ===
        output_frame = ttk.LabelFrame(main_frame, text="Выходной JSON", padding=5)
        output_frame.pack(fill=tk.X, pady=5)
        ttk.Label(output_frame, text="Имя:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_filename, width=30).grid(row=0, column=1, padx=5)
        ttk.Label(output_frame, text="Папка:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_dir, width=60, state='readonly').grid(row=1, column=1, padx=5)

        # === Вкладки ===
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # Вкладка: Domains
        self.domain_frame = self.create_domain_tab(notebook)
        notebook.add(self.domain_frame, text="Domains")

        # Вкладка: IPs
        self.ip_frame = self.create_ip_tab(notebook)
        notebook.add(self.ip_frame, text="IPs")

        # Вкладка: Process & App
        self.process_frame = self.create_process_tab(notebook)
        notebook.add(self.process_frame, text="Process / App")

        # Вкладка: Network
        self.network_frame = self.create_network_tab(notebook)
        notebook.add(self.network_frame, text="Network")

        # === Кнопки ===
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="Генерировать", command=self.generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить", command=self.clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Выход", command=self.master.quit).pack(side=tk.RIGHT, padx=5)

        # === Лог ===
        self.log = scrolledtext.ScrolledText(main_frame, height=6, state='disabled')
        self.log.pack(fill=tk.X, pady=5)
        self.log_msg("Готов к работе. Выберите sing-box.exe и заполните вкладки.")

    def create_domain_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.domain_widgets = {}
        fields = [
            ('domain', "Domains (точные):", "example.com"),
            ('domain_suffix', "Suffixes:", ".ru"),
            ('domain_keyword', "Keywords:", "test"),
            ('domain_regex', "Regex:", "^stun\\..+")
        ]
        for i, (key, label, placeholder) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            text = scrolledtext.ScrolledText(frame, height=4, width=50)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            self.domain_widgets[key] = text
            ttk.Button(frame, text="Файл", command=lambda k=key: self.load_file(k, 'domain')).grid(row=i, column=2, padx=2)
        frame.columnconfigure(1, weight=1)
        return frame

    def create_ip_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.ip_widgets = {}
        fields = [
            ('ip_cidr', "IP CIDR (целевые):", "10.0.0.0/24"),
            ('source_ip_cidr', "Source IP CIDR:", "192.168.1.0/24")
        ]
        for i, (key, label, placeholder) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            text = scrolledtext.ScrolledText(frame, height=4, width=50)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            self.ip_widgets[key] = text
            ttk.Button(frame, text="Файл", command=lambda k=key: self.load_file(k, 'ip')).grid(row=i, column=2, padx=2)
        frame.columnconfigure(1, weight=1)
        return frame

    def create_process_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.process_widgets = {}

        # Process Path Regex
        ttk.Label(frame, text="Process Path Regex:").grid(row=0, column=0, sticky=tk.W, pady=2)
        text = scrolledtext.ScrolledText(frame, height=3, width=50)
        text.grid(row=0, column=1, pady=2, padx=5, sticky=tk.EW)
        text.insert(tk.END, "# ^C:\\\\Program Files\\\\Chrome\\\\chrome\\.exe$")
        self.process_widgets['process_path_regex'] = text
        ttk.Button(frame, text="Файл", command=lambda: self.load_file('process_path_regex', 'process')).grid(row=0, column=2, padx=2)

        # Package Name
        ttk.Label(frame, text="Package Name (Android):").grid(row=1, column=0, sticky=tk.W, pady=2)
        text = scrolledtext.ScrolledText(frame, height=3, width=50)
        text.grid(row=1, column=1, pady=2, padx=5, sticky=tk.EW)
        text.insert(tk.END, "# com.example.app")
        self.process_widgets['package_name'] = text
        ttk.Button(frame, text="Файл", command=lambda: self.load_file('package_name', 'process')).grid(row=1, column=2, padx=2)

        frame.columnconfigure(1, weight=1)
        return frame

    def create_network_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.network_widgets = {}

        # network_type
        ttk.Label(frame, text="Network Type:").grid(row=0, column=0, sticky=tk.W, pady=2)
        combo = ttk.Combobox(frame, values=["", "wifi", "cellular", "ethernet", "other"], state="readonly", width=15)
        combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.network_widgets['network_type'] = combo

        # network_is_expensive
        ttk.Label(frame, text="Expensive Network:").grid(row=1, column=0, sticky=tk.W, pady=2)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=exp_var, value="true").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=exp_var, value="false").grid(row=1, column=1, sticky=tk.W, padx=60)
        self.network_widgets['network_is_expensive'] = exp_var

        # network_is_constrained
        ttk.Label(frame, text="Constrained (iOS):").grid(row=2, column=0, sticky=tk.W, pady=2)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=con_var, value="true").grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=con_var, value="false").grid(row=2, column=1, sticky=tk.W, padx=60)
        self.network_widgets['network_is_constrained'] = con_var

        # network_interface_address
        ttk.Label(frame, text="Interface Address:").grid(row=3, column=0, sticky=tk.W, pady=2)
        text = scrolledtext.ScrolledText(frame, height=3, width=50)
        text.grid(row=3, column=1, pady=2, padx=5, sticky=tk.EW)
        text.insert(tk.END, "# 192.168.1.100")
        self.network_widgets['network_interface_address'] = text
        ttk.Button(frame, text="Файл", command=lambda: self.load_file('network_interface_address', 'network')).grid(row=3, column=2, padx=2)

        # default_interface_address
        ttk.Label(frame, text="Default Interface IP:").grid(row=4, column=0, sticky=tk.W, pady=2)
        text = scrolledtext.ScrolledText(frame, height=3, width=50)
        text.grid(row=4, column=1, pady=2, padx=5, sticky=tk.EW)
        text.insert(tk.END, "# 8.8.8.8")
        self.network_widgets['default_interface_address'] = text
        ttk.Button(frame, text="Файл", command=lambda: self.load_file('default_interface_address', 'network')).grid(row=4, column=2, padx=2)

        frame.columnconfigure(1, weight=1)
        return frame

    def browse_singbox(self):
        path = filedialog.askopenfilename(title="Выберите sing-box.exe", filetypes=[("EXE", "*.exe")])
        if path:
            self.singbox_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_msg(f"Выбран: {path}")

    def load_file(self, key, category):
        path = filedialog.askopenfilename(title="Выберите файл")
        if not path: return
        items = read_list_from_file(path)
        if category == 'domain':
            widget = self.domain_widgets[key]
        elif category == 'ip':
            widget = self.ip_widgets[key]
        elif category == 'process':
            widget = self.process_widgets[key]
        elif category == 'network':
            widget = self.network_widgets[key]
        else:
            return
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, '\n'.join(items))
        self.log_msg(f"Загружено {len(items)} строк в {key}")

    def generate(self):
        if not self.singbox_path.get():
            messagebox.showerror("Ошибка", "Выберите sing-box.exe!")
            return

        output_path = os.path.join(self.output_dir.get(), self.output_filename.get())

        data = {}

        # Сбор данных
        for w in self.domain_widgets.values():
            key = [k for k, v in self.domain_widgets.items() if v == w][0]
            data[key] = parse_multiline_text(w)

        for w in self.ip_widgets.values():
            key = [k for k, v in self.ip_widgets.items() if v == w][0]
            data[key] = parse_multiline_text(w)

        for k, w in self.process_widgets.items():
            data[k] = parse_multiline_text(w)

        # Network
        if self.network_widgets['network_type'].get():
            data['network_type'] = self.network_widgets['network_type'].get()
        data['network_is_expensive'] = self.network_widgets['network_is_expensive'].get()
        data['network_is_constrained'] = self.network_widgets['network_is_constrained'].get()
        for key in ['network_interface_address', 'default_interface_address']:
            data[key] = parse_multiline_text(self.network_widgets[key])

        try:
            msg = generate_ruleset(data, output_path)
            self.log_msg(msg)
            messagebox.showinfo("Готово", msg.split('\n')[0])
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            self.log_msg(f"Ошибка: {e}")

    def clear_all(self):
        for widgets in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
            for w in widgets.values():
                if isinstance(w, scrolledtext.ScrolledText):
                    w.delete('1.0', tk.END)
        self.network_widgets['network_type'].set("")
        self.network_widgets['network_is_expensive'].set("false")
        self.network_widgets['network_is_constrained'].set("false")
        self.log_msg("Все поля очищены.")

    def log_msg(self, msg):
        self.log.configure(state='normal')
        self.log.insert(tk.END, msg + '\n')
        self.log.see(tk.END)
        self.log.configure(state='disabled')

# === CLI Режим ===
def run_cli():
    parser = argparse.ArgumentParser(description="Sing-Box Ruleset Builder CLI")
    parser.add_argument('--singbox-path', type=str, help='Путь к sing-box.exe')
    parser.add_argument('--output', type=str, default='kakdusheugodno.json')
    # ... (можно добавить все поля, но GUI — основное)
    args = parser.parse_args()
    print("CLI не реализован полностью. Используйте GUI.")
    print("Запустите без аргументов для GUI.")

# === ЗАПУСК ===
if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_cli()
    else:
        root = tk.Tk()
        app = SingBoxRulesetGUI(root)
        root.mainloop()
