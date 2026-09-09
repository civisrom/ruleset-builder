# Ruleset Builder

Приложение на Python/Tkinter для создания наборов правил Sing-box (`.json`, `.srs`)
и Mihomo (`.mrs`). Есть GUI, CLI, импорт списков UTF-8 и сохранение шаблонов.

## Запуск

Нужен Python 3.10 или новее. Внешних Python-зависимостей для работы нет.
Для GUI нужен Tkinter: в Debian/Ubuntu установите `python3-tk`.
CLI работает и без Tkinter.

```bash
python main.py
python main.py --help
```

Для бинарных файлов установите [Sing-box](https://sing-box.sagernet.org/installation/)
или [Mihomo](https://wiki.metacubex.one/en/start/). Укажите путь в GUI
или передайте `--singbox` / `--mihomo` в CLI. Поддерживаются имена программ из `PATH`.

## Смысл правил

Каждое заполненное поле Sing-box становится **отдельным правилом**. Поля и записи
внутри списков объединяются по **ИЛИ**: достаточно одного совпадения.
Например, заполненные `ip_cidr` и `source_ip_cidr` означают совпадение с адресом
назначения **или** источника. Процессы и сетевые условия также независимы.
Конструктор не создаёт комбинации условий по И.

Пустые поля, комментарии с `#` в начале строки и примеры в GUI не экспортируются.
Повторы удаляются. Международные домены преобразуются в IDNA ASCII, домены —
в нижний регистр, CIDR — в адрес сети. IPv4 и IPv6 поддерживаются.

| Поле / запись | Поведение |
| --- | --- |
| `domain: example.com` | Только `example.com` |
| `domain_suffix: example.com` | Сам домен и все поддомены |
| `domain_suffix: .example.com` | Только поддомены, без самого `example.com` |
| `domain_keyword` | Подстрока в домене, только Sing-box |
| `domain_regex`, `process_path_regex` | Регулярные выражения Go, только Sing-box |
| `ip_cidr` | Адрес назначения, IPv4/IPv6, с префиксом или без |
| `source_ip_cidr` | Адрес источника, только Sing-box |

Регулярные выражения проверяет **`sing-box check`**, поэтому для их экспорта
нужен Sing-box даже при выборе JSON. Одной команды `rule-set compile`
недостаточно: она может сохранить неработающее регулярное выражение.
Обычные домены, IP и структура полей проверяются всегда. Флажок GUI
«Проверять JSON через Sing-box» / параметр `--validate` дополнительно загружает
весь JSON в указанный движок. Для SRS эта проверка обязательна.

Версия JSON выбирается по используемым полям: 1 для базовых правил,
2 для `process_path_regex` (Sing-box 1.10+), 3 для сетевых флагов/типов (1.11+),
4 для адресов интерфейсов (1.13+). В поле адресов интерфейсов GUI используется
запись `wifi=192.168.0.0/16`; в JSON получается объект
`{"wifi": ["192.168.0.0/16"]}`. «Не учитывать» у сетевого флага пропускает условие,
а не создаёт проверку обратного значения.

Сетевые типы/флаги доступны лишь на платформах, указанных в
[официальной схеме Sing-box](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/).
Описание версий и компиляции: [Source Format](https://sing-box.sagernet.org/configuration/rule-set/source-format/).

## Mihomo

Один MRS содержит **либо домены (`domain`), либо IP (`ipcidr`)**.
Для смешанного списка создайте два набора. `classical` в MRS не поддерживается.
Ключевые слова, regex, исходные IP, процессы и сетевые условия не переносятся в MRS:
приложение сообщает об ошибке, чтобы не потерять условия и не изменить их смысл.

Во вкладке Mihomo можно вводить маски: `.example.com` — только поддомены,
`+.example.com` — домен вместе с поддоменами, `*.example.com` — ровно одна метка
перед доменом. При переносе из поля `domain_suffix` вариант без начальной точки
преобразуется в `+.example.com`, вариант с точкой сохраняется.
Все строки YAML заключаются в кавычки, включая маски `*` и имена вроде `true`.
Предпросмотр и экспорт используют один генератор YAML.

При подключении MRS в `rule-providers` укажите соответствующий `behavior` и
`format: mrs`. Официальная документация:
[rule-providers](https://wiki.metacubex.one/en/config/rule-providers/),
[содержимое списков](https://wiki.metacubex.one/en/config/rule-providers/content/).

## CLI

```bash
# JSON из списка точных доменов
python main.py --domain domains.txt -o output/domains -f json

# SRS с проверкой правил движком
python main.py --domain-suffix suffixes.txt -o output/domains -f srs --singbox /path/to/sing-box

# Два отдельных MRS для доменов и адресов
python main.py --domain-suffix suffixes.txt -o output/domains -f mrs --mihomo /path/to/mihomo
python main.py --ip-cidr networks.txt -o output/networks -f mrs --mihomo /path/to/mihomo
```

Списки читаются как UTF-8, в том числе с BOM. Отсутствующий или повреждённый файл
вызывает ошибку. CLI возвращает ненулевой код при любом сбое. Выходные папки
создаются автоматически. Рядом с SRS сохраняется исходный JSON, рядом с MRS —
YAML. При ошибке компиляции прежний бинарный ruleset сохраняется; сообщения
перечисляют уже созданные промежуточные файлы.

## Проверки и сборка

```bash
python -m unittest discover -s tests

# Полный прогон Linux: настоящие движки и GUI на виртуальном экране
SINGBOX_BINARY=/path/to/sing-box MIHOMO_BINARY=/path/to/mihomo xvfb-run -a python -m unittest discover -s tests -v

python -m pip install pyinstaller Pillow
pyinstaller --noconfirm ruleset_builder.spec
```

Без движков/дисплея соответствующие интеграционные и GUI-тесты пропускаются.
CI запускает полный прогон с Sing-box 1.14.0 и Mihomo 1.19.30, затем собирает
приложение для Windows, Linux и macOS. Тесты проверяют совпадения JSON/SRS,
сохранность полей SRS, маршрутизацию через YAML/MRS на локальном HTTP-прокси,
границы IPv4/IPv6 сетей, ошибки компиляции и сценарии GUI.

Вкладка GeoIP/GeoSite требует отдельную утилиту
[generate-geoip-geosite](https://github.com/Dunamis4tw/generate-geoip-geosite).
Экспорт в её входные списки ограничен доменами, суффиксами и IP; регулярные
выражения включения не преобразуются в исключения.
