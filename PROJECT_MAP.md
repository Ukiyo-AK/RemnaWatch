# Карта проекта

| Файл | Назначение |
|---|---|
| `remnawatch/events.py` | Event, домены/IDNA/IP, access.log parser, UserMap, trusted metadata contract |
| `remnawatch/store.py` | SQLite WAL, retention, dedup, атомарные rollups, история и аналитика |
| `remnawatch/collector.py` | Bounded polling, cursor, rotation, optional Linux interface load |
| `remnawatch/api.py` | Общая Bearer-авторизация, шесть REST routes, фильтры и ошибки |
| `remnawatch/__main__.py` | CLI, конфигурация, lifecycle коллектора/API/очистки |
| `config.example.json` | Пример node/user mapping и политики хранения |
| `tests/test_domains.py` | Парсинг, attribution, filtering, history, auth, retention, volume/rotation |
| `API.md`, `openapi.yaml` | Контракт REST |
| `ARCHITECTURE.md` | Устройство модуля и исследование Xray |
| `INTEGRATION_FOR_PANEL_AGENT.md` | Подключение агента панели |
| `LIMITATIONS.md` | Границы полноты и достоверности |

Запуск: `python -m remnawatch --config config.json`. Проверка: `python -m unittest discover -s tests -v`. Runtime использует только стандартную библиотеку Python.
