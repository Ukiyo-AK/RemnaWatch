# Карта проекта

| Файл | Назначение |
|---|---|
| `remnawatch/events.py` | Event, домены/IDNA/IP, access.log parser, UserMap, trusted metadata contract |
| `remnawatch/store.py` | SQLite WAL, retention, dedup, атомарные rollups, история и аналитика |
| `remnawatch/collector.py` | Bounded polling, cursor, rotation, optional Linux interface load |
| `remnawatch/api.py` | Общая Bearer-авторизация ноды, domain/server routes, проверка подключения, фильтры и ошибки |
| `remnawatch/auth.py` | Генератор per-node credentials для основного сервера, config/env resolution и проверка Bearer |
| `tests/test_auth.py` | Генерация/ротация, изоляция нод, config precedence и HTTP pairing/auth |
| `NODE_ENROLLMENT.md` | Ручное добавление ноды, backend Python/Node.js generation, connection check и отзыв |
| `remnawatch/__main__.py` | CLI, конфигурация, lifecycle коллектора/API/очистки |
| `remnawatch/management.py` | Linux plans/actions, async job audit, idempotency, Docker/systemd/tc/sysctl |
| `remnawatch/health.py` | Host telemetry, memory pressure guard, disk alerts и ранняя очистка |
| `remnawatch/network.py` | Раздельные NIC rates с ошибками/reset metadata, интерфейсы/bridge/bond inventory |
| `remnawatch/diagnostics.py` | Capabilities и безопасный in-memory source health, lag/gaps/permissions |
| `remnawatch/live.py` | Opt-in inet_diag socket snapshots, stable cookie IDs, frozen pagination/change cursors |
| `tests/test_diagnostics_live.py` | P0/P1 fixtures, real Linux TCP/UDP и fallback startup/API tests |
| `tools/benchmark_live.py` | Воспроизводимый synthetic 50k microbenchmark, не VPN benchmark |
| `LIVE_DIAGNOSTICS.md`, `TEST_REPORT_LIVE.md` | Контракт, compatibility matrix, migration/rollback и честные результаты проверок |
| `tests/test_server.py` | Synthetic telemetry, API auth, management fake runners, disk/memory/rollback tests |
| `deploy/` | Примеры systemd service и persistent OOM sysctl для оператора |
| `SERVER_MANAGEMENT.md` | Управление, характеристики сервера и защита ресурсов |
| `config.example.json` | Пример node/user mapping и политики хранения |
| `tests/test_domains.py` | Парсинг, attribution, filtering, history, auth, retention, volume/rotation |
| `API.md`, `openapi.yaml` | Контракт REST |
| `ARCHITECTURE.md` | Устройство модуля и исследование Xray |
| `INTEGRATION_FOR_PANEL_AGENT.md` | Подключение агента панели |
| `LIMITATIONS.md` | Границы полноты и достоверности |

Запуск: `python -m remnawatch --config config.json`. Проверка: `python -m unittest discover -s tests -v`. Runtime использует только стандартную библиотеку Python.
## Добавления 0.2.0

| Файл | Назначение |
|---|---|
| `remnawatch/version.py`, `runtime.py` | Версия агента, безопасная read-only идентификация реальных Node/Xray |
| `remnawatch/preflight.py`, `install.py` | Матрица, logger/mount discovery, независимые этапы, venv, health/rollback |
| `remnawatch/dependencies.py`, `deploy/install.sh` | Python-free bootstrap, установка только недостающих APT dependencies, opt-out и безопасные конфликты |
| `tests/test_dependencies.py` | Отсутствующие пакеты, идемпотентность, конфликты resolver, права, ошибки и shell preflight |
| `remnawatch/update.py`, `releases.py` | HTTPS/digest/path validation, manifest, SemVer и panel policy helpers |
| `remnawatch/tls.py`, `probe.py` | TLS вне accept loop; отдельный browser RTT endpoint |
| `remnawatch/user_metrics.py` | Opt-in user totals, непрерывная нагрузка, честный unsupported UUID shaping |
| `remnawatch/transport.py` | Redacted central history HTTP/DNS/TLS/connect/timeout диагностика |
| `tests/test_deployment.py` | Матрица fixtures, provenance, SemVer, supply chain, rollback, TLS IPv4/IPv6, gaps/load |
| `INSTALLATION.md`, `COMPATIBILITY.md`, `TEST_REPORT_INSTALLATION.md` | Установка, целевая матрица и реально выполненная проверка |
| `deploy/probe.example.json`, `deploy/xray-log-plan.example.json` | Probe config и review-only план логирования без исполнения |
