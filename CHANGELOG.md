# 0.2.0 (рабочая поставка, 2026-10-20)

Дополнение совместимости: Debian 11/12/13, Ubuntu LTS 20.04/22.04/24.04/26.04;
минимум Python 3.8. Добавлены Python-free `deploy/install.sh` и автоматическая
установка недостающих allowlisted APT-зависимостей. Исправлены dict union и
SQLite UPSERT для старых дистрибутивов; подписи/TLS/конфиги сохраняются.

- Добавлены read-only inventory/preflight, staged installer и отдельные этапы
  истории/browser probe. UFW не обязателен; автоматических firewall/Caddy/VPN
  изменений нет. Целевые ОС и версии Python — в COMPATIBILITY.md.
- HTTPS+trusted SHA256 acquisition, ограниченная распаковка без links/traversal,
  контроль manifest, venv без pip, backup/health/rollback и повтор без restart.
- `/v1/node` разделяет версии агента, Node и Xray. Добавлены SemVer/policy helpers.
- Источники сообщают mapping/format/storage ошибки отдельно, lag/read/write/
  last-success timestamps. FIFO и ошибочный cursor не блокируют/не оставляют fd.
- Optional read-only user StatsService totals, sustained-load episode events,
  unsupported UUID shaping API без node-wide fallback.
- Отдельный TLS GET/HEAD 204 probe; HTTPS history transport с redacted errors
  и GET-only retries. Добавлена поддержка IPv6 listener/URL.
- Новый config.example выключает историю, live и удаление rotated logs;
  существующие конфиги не переписываются автоматически. Для установки нужен
  абсолютный путь прежней БД. Legacy unmanaged unit требует отдельной миграции.

Версия ещё должна быть опубликована доверенным commit/release оператором.
Не означает прохождение всей эксплуатационной матрицы или включение access
logging на production: фактические результаты в TEST_REPORT_INSTALLATION.md.
