# Управление сервером и защита ресурсов

Модуль предназначен для Linux хоста Remnawave Node. По умолчанию `management.enabled=false`: характеристики сервера и защита истории работают, команды ОС не выполняются. Windows возвращает доступные характеристики, неизвестные Linux metrics — null; управляющие действия отвечают 501.

## API и запуск

Все endpoints используют один токен конкретной ноды из auth.token (fallback для старых установок — REMNAWATCH_API_TOKEN). Основной сервер выдаёт отдельный credential каждой ноде; процедура описана в [NODE_ENROLLMENT.md](NODE_ENROLLMENT.md). Это административный секрет: после включения управления его владелец может перезагрузить сервер. Доступ только backend панели/оператору, через localhost или TLS reverse proxy с RBAC. Не отдавайте токен браузеру конечного пользователя. JSON-конфиг, Python код, Compose файлы/.env и hooks должны контролироваться оператором и не быть доступны на запись непривилегированным пользователям.

- `GET /v1/server` — hostname, OS release (текущее ядро ОС), architecture, CPU model/count/usage, RAM/swap, uptime/load average, disk capacity/free space/free inodes, NIC TX/RX counters/rates; protection alerts и capabilities управления.
- `GET /v1/server/jobs?limit=100&offset=0` — журнал задач (до 500 записей на страницу).
- `GET /v1/server/jobs/{id}` — состояние конкретной задачи.
- `POST /v1/server/actions` — JSON action/params/dry_run/request_id. По умолчанию dry_run=true: только план, никаких системных команд.

Пример проверки лимитов:

```json
{"action":"traffic_limits","params":{"interface":"eth0","tx_mbps":100,"rx_mbps":100},"dry_run":true}
```

Для выполнения того же действия передайте `dry_run=false` и уникальный `request_id`, например `traffic_20261015_01`, при включённом management.enabled. Возврат 202 с queued job; проверяйте jobs/{id}. Повтор того же request_id с теми же параметрами возвращает прежнюю задачу, а с другими — 409. Один управляющий процесс/задача за раз. Прерванные при restart queued/running задачи помечаются interrupted и никогда не повторяются автоматически. Idempotency хранится вместе с аудитом 30 дней (очистка при новом submit), максимум 10000 задач; после удаления старого ID он может быть использован снова.

После успешного планирования reboot новые управляющие операции блокируются 120 секунд, чтобы обновление не началось перед выключением хоста. Повтор прежнего request_id по-прежнему возвращает уже созданный job.

Ошибки: 400 — входные данные; 401 — авторизация; 403 — управление выключено; 404 — неизвестный путь/job; 409 — конфликт ID, выполняющаяся задача или давление ресурсов; 501 — платформа/действие не поддерживается конфигурацией; 503 — база недоступна. Ошибки исполнения появляются в job.status=failed. Текст child stdout/stderr и секреты не возвращаются в аудит. `completed_steps` показывает частично применённые шаги.

## Действия

| action | Поведение |
|---|---|
| `server_reboot` | ОС `shutdown -r +1`, запланированная через минуту перезагрузка всего хоста |
| `xray_restart` | `systemctl restart` настроенного xray_service; для контейнера — перезапуск всей ноды |
| `xray_update` | В Remnawave Docker — pull/up сервиса ноды вместе с включённым Xray; standalone — root-owned updater hook |
| `node_restart` | `docker compose restart` только настроенного сервиса |
| `node_update` | `docker compose pull SERVICE`, затем `up -d --no-deps SERVICE`, без compose down и без затрагивания соседних сервисов |
| `os_kernel_update` | Debian/Ubuntu: apt-get update и install --only-upgrade настроенного kernel metapackage; перезагрузка отдельно |
| `traffic_limits` | TX TBF shaping и RX ingress policing на разрешённом интерфейсе, Mbit/s |
| `traffic_clear` | Удаление своих TX/RX rules после проверки сохранённого ownership и текущего tc state |
| `oom_protection` | Runtime vm.panic_on_oom=0; optional runtime systemd MemoryHigh/MemoryMax для разрешённого service |

Перезапуск Xray/ноды/ОС разрывает активные подключения. Job succeeded для reboot означает только успешное планирование; не доказательство завершившейся перезагрузки. Для update/restart succeeded означает успешное завершение команд, не проверку доступности из панели или готовности Xray. Проверяйте состояние ноды в панели и её health после обновления. Автоматического rollback обновления нет; версия определяется настроенным Compose image tag. Закреплённый tag не станет новой версией сам. Перед обновлением нод проверьте совместимость с версией панели.

Для standalone Xray задайте `xray_service: "xray.service"`, а при обновлении `xray_update_hook: "/usr/local/libexec/remnawatch-update-xray"`. Hook должен быть обычным executable файлом root:root, без group/other write и без symlink. Его установка и реализация — задача оператора: verified download/package update, backup, config validation, restart и health-check. Универсального безопасного updater для любой установки Xray здесь нет; без hook действие недоступно. Произвольные команды/пути обновления через HTTP не принимаются.

`os_kernel_package` допускает только linux-generic (Ubuntu), linux-image-amd64 или linux-image-arm64 (Debian). Выбирайте **уже установленный** пакет для своей системы; --only-upgrade не устанавливает отсутствующий пакет. Обновление использует настроенные доверенные APT repositories и требует network/disk space; новый Linux kernel вступает в силу только после reboot. Не путайте Xray core с ядром ОС: отдельная «перезагрузка Linux ядра» — перезагрузка ОС.

## Ограничения скорости

`management.interfaces` — явный allowlist, например `["eth0"]`. traffic_limits требует обе целые скорости tx_mbps/rx_mbps от 1 до 100000. Это лимит **всего интерфейса**, включая SSH, панель и другие процессы, а не отдельного пользователя. RX policing отбрасывает избыток входящих пакетов: это не lossless download shaping и не управление скоростью отправителя.

Сервис отказывается менять existing custom root qdisc/ingress/clsact. Поддерживается default root с handle 0: (noqueue/fq_codel/pfifo_fast/fq); multiqueue и сложные tc конфигурации требуют отдельного сетевого администрирования. Своему TX назначается handle 7a10:, ingress ffff:, matchall pref 49152. Частичное применение откатывает созданные им qdiscs; если rollback не удался, job это сообщает. Для изменения скоростей сначала выполните traffic_clear, потом traffic_limits. Clear не восстанавливает предыдущее custom дерево (оно не изменяется) и отказывается удалять явно изменённую извне конфигурацию. Не изменяйте управляемые правила параллельно другими программами.

TC limits — runtime, после reboot исчезают. Их сохранённый ownership marker не означает, что правила применены: при следующей операции проверяется реальный tc state. Автоприменения после reboot нет. Это позволяет оператору восстановить доступ после ошибочного низкого лимита. Для постоянных лимитов настройте deployment отдельно после проверки сети.

## Защита ОЗУ

Встроенный guard раз в 10 секунд смотрит MemAvailable: при RAM used >=92% приостанавливает запись/чтение новых доменных событий, при <=85% возобновляет. Пороговые значения настраиваются. Cursor сохраняется: события не пропускаются намеренно; backlog будет дочитан, если лог ещё доступен. При долгой паузе/rотации возможна потеря. Неизвестный MemAvailable не выдаётся за нормальное состояние. Guard **никогда не перезагружает сервер** и не убивает Xray.

oom_protection без params устанавливает `vm.panic_on_oom=0` на текущий boot. Optional params:

```json
{"action":"oom_protection","params":{"service":"remnawatch.service","memory_high_mb":256,"memory_max_mb":384},"dry_run":true}
```

service должен быть в memory_services. MemoryHigh способствует reclaim/throttling; MemoryMax — жёсткий предел и может вызвать уничтожение процесса. Для Docker такие лимиты относятся к конкретному systemd service, не автоматически ко всем контейнерам. Не задавайте memory_services=docker.service ради ограничения одной ноды. Swap, OOM killer, watchdog и overcommit не выключаются/не меняются. Нельзя гарантировать отсутствие reboot: hardware, kernel faults, watchdog или иной OOM policy могут его вызвать.

`deploy/remnawatch.service` даёт сервису MemoryHigh=256M, MemoryMax=384M, OOMPolicy=stop и restart-on-failure без перезагрузки хоста. При включённом управлении необходим host root; для monitoring-only запуска используйте непривилегированного пользователя с доступом к log/database. `deploy/90-remnawatch-oom.conf` — optional persistent sysctl пример для установки оператором в /etc/sysctl.d. Сам сервис не устанавливает эти файлы и не меняет OS policy при запуске.

## Защита диска и сообщения

`GET /v1/server` → protection.alerts сообщает memory_pressure, log_disk_pressure, history_disk_pressure, storage/cleanup failures. Backend панели должен опрашивать endpoint и показывать уведомление оператору. Отправки email/webhooks нет. Disk alert обновляется через <=10 секунд при работающем guard; история имеет quality.collection_paused/pause_reasons/emergency_retention.

По умолчанию порог — >=90% used либо <256 MiB свободно. На явно заданных `protection.log_directories` удаляются по возрасту только `access.log.NUMBER[.gz]`, `error.log.NUMBER[.gz]` и варианты с YYYY-MM-DD, старше min_rotated_age_seconds (default 1 час). Максимум 100 файлов за проход, scan максимум 5000 entries на каталог. Файлы активных collectors, symlinks, hardlinks и произвольные файлы не удаляются. Каталоги не сканируются рекурсивно. `delete_rotated_logs=false` отключает удаление внешних логов. Не разрешайте непривилегированным пользователям изменять эти каталоги во время удаления. Logrotate с compress обязателен для активных Xray logs: guard не truncate/unlink активный лог.

При нехватке места для SQLite по умолчанию запускается ранняя очистка: до 2000 старых строк каждой таблицы events/aggregates/network за проход, сохраняя последний час подробных событий и сутки агрегатов (настраивается). Dedup сохраняется, чтобы replay не вернул удалённые события. Если места всё ещё мало — сбор ставится на паузу до восстановления свободного пространства. История становится короче настроенного retention, о чём свидетельствует quality.emergency_retention. Full-disk ошибки сборщика не вызывают reboot.

Новые базы создаются с incremental auto-vacuum: удалённые страницы могут возвращаться файловой системе; WAL checkpoint сокращает WAL. У старых баз без auto-vacuum ранняя очистка прежде всего освобождает страницы для повторного использования внутри файла, но не гарантирует уменьшение размера файла. Для миграции при достаточном свободном месте, остановленном сервисе и сделанном backup выполните через SQLite `PRAGMA auto_vacuum=INCREMENTAL; VACUUM;`. Автоматический full VACUUM на заполненном диске не запускается. Dedup/state/job audit, другие приложения и активные файлы могут занимать место; guard сообщает об оставшейся проблеме, не удаляет всё подряд.

## Проверки и границы

Unit/integration tests используют synthetic /proc и временные log/SQLite files, fake runners для всех системных операций. Проверяются HTTP authorization, dry-run, включение управления, request idempotency, interrupted jobs, команды обновления, TX/RX validation/rollback/foreign qdisc, memory hysteresis, bounded emergency deletion, full disk errors и сохранение cursor. Никаких reboot, apt/docker update, sysctl или tc на машине разработки не выполнялось. Реальная privileged Linux интеграция требует отдельной ноды/VM и проверки выбранного deployment; обычный unit pass не доказывает доступность всех host tools.

Источники для реализации: [Remnawave Node installation](https://docs.rw/install/remnawave-node/), [Remnawave upgrading](https://docs.rw/install/upgrading/), [Linux TBF](https://man7.org/linux/man-pages/man8/tc-tbf.8.html), [Linux ingress policing](https://man7.org/linux/man-pages/man8/tc-police.8.html), [Linux vm.panic_on_oom](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html), [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).

Дополнение диагностики: storage alerts version=2 разделяют missing/permissions/read-only/cleanup/I/O, учитывают required/disabled и имеют legacy_alerts. `/v1/server` теперь содержит per-NIC sample/error/reset/origin metadata, а `/v1/network/interfaces` — inventory без суммирования bridge/member. Host telemetry и read-only API работают при недоступной истории; без durable job audit mutations выключаются. Подробности capabilities и optional socket monitoring: [LIVE_DIAGNOSTICS.md](LIVE_DIAGNOSTICS.md).
