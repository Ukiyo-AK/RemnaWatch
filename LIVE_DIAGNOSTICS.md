# Диагностика и live-снимки RemnaWatch

Изменения сохраняют access.log history как события принятия запросов. Они не превращаются в живые сессии, объёмы или посещения страниц. Панель Remnawave 2.7.4 не обновляется и не вызывается этим сборщиком; Xray конфигурация, маршруты, sniffing и forwarding не изменяются.

## Состояние источников

Все новые endpoints используют существующий Bearer node token, no-store и backend RBAC панели. Source status не содержит token, raw exception, log line, содержимое config, домены или IP соединений.

`GET /v1/capabilities` сообщает отдельно supported (адаптер существует для платформы), configured (оператор включил/настроил источник), healthy (результат наблюдения; null до замера или при выключенном источнике). Ошибка source не является доказательством отсутствия соединений.

Имена capabilities:

| Capability | Значение текущего адаптера |
|---|---|
| host_network_rates | Linux /proc counters, раздельные RX/TX по NIC |
| connection_events | accepted events существующего access.log |
| live_connections | Linux transport_socket snapshots; это не список логических Xray streams |
| per_connection_bytes | unsupported |
| per_connection_rates | unsupported |
| connection_duration | unsupported |
| application_streams | unsupported |

`GET /v1/diagnostics/sources` возвращает sources, sampled_at и storage. Для access logs доступны configured/required/healthy, timestamp последней попытки, ошибки, lag_bytes, observed_gaps/last_gap_reason. Lag в секундах и точное количество потерянных событий остаются null, если источник их не даёт. Для socket dump — failed_polls, lost_intervals, lag_seconds, лимиты/ограничения и error_code. После остановки polling просроченный sample даёт healthy=false, stale_sample. Не вычислять полноту по нулю ошибок.

Если историческая SQLite недоступна уже при старте, агент запускает read-only диагностику хоста и live-сборщик с аварийной in-memory служебной базой, без записи новой истории и без привилегированных mutations, которым нужен durable audit. Доменная quality.history_storage_available=false и diagnostics/history_storage указывают проблему. Для восстановления persistent storage исправьте mount/permissions/space и перезапустите агент. Невалидный user mapping атомарно отключает обработку событий с invalid_user_mapping, а неправильный optional live config сообщает invalid_configuration; host telemetry/API продолжают работать. Невалидная авторизация по-прежнему останавливает старт.

## Storage diagnostics v2

`GET /v1/server` → protection.diagnostics_version=2, alerts содержит:

| code | Причина |
|---|---|
| log_directory_missing | Нет реального каталога/mount |
| log_directory_permission_denied | Нет прав проверки источника |
| log_directory_read_only | Операция получила EROFS |
| log_cleanup_failed | Проверка диска прошла, выбранный rotated log удалить не удалось |
| log_storage_io_error | Прочая ошибка FS |

У каждого такого alert: component, code, severity, path, error_type, errno (из известных OS errno или null), required, impact, remediation, legacy_code. Raw exception text не выдаётся. Каталог не создаётся автоматически: пустой каталог не восстанавливает Xray logging.

required берётся из access_logs[].required только при включённом domains.enabled и access_logs[].enabled. Для обязательного источника ошибка critical, для включённого optional — warning, для выключенного — info. Ошибка внешней log cleanup не останавливает CPU/RAM/NIC и управление. Реальная нехватка места в каталоге SQLite может отдельно приостановить ingestion, как прежде.

Для миграции старых клиентов добавлен protection.legacy_alerts, где соответствующие коды представлены как log_storage_unavailable. Новый backend должен ориентироваться на diagnostics_version=2 и alerts, старому доступен legacy_code. Глобальный critical нельзя вычислять из ошибки выключенного optional source.

## Интерфейсы и скорость сети

`GET /v1/server` сохраняет network[].rx_bytes/tx_bytes и раздельные rates; добавлены:

- available — доступны ли counters данного интерфейса;
- sampled_at — Unix UTC seconds с fractional precision;
- sample_interval_seconds — фактическая monotonic дельта;
- counter_reset — уменьшение счётчиков или изменение ifindex;
- error_code — first_sample, counter_reset, interface_disappeared, counter_unavailable, permission_denied, source_missing, source_read_error, invalid_interval либо null;
- origin — host/container/unknown, задаётся оператором через network_origin. Автоматического setns нет.

Первый/неполный/неудачный замер и reset дают rates=null. Ноль означает корректную дельту 0 за положительный интервал. После ошибки чтения baseline сбрасывается, чтобы не склеить разные эпохи счётчиков. Исчезнувший NIC показывается unavailable; новое появление начинает новый baseline.

`GET /v1/network/interfaces` — read-only inventory: interface, ifindex, state, type (Linux ARPHRD), kind (bridge/bond при подтверждённой структуре sysfs), master, members, loopback, default_route, capacity_bits_per_second/capacity_origin. Последнее — только driver-reported link speed, если доступно; не гарантированная скорость интернета/тарифа и не значение из текущего traffic rate. Неизвестные характеристики null. Default route читается из видимых /proc main route tables, без обещания определения policy routing. NIC, bridge/bond и их members не суммируются: aggregation=none. Sysfs inventory может оставаться доступен при ошибке counters.

## Исследование Xray и совместимость

Проверены публичные интерфейсы точных Xray tags:

- [26.3.27 StatsService](https://github.com/XTLS/Xray-core/blob/v26.3.27/app/stats/command/command.proto): user counters/online IPs и sys stats, без подтверждённой таблицы per-stream lifecycle/bytes/start time.
- [26.7.28 StatsService](https://github.com/XTLS/Xray-core/blob/v26.7.28/app/stats/command/command.proto): дополнительно GetUsersStats, но это traffic целого пользователя, не логического потока.
- [26.3.27 RoutingService registration](https://github.com/XTLS/Xray-core/blob/v26.3.27/app/router/command/command.go) и [26.7.28 registration](https://github.com/XTLS/Xray-core/blob/v26.7.28/app/router/command/command.go): штатный streaming routing stats создаётся без канала. Его нельзя объявлять готовым lifecycle exporter.
- [Node 2.7.0 manifest](https://github.com/remnawave/node/blob/2.7.0/package.json) и [Node 3.4.2 manifest](https://github.com/remnawave/node/blob/3.4.2/package.json) проверены отдельно; один номер Node не доказывает наличие необходимого exporter или состав конкретного container image.

Вывод ограничен этими интерфейсами: доказуемого готового Xray exporter логических потоков с точной user attribution для данных сборок не найдено. Не включаются debug, sniffing, FakeDNS, MITM или payload capture. Сторонний/кастомный exporter может быть отдельным будущим адаптером после проверки фактической схемы, измерений и trust boundary.

| Сочетание | Проверка | Статус |
|---|---|---|
| Panel 2.7.4 / ALTLINK | Сборщик не вызывает/не изменяет panel API, старые endpoints сохранены | Совместимость контракта, без полного end-to-end теста ALTLINK |
| Node 2.7.0 / Xray 26.3.27 | Публичный код интерфейсов | Static review; отдельный runtime image не запускался |
| Node 3.4.2 / Xray 26.7.28 | Публичный код; на предоставленной ноде подтверждён Xray 26.7.28 и remnanode image latest | Linux kernel/API tests выполнены; Node version не выведена из mutable image tag |
| Linux 6.8.0-146 / Ubuntu 24.04 / Python 3.12 | Реальный NETLINK_SOCK_DIAG TCP/UDP; обычный UID 65534 | Runtime проверено без CAP_NET_ADMIN/root для чтения |
| Windows | Synthetic fixtures, byte parser, API | Kernel adapter unsupported; native Linux integration пропускается |

Не считать эту таблицу сертификатом всех промежуточных образов и plugin/exporter конфигураций.

## Opt-in Linux socket adapter

Пример секции config.json (обычный node token уже содержит UUID агента):

```json
"network_origin": "host",
"live_connections": {
  "enabled": true,
  "adapter": "linux_inet_diag",
  "protocols": ["tcp", "udp"],
  "fields": ["local_ip", "local_port", "peer_ip", "peer_port"],
  "poll_seconds": 5,
  "max_connections": 10000,
  "max_changes": 10000,
  "snapshot_ttl_seconds": 30,
  "tombstone_seconds": 60
}
```

По умолчанию enabled=false. Для legacy auth явно задайте live_connections.node_id UUID. fields — whitelist разрешённых адресных полей; без него эти поля null. Другие поля вне whitelist не принимаются как расширение сбора. Application payload, HTTP headers/paths/cookies и DNS cache не читаются.

Источник — [Linux NETLINK_SOCK_DIAG inet_diag_req_v2](https://man7.org/linux/man-pages/man7/sock_diag.7.html), parsed fixed inet_diag_msg header по [официальному UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/inet_diag.h). Читаются IPv4/IPv6 TCP и UDP в текущем namespace, TCP LISTEN исключён. Это **все видимые сокеты namespace**, не только Xray. Socket ID строится из opaque kernel socket cookie + protocol/family, scoped к agent_boot_id. Номер inode/IP/NAT/time не используется как доказательство пользователя.

Адаптер не запрашивает/не интерпретирует TCP_INFO byte counters, не экспортирует retransmit/overhead/L3/application byte measurements. rx_bytes/tx_bytes/rates всегда null и capabilities unsupported. byte_direction=node_socket описывает будущую интерпретацию полей относительно ноды; пользовательские счётчики к ним не относятся. client/destination direction неизвестен — поля null; для наблюдаемых адресов есть отдельные local/peer поля.

user_id/inbound/domain/domain_source/transport_stream_id всегда null: никакой socket-to-Xray correlation не доказано. TCP transport может нести много multiplexed logical streams. NAT/общий IP и время не назначают владельца. user_id/inbound фильтры поэтому не находят записи этого адаптера. Нет PTR/shared DNS/ECH догадок. Для application_stream и user attribution требуется отдельный проверенный producer; текущий socket adapter не закрывает эту часть P1.

## Состояние и время

TCP active означает видимый ещё не полностью закрытый kernel socket, а не факт передачи данных. TIME_WAIT/CLOSE считаются observed closed, но точное closed_at неизвестно. UDP — запись привязанного kernel socket, state=unknown: присутствие не доказывает активность UDP flow, idle timeout не моделируется как TCP closure. Disappearance открытого сокета даёт unknown tombstone, а не доказанное closed; ранее подтверждённый closed не меняется обратно на active/unknown.

started_at, closed_at и duration_seconds null. first_observed_at — первый успешный опрос этой записи, его нельзя использовать как настоящее начало. last_seen_at/measured_at и timestamp_origin=agent_poll_wall_clock обозначают время наблюдения, sample_interval_seconds вычисляется monotonic. Не использовать wall-clock subtraction для придумывания длительности. Для каждого неизвестного поля возвращается unavailable_reason.

Задержка обнаружения — до poll_seconds плюс время успешного dump (бюджет 2 секунды). Очень короткое соединение между polls может быть пропущено. Dump не атомарен на уровне всего ядра: IPv4/IPv6/protocol читаются последовательно, но API замораживает один опубликованный набор. Interrupted/truncated/netlink-overrun, timeout, отсутствие разрешений или превышение max_connections/16 MiB dump budget не превращаются в пустой успешный снимок. Происходит смена collector_epoch, invalidation cursors/snapshots, healthy=false и обязательный full resync. При следующем успехе cookie ID того же сокета сохраняется в пределах agent_boot_id; реальный start всё равно неизвестен.

## API снимков и cursor

- GET /v1/connections/live: limit=1..500 (default 100), offset=0..100000, snapshot_id, user_id, inbound, protocol=tcp|udp, state=active|closed|unknown.
- GET /v1/connections/{id}: одна текущая/retained запись в envelope.items; неизвестный/истёкший ID → 404.
- GET /v1/connections/changes: limit, cursor, те же filters; offset/snapshot_id не принимаются.

Envelope всегда включает items, agent_boot_id, collector_epoch, next_cursor, has_more, sampled_at, snapshot_id (null для changes/detail), resync_required=false, source. Live дополнительно total/limit/offset. Неизвестные данные не заполняются нулями.

Порядок синхронизации:

1. Получить live с offset=0 и сохранить snapshot_id/next_cursor.
2. Получить остальные страницы **с тем же snapshot_id и фильтрами** до has_more=false. Offset без snapshot_id отклоняется. Rows и sampled_at заморожены, новые/исчезнувшие сокеты не сдвигают страницы.
3. Использовать сохранённый cursor в changes, применять записи идемпотентно по connection_id и sequence. Для одного ID updated заменяет запись, а не добавляет bytes.
4. Выход из state-фильтра тоже возвращается (previous_state), чтобы клиент удалил/обновил прежнюю active запись. Это сознательное исключение из совпадения нового state, с сохранением остальных filters до пагинации.
5. При has_more=true читать следующий cursor до хвоста. Отсутствующий cursor начинает feed с текущего хвоста без backlog; это не замена full snapshot.
6. HTTP 409 `{error:"cursor_or_snapshot_expired", resync_required:true, remediation:...}` — отбросить локальную replica и повторить полный snapshot. Никогда не игнорировать gap.

Cursor содержит boot/epoch/sequence, но не секреты/IP/домены. Он непрозрачный протокольный маркер, не credential. Ring ограничен max_changes (default 10000, max 100000), поэтому медленный клиент может потребовать resync. Всего два frozen snapshots с TTL, вытеснение также даёт 409. Detail tombstones живут 60 секунд и ограничены max_connections. Текущие записи ограничены max_connections (default 10000, max 50000). Эти лимиты задают границы памяти, а не обещание throughput. SSE не реализован; bounded polling обязателен и достаточен для текущего контракта.

Все live данные только в RAM. SQLite/WAL/backups истории не получают новых socket records. После restart agent_boot_id меняется и прежние cursors недействительны. Хранение live history на диске не реализовано; включать несуществующий history/exporter параметр нельзя. Sensitive адреса существуют только в опциональном whitelist снимка и защищённых ответах; обычный log агента их не печатает.

## Mapping, миграция и rollback

CLI по умолчанию strict_user_uuid=true: user_id в mapping должен быть canonical nonzero UUID Remnawave, не Telegram ID. При invalid mapping целиком выключается источник событий с диагностикой, частичный mapping не применяется. Library UserMap сохраняет legacy-compatible режим для существующих интеграций; CLI strict_user_uuid=false допустим только как явный временный migration override, без утверждения достоверности не-UUID идентификаторов.

Mapping immutable в процессе. В cursor access.log хранится fingerprint node/inbound/email→user UUID mapping. При изменении fingerprint или первом переходе со старого cursor без fingerprint непрочитанный backlog пропускается до текущего EOF и сообщается mapping_changed_backlog_skipped. Это намеренная потеря неподтверждённого backlog вместо присвоения старого события новому владельцу. Уже сохранённые события не переназначаются. Для импорта исторического backlog используйте проверенный старый mapping отдельным контролируемым импортом до миграции; не удаляйте cursor вслепую.

Backend ALTLINK должен пробовать capabilities; 404 на старом агенте означает отсутствие нового контракта и не ломает основной host monitoring. Domain history остаётся независимой. Для rollback достаточно live_connections.enabled=false и restart; kernel/panel/Xray changes для отмены отсутствуют. При rollback к v1.2 сохраняются SQLite tables и history. Новые source-health fields аддитивны; клиент должен игнорировать неизвестные поля и учитывать diagnostics_version. Базовые loopback bind, TLS/UFW и token policies не меняются.

## Проверки и оставшиеся ограничения

Нативные Linux tests охватывают реальный TCP connect/данные и UDP socket, IPv4/IPv6 parser, kernel cookies, отсутствие user/domain inference, reset/gaps, stable pagination, cursor loss/boot changes, mapping migration, storage permissions/readonly/missing, disabled sources, slow API client и authorization всех новых endpoints. См. [TEST_REPORT_LIVE.md](TEST_REPORT_LIVE.md).

Пользовательские логические потоки с точной attribution, bytes/rates/duration остаются unsupported: они не заменяются socket guesses. End-to-end ALTLINK/Panel 2.7.4, runtime старой пары Node/Xray и 50000 **реальных VPN** streams before/after ещё требуют отдельного стенда/источника. Synthetic p95 не является HTTP/VPN p95. Это граница текущего P1 socket adapter; дополнительные application exporters и persistent live history относятся к дальнейшему P2.
