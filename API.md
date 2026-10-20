# Domain Activity REST API

Все routes требуют `Authorization: Bearer <полный токен ноды>`. Основной сервер генерирует credential формата `rw_node_v1.<UUID>.<256-bit secret Base64URL>` и оператор вставляет его в auth.token. Один механизм авторизации защищает всю поверхность API данной ноды. Непустой auth.token имеет приоритет над legacy REMNAWATCH_API_TOKEN (32..512 printable ASCII без пробелов). Возврат `Cache-Control: no-store`. По умолчанию localhost:8080; удалённое подключение через защищённый канал. Генерация/ротация: [NODE_ENROLLMENT.md](NODE_ENROLLMENT.md).

`GET /v1/node` без query параметров возвращает `{node_id, authentication, service, api_version}`. При новом токене authentication=node_token_v1, node_id — UUID из сконфигурированного credential, service=remnawatch, api_version=v1. Для legacy Bearer authentication=legacy_bearer и node_id=null. Endpoint требует авторизацию, токен не возвращает; 400 при query, 401 при неверном/повторном/отсутствующем Authorization. Основной сервер обязан сравнить ожидаемый UUID и service/version, прежде чем отмечать ноду подключённой.

| Endpoint | Результат |
|---|---|
| `GET /v1/domains` | Статистика по domain + достоверно известному destination IP; IP-only строки имеют domain=null |
| `GET /v1/domains/top` | Топ доменов, соединения суммируются по IP; IP-only исключены |
| `GET /v1/domains/{domain}/users` | Пользователи указанного нормализованного домена |
| `GET /v1/users/{id}/domains` | Статистика пользователя |
| `GET /v1/users/{id}/domains/history` | Подробные события, новые сначала |
| `GET /v1/users/{id}/domains/top` | Топ доменов пользователя |

Все endpoints: `period=5m|1h|24h` (default 24h) **или** `from` и `to`. Обе границы обязательны вместе, period с ними запрещён. Unix UTC seconds или ISO 8601 с timezone и без fractional seconds. Интервал `[from,to)`, максимум 365 дней. `limit=1..500` (default 100), `offset=0..100000` (default 0), `user_id`, `node_id`, `search` (substring домена, lowercase, максимум 253 символа). Фильтры применяются до группировки/пагинации. Domain path принимает IDNA/Unicode, канонизирует lower-case/trailing dot. IP не принимается как домен. User path и user_id query не могут противоречить друг другу.

Для `/v1/domains`, `/v1/users/{id}/domains`, `/v1/users/{id}/domains/history`: `view=activity&bucket=hour|day` (hour по умолчанию) возвращает UTC buckets с connections/first_seen/last_seen и `network_load` по node: average_bps, peak_bps, samples. Измерения нагрузки могут отсутствовать; это не трафик домена. Пагинация и временные фильтры применимы к этому view.

Envelope:

```json
{"items": [], "total": 0, "limit": 100, "offset": 0,
 "period": {"from": 1791900000, "to": 1791900300},
 "quality": {"collection_enabled": true, "registered_connections": 0,
   "domain_connections": 0, "domain_coverage": null, "attributed_connections": 0,
   "complete": false, "period_truncated": false,
   "timestamp_precision": "second", "event_retention_days": 7,
   "aggregate_retention_days": 30, "collector_counters": {},
   "sniffed_domain_export": "unavailable_in_stock_xray",
   "traffic_semantics": "exact_measurements_only",
   "limitations": ["ECH", "CDN", "IP-only requests", "missing logs", "Xray source limitations"],
   "connection_semantics": "registered connection event; not a web page visit"}}
```

Статистическая строка содержит connections, first_seen, last_seen, measured_connections, bytes_transferred и ключ группировки domain/destination_ip или user_id. `bytes_transferred=null`, если хотя бы одно включённое соединение не имеет точного измерения. `measured_connections` показывает число измеренных соединений; user-level Xray counters не распределяются по доменам. Время первого/последнего обращения относится к выбранному периоду.

History содержит Event: event_id, node_id, user_id, timestamp, domain, destination_ip, client_ip, protocol, destination_port, inbound, outbound, source, confidence, bytes_transferred, connections=1. Domain и IP могут быть null по отдельности. Источник: client_request/http_host/tls_sni/quic_sni/fakedns/dns_metadata/xray_access/ip_only. Confidence: observed (проверенный клиентский запрос), attributed (доверенная корреляция), unknown (происхождение не доказано). Значение не подтверждает посещение страницы, успех TLS или владельца сайта.

`quality` считает наблюдаемые события в выбранном фильтре по aggregate retention, включая IP-only (для top тоже до исключения IP-only). Поэтому у history число registered_connections может превышать число доступных подробных записей. `domain_coverage` — доля доменных записей среди зарегистрированных, не доля всего трафика. `period_truncated` показывает выход за срок соответствующего хранения. Коллекторские счётчики общие за срок работы базы, не отфильтрованы по пользователю/периоду; объединённый unparsed_or_unmapped не позволяет вычислить полноту пользовательской истории. `complete=false` всегда, отсутствие событий не доказывает отсутствия активности.

Ошибки JSON: 400 invalid request parameters; 401 unauthorized; 404 not found; 503 query budget exceeded or storage busy. Неизвестные/повторяющиеся query параметры отклоняются. Доменные write endpoints отсутствуют; управление сервером использует отдельный POST, описанный ниже. Пагинация offset не является snapshot: при поступлении/удалении событий страницы могут смещаться.

Пример: `/v1/users/USER_UUID/domains/history?period=5m&limit=100&offset=0`, `/v1/domains?view=activity&bucket=hour&period=24h&node_id=node-1`.

## Server API

`GET /v1/server` возвращает характеристики/нагрузку, disk/memory alerts и configured capabilities. `GET /v1/server/jobs` с limit/offset и `GET /v1/server/jobs/{id}` возвращают аудит управления. `POST /v1/server/actions` принимает `{action, params?, dry_run?, request_id?}`; dry_run по умолчанию true (200), реальное выполнение требует management.enabled=true, dry_run=false и request_id (202). Дополнительные ошибки: 403 disabled, 409 conflict/pressure, 501 unsupported. Все endpoints защищены общим Bearer token и no-store. Детальные параметры, действия и ограничения: [SERVER_MANAGEMENT.md](SERVER_MANAGEMENT.md).

Domain quality дополнена collection_paused, pause_reasons и emergency_retention (null либо timestamp/removed/early_deletion). Это отражает паузу при давлении памяти/диска и удаление истории раньше 7/30 дней. period_truncated по-прежнему показывает только настроенный retention cutoff; при аварийном удалении всегда дополнительно смотрите emergency_retention.

## Source diagnostics и live sockets

Все новые endpoints используют тот же Bearer/no-store. `GET /v1/capabilities` разделяет supported/configured/healthy (null до измерения/при отключении). `GET /v1/diagnostics/sources` возвращает безопасные source states/lag/gaps/permissions. `GET /v1/network/interfaces` возвращает inventory без NIC/bridge суммирования. В `/v1/server` network[] добавлены available/sampled_at/sample_interval_seconds/counter_reset/error_code/origin; error/first/reset → rates=null, корректная нулевая дельта → 0.

Storage diagnostics version=2 использует log_directory_missing, log_directory_permission_denied, log_directory_read_only, log_cleanup_failed, log_storage_io_error. Есть component/severity/path/error_type/errno/required/impact/remediation, legacy_code и legacy_alerts. Выключенный optional source не делает агент critical. History quality.history_storage_available отражает persistent database availability; при аварийном старте host/live API доступны независимо от истории.

`GET /v1/connections/live`: limit<=500, offset, snapshot_id, user_id/inbound/protocol/state; offset>0 требует frozen snapshot_id. `GET /v1/connections/{id}`: текущая либо retained запись. `GET /v1/connections/changes`: cursor, limit и те же filters, без offset. Envelope содержит items, next_cursor, has_more, sampled_at, snapshot_id, agent_boot_id, collector_epoch, source и resync_required. Cursor/snapshot loss → HTTP 409 с resync_required=true, полный snapshot обязателен. Фильтры применяются до пагинации; changes включает state-exit transition для согласованности filtered replica.

Текущий source только transport_socket, а не application_stream: user_id/inbound/domain/stream_id/start/duration/bytes/rates неизвестны и null/unsupported. Наблюдаемые адреса только local/peer, без угадывания client/destination. Disappearance открытого сокета → unknown tombstone; UDP socket presence не доказывает активный flow. Локальный snapshot не является всей сетевой историей. Старый access history API не меняет семантику. Поля, модели времени, буферы, миграция: [LIVE_DIAGNOSTICS.md](LIVE_DIAGNOSTICS.md).
## Дополнения 0.2.0

`GET /v1/node` теперь содержит обязательные agent_version (SemVer), platform, architecture, started_at; nullable agent_build, remnanode_version, xray_version. Версии Xray/Node заполняются только при explicit runtime.container и достоверном discovery. Node initializer 0.0.0 не считается релизом. Ответ остаётся аутентифицированным и no-store, секретов/адресов/конфига не добавлено.

Source diagnostics дополнены last_event_at, last_success_at, lag_bytes, skipped_events, errors, parse_errors, read_seconds, storage_seconds, event_age_seconds. invalid_line отличается от user_mapping_mismatch, source_missing, permission_denied, history_storage_unavailable. Idle сохраняет healthy=true; возраст последнего события не является измерением задержки central import. Optional central_history даёт central_dns_error/central_tls_error/central_connect_error/central_timeout/central_http_NNN (401/403/404/409/5xx отдельно), transfer_seconds, последнюю успешную проверку. Это control-plane latency, не задержка всех импортированных событий. Probe diagnostics показывают HTTPS availability, не browser RTT.

`GET /v1/users/{id}/metrics` — canonical Remnawave UUID, без query; sampled_at, sample_interval_seconds, source=xray_stats_user_totals, available, rx_bytes_per_second/tx_bytes_per_second. Неизвестное/first/reset/gap/stale/missing → null, не 0. Direction — proxy uplink/downlink; статистика суммирует все измеренные email/подключения одного пользователя на данной ноде. При выключенном источнике ответ available=false. Статистика не является per-domain bytes.

`GET /v1/alerts/sustained-load?limit=100&offset=0` — до 500 последних RAM-эпизодов, одно событие на непрерывное превышение. UUID, node_id, sampled_at, duration_seconds, measured average/capacity_fraction, telegram_id=null и относительный user_card_path. Адрес карточки адаптирует backend; никакого Telegram lookup/sending. После рестарта RAM-история предупреждений очищается. Default правило выключено.

`GET /v1/users/{id}/rate-limit` и `POST` с action=apply|revoke возвращают **501**: supported=false, state=unsupported, applied=false, expires_at=null. Дополнительные поля будущего POST: mbps, expires_at, reason, request_id. Действие не применяется и не ставится в очередь. Нет фиктивных TTL/лимитов/успеха: backend точного aggregate shaping отсутствует. Node-wide tc endpoint не является заменой. Требования expiry/persistence/migration относятся к будущему подтверждённому backend.

Все три новых API path защищены прежним Bearer. Probe отдельного сервиса намеренно публичен: GET/HEAD /ping 204, no-store, без query, другие пути 404. Он не публикует /v1 API и не использует token. Его порт/домен/path конфигурируются отдельно.
