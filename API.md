# Domain Activity REST API

Все routes требуют `Authorization: Bearer <REMNAWATCH_API_TOKEN>`. Токен — не менее 32 ASCII символов без пробелов; одинаковая авторизация для всей поверхности API. Возврат `Cache-Control: no-store`. По умолчанию localhost:8080; удалённое подключение через защищённый reverse proxy.

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

Ошибки JSON: 400 invalid request parameters; 401 unauthorized; 404 not found; 503 query budget exceeded or storage busy. Неизвестные/повторяющиеся query параметры отклоняются. Стандартный HTTP server возвращает 501 для неподдерживаемых методов; публичных write endpoints нет. Пагинация offset не является snapshot: при поступлении/удалении событий страницы могут смещаться.

Пример: `/v1/users/USER_UUID/domains/history?period=5m&limit=100&offset=0`, `/v1/domains?view=activity&bucket=hour&period=24h&node_id=node-1`.
