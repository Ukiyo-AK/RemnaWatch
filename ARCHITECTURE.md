# Архитектура RemnaWatch

В исходном репозитории отсутствовал сервис; модуль реализован как самостоятельный Python 3.11+ сервис без сторонних runtime-зависимостей. Xray и Remnawave не встраиваются в процесс RemnaWatch.

Поток данных: локальный access.log → ограниченный polling → строгий парсер → точная таблица пользователей → пакетная транзакция SQLite WAL → REST API. Один процесс владеет базой; несколько log sources могут обслуживать разные node_id. API использует общую Bearer-авторизацию, слушает localhost по умолчанию. При интеграции с большим API передавайте тот же авторизованный контекст или устанавливайте общий middleware перед `dispatch`.

## Источники и достоверность

AccessParser принимает только accepted TCP/UDP записи с email. Идентификация: `(node_id, inbound, email)` → Remnawave user ID. IP клиента не используется для идентификации. Неизвестные/неоднозначные пользователи отбрасываются, учитываются в общем счётчике `unparsed_or_unmapped`. Это предотвращает ошибки при NAT, переиспользовании email на разных нодах и shared inbound.

Домен в access.log получает `source=xray_access`, `confidence=unknown`: домен наблюдался, но механизм его получения не доказан. `client_request_verified=true` разрешён только после проверки, что данная конфигурация/версия пишет исходный домен клиентского запроса без подмены sniffing. Тогда источник — `client_request`, достоверность — `observed`. Этот флаг не меняет Xray. `client_ip` означает наблюдаемый Xray peer IP, который может принадлежать reverse proxy. Неизвестные значения — null.

`correlated_metadata` — библиотечный интерфейс доверенного производителя для `http_host`, `tls_sni`, `quic_sni`, `fakedns`, `dns_metadata`. Он требует стабильный ID соединения, authenticated email и явное подтверждение точной корреляции. Это не готовый экспортёр sniffing и не публичный ingestion API. Запрещены поля вне whitelist. Для одного соединения используйте один источник; access.log и метаданные нельзя объединять по времени/IP. Без общего connection ID нельзя безопасно устранить двойной учёт. Для DNS недостаточно общего кеша или совпадения IP.

## Исследование sniffed domain без изменения Xray

Проверены upstream исходники 2026-10-13:

- [RoutingContext protobuf](https://github.com/XTLS/Xray-core/blob/main/app/router/command/command.proto) описывает домен, user email, IP, порты, inbound/outbound и streaming RPC. Само наличие RPC не означает работающий экспорт событий.
- [Регистрация RoutingService](https://github.com/XTLS/Xray-core/blob/main/app/router/command/command.go) создаёт сервер с nil каналом. Штатный SubscribeRoutingStats сообщает, что routing statistics не включены. Модуль не полагается на этот RPC.
- [Routing session context](https://github.com/XTLS/Xray-core/blob/main/features/routing/session/context.go) видит RouteTarget/Target внутри процесса. Данные не становятся автоматически доступными внешнему агенту.
- [Dispatcher](https://github.com/XTLS/Xray-core/blob/main/app/dispatcher/default.go) пишет sniffed domain в info error-log. Sniffing может изменять RouteTarget или Target; `routeOnly` сохраняет цель в некоторых случаях, но домен всё равно может влиять на выбор маршрута. Включать его ради мониторинга нельзя. Info-строка сама по себе не даёт надёжной связи с access.log пользователем; постоянный info/debug сбор здесь не используется.
- [Формат access message](https://github.com/XTLS/Xray-core/blob/main/common/log/access.go) содержит From/To, email и detour, но не универсальный connection ID или доказанный sniffing source.

Итог: безопасного универсального внешнего экспорта sniffed domain в исследованной штатной сборке не найдено. HTTP Host, TLS/QUIC SNI и FakeDNS не объявляются доступными без отдельного подтверждённого metadata adapter. Не добавляются маршруты, не включается sniffing, не производится перехват пакетов. Для конкретной сборки Remnawave/Xray требуется повторная проверка capabilities.

## Хранение и аналитика

`events` хранит подробные события 7 дней: идентификаторы, домен/IP, peer IP, timestamp UTC в секундах, TCP/UDP, порт, теги, источник, confidence и optional exact bytes. `aggregates` хранит 30 дней счётчики по секунде и измерениям node/user/domain/destination IP/transport/port/tags/source/confidence. Секундная гранулярность обеспечивает точную фильтрацию произвольных периодов без включения соседних часов. Высокая кардинальность снижает степень сжатия. `seen` предотвращает повторный учёт в течение aggregate retention даже после удаления деталей.

Транзакция атомарно обновляет seen, events, aggregates и offset лог-файла. Стабильный ID access event: поколение файла + byte offset + node. Cursor сохраняет filesystem identity и хеш последних 128 байт для обнаружения truncate/rewrite. Rename rotation дочитывается при доступном старом дескрипторе; пропущенная ротация отмечается как ограничение. История упорядочена по timestamp, node, event ID; агрегаты — по числу соединений и стабильным ключам.

Очистка раз в минуту; query дополнительно ограничен retention cutoff. `enabled=false` прекращает парсинг и пропускает новые записи, чтобы не импортировать их после включения. По умолчанию очистка при отключении удаляет события, агрегаты, dedup и network context, с secure_delete и WAL checkpoint. Ранее созданные backup, исходные Xray logs и копии на уровне диска управляются отдельно. Сроки и purge_on_disable настраиваются.

## Нагрузка и изоляция

Сборщик читает не более batch_lines записей за poll; строки ограничены 8 KiB, память ограничена размером пакета. Oversized строки пропускаются bounded chunks. Нет синхронного вызова из Xray; медленная база увеличивает задержку мониторинга, а не блокирует подключение. SQLite cache 8 MiB, WAL, batch writes, индексы времени/user/domain, максимум 500 результатов и 100000 offset, SQL budget 2 секунды. REST-сервер последовательно обслуживает запросы; для внешнего доступа нужен reverse proxy с TLS, timeout, rate limits. Данные запросов не попадают в access log сервиса.

Опциональный NetworkSampler читает `/proc/net/dev` раз в 5 секунд для явно выбранных интерфейсов. Он сохраняет host/node bytes per second, не payload. Активность и peak/average load сопоставляются по UTC bucket и node. Это контекст нагрузки, без причинного вывода и без распределения байтов по доменам. Нельзя одновременно включать интерфейсы, дублирующие одни и те же пакеты (например bridge и его member).
