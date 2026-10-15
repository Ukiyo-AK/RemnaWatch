# Проверка диагностики и live API

Дата: 15.10.2026. Испытания проводились локально на Windows/Python 3.13 и на предоставленной пользователем тестовой Linux-ноде. Адрес SSH, пароли, конфиги и API tokens в отчёт/репозиторий не включены.

## Функциональные проверки

- Локально: 77 tests, OK, один native Linux integration skipped по платформе.
- На Ubuntu 24.04.4, Linux 6.8.0-146-generic, Python 3.12.3: 77 tests, OK, без пропусков. Рабочий Xray идентифицирован как 26.7.28 (5ca6f4b); контейнер remnanode использует mutable remnawave/node:latest, точный Node version из этого тега не выводился.
- Реальный TCP connect/send/recv и bound UDP socket проверены через NETLINK_SOCK_DIAG, стабильный socket ID при повторном polling, после закрытия — closed либо unknown при disappearance, без ложного вывода из timeout. User/domain/duration/byte поля остались null.
- Непривилегированный запуск socket diagnostics от UID 65534 успешно прочитал 41 видимый TCP/UDP socket. CAP_NET_ADMIN не предоставлялся. Ни PID socket owner, ни user UUID из этого не выводились.
- HTTP проверки: все новые routes требуют Bearer; no-store; slow header client не блокирует другой запрос; limit<=500; stable frozen snapshots; ring/snapshot/boot/epoch loss даёт 409/resync, повторные запросы не создают новый socket ID.
- Network fixtures: first sample, реальный zero delta, reset, missing/reappearing interface, permission/read errors; bridge inventory без double count, неизвестная capacity null.
- Storage fixtures: missing/EACCES/EROFS/EIO/cleanup failure, safe errno/redaction, выключенный optional source без critical, legacy_alerts и diagnostics_version=2.
- Mapping: UUID validation, immutable map, atomic rejection bad map, fingerprint migration исключает переназначение старого backlog новому UUID.
- Отдельный реальный запуск нового агента на временном loopback port с отсутствующим каталогом SQLite и invalid optional adapter: host API работает, storage недоступен явно, mutations выключены без durable audit, live healthy=false.

Production RemnaWatch/Xray не заменялись, сервисы не перезапускались, маршруты/sniffing/FakeDNS/iptables/tc/sysctl не изменялись. Код и тесты запускались из отдельного /tmp каталога, без production config и секретов; удаление временного каталога после проверок подтверждено. Рабочий RemnaWatch оставался active с 10:28:14 UTC 15.10.2026, контейнер remnanode — running с 14.10.2026; испытания не изменили время их запуска.

## Реальный kernel polling при текущей небольшой нагрузке

Три read-only dump за 10.0199 секунды с polling-интервалами 5 секунд:

| Метрика | Результат |
|---|---:|
| Видимые sockets по трём dump | 36 / 36 / 36 |
| CPU измерительного процесса за весь интервал | 0.01949 секунды |
| Пиковый RSS процесса (включая импорт и host probe) | 19 328 KiB |
| MemAvailable перед/после | 1 436 053 504 / 1 436 082 176 bytes |

Host NIC counters/rates продолжили считываться отдельно для ens3, lo и docker0; валидный ноль на docker0 не подменял неизвестное значение. NIC rates не использовались как bytes сокетов или доказательство VPN throughput.

## Synthetic 50 000 records

`python3 tools/benchmark_live.py --connections 50000` использует FakeSource в памяти, два poll и 20 запросов по 500 записей с JSON serialization. Это не 50 000 живых VPN connections и не HTTP round-trip benchmark. Tracemalloc включён и добавляет overhead.

| Метрика | Windows | Linux test node |
|---|---:|---:|
| Первый synthetic poll, wall | 1.546 s | 2.515 s |
| CPU первого poll | 1.547 s | 2.512 s |
| In-process snapshot+JSON p95 | 0.381 s | 0.444 s |
| Python allocations peak | 190 402 982 bytes | 190 400 878 bytes |

Результат [Linux](benchmarks-live-synthetic-linux.json) относится к варианту с fixed close-state/cursor behavior. Файл [benchmarks-live-synthetic.json](benchmarks-live-synthetic.json) содержит локальный baseline до этих небольших уточнений. Disk I/O микробенчмарком не измеряется (null), код live не пишет socket history в SQLite. Микробенчмарк воспроизводим, но не доказывает достижение production цели API HTTP p95<=1s или допустимого влияния на реальный VPN при 50 000 streams. Peak Python allocations не равен процессному RSS.

## Что не подтверждено этим прогоном

- Полный end-to-end ALTLINK с панелью Remnawave 2.7.4.
- Runtime отдельного образа Node 2.7.0 / Xray 26.3.27 (публичные API изучены отдельно).
- Логические Xray streams с точным user UUID/domain и per-stream bytes/rates/start/end. Эти capabilities текущий source объявляет unsupported.
- VPN throughput/latency до/после при контролируемом внешнем VPN-трафике; 50 000 реальных активных VPN streams; RSS/CPU/I/O всего VPN под такой нагрузкой. Малый read-only kernel test и synthetic benchmark это не заменяют.

Следующий этап — отдельно согласованный нагрузочный стенд и доказуемый application-level exporter, если нужна именно пользовательская flow attribution. Неподтверждённые значения не включены в API.
