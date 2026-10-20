# Проверка поставки 0.2.0 — 2026-10-20

Последующее расширение Debian/Ubuntu и автоматической подготовки зависимостей
проверяется отдельно: [TEST_REPORT_DEBIAN_UBUNTU.md](TEST_REPORT_DEBIAN_UBUNTU.md).
Ниже сохранены фактические результаты предыдущего набора из 121 теста.

Статус: изменения агента проверены перечисленными тестами. **Полная приёмка
всего ТЗ и production rollout не закрыты.** Нет второй среды arm64 / Node 2.7.x /
панель 2.7.4; пользователь подтвердил отсутствие такой среды. Контейнерные
прогоны не являются установкой systemd на чистой VM.

## Выполненные проверки

```text
python -m unittest discover -s tests -q
python -m compileall -q remnawatch tests
python tests/check_openapi.py
ruff check remnawatch tests --select E9,F63,F7,F82 --target-version py310
ruff check <новые модули и test_deployment.py> --select F --target-version py310
git diff --check
```

Ruff 0.17.1 установлен в отдельный временный venv, глобальный pip не менялся.
Все приведённые статические проверки прошли. OpenAPI: 20 paths, 21 operation;
локальные references и контракты проверены. JSON examples читаются.
Новых shell-скриптов нет: ShellCheck неприменим к Python CLI.
Оба сгенерированных systemd unit дополнительно прошли `systemd-analyze verify`
на реальном Ubuntu 24.04 хосте: exit 0, diagnostic lines 0. Units не
устанавливались и не запускались этой проверкой.

| Среда | Результат последнего набора |
|---|---|
| Windows, Python 3.13 | 121 тест, OK, 4 skipped (13.698 s) |
| Реальная Ubuntu 24.04 amd64, Python 3.12.3 | 121 тест, OK, без пропусков (16.018 s) |
| Чистый Ubuntu 22.04 amd64, Python 3.10.12 | 121 тест, OK, без пропусков (22.836 s) |
| Чистый Debian 12 amd64, Python 3.11.2 | 121 тест, OK, без пропусков (21.822 s) |
| Чистый Ubuntu 24.04 amd64, Python 3.12.3 | 121 тест, OK, без пропусков (20.186 s) |

Четыре Windows-пропуска: native inet_diag; POSIX atomic directory-symlink
replacement; FIFO; IPv6 loopback connection (WinError 10013, host policy).
На Linux эти проверки исполняются. Реальный TLS IPv4 GET/HEAD и private API
health с hostname verification выполнены и на Windows.

Контейнерные команды (последовательно, не production container):

```sh
docker run --rm --name remnawatch-test-OS \
  --cpus=0.5 --memory=384m --pids-limit=128 \
  --security-opt=no-new-privileges \
  -v TEMP_TEST_DIRECTORY:/work:ro -w /work IMAGE sh -c \
  'export DEBIAN_FRONTEND=noninteractive;
   apt-get update -qq >/tmp/packages.log 2>&1 &&
   apt-get install -y --no-install-recommends python3 python3-venv openssl >>/tmp/packages.log 2>&1 &&
   python3 --version && python3 -m unittest discover -s tests -q &&
   python3 -m remnawatch.install'
```

Образы: Ubuntu 22.04 digest
`sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956`,
Debian 12 slim
`sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587`,
Ubuntu 24.04
`sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`.
Во всех трёх проверен безопасный `systemd_unavailable` до установки.
Пакеты устанавливались только внутрь удаляемых тестовых контейнеров.

## Покрытие и найденные дефекты

- Целевая матрица шести OS/architecture комбинаций — fixtures, отдельно отказ
  неизвестной ОС/архитектуры/Python/init. Реальные arm64 не подменены fixtures.
- Пятнадцать fixture-сочетаний UFW active/inactive/absent, firewalld/nftables и
  Compose v1/v2/absent: inventory без enable/reset/insert/restart.
- s6/Supervisor, stopped/ambiguous container, injection в container name,
  mounted/missing log, отсутствие mount. Read-only preflight не создаёт лог.
- Семантика SemVer/prerelease/build, unknown/custom/stale heartbeat, invalid policy.
- HTTPS/digest mismatch, unavailable release, traversal/links, duplicate/invalid
  release, archive expansion budget в том числе для ignored/PAX content;
  DNS rebinding к private IP блокируется в момент connect.
- Повторная установка переиспользует проверенный manifest, изменённый source
  отвергается, failed download удаляет только свой staging. Health rollback
  сохраняет прежние config/unit/release; managed operator unit не затирается.
- Найден и исправлен дефект отката при неуспешном rename до переключения current:
  старая ссылка больше не удаляется. Native атомарный откат проверен на Linux.
- Real TLS GET/HEAD 204, no-store, 404 для API/query, wrong trust chain, occupied
  port; compatible probe сохранён. Failed probe восстанавливает старые config,
  unit и состояние service, не трогая agent/VPN. TLS handshakes bounded.
- Private health проверяет TLS hostname, но соединяется с локальным listener:
  token не отправляется по внешнему DNS серверу с ошибочным адресом.
- Invalid line и mapping mismatch разделены; idle healthy; cursor failures
  закрывают fd. FIFO открывается nonblocking и отвергается как не regular file.
- User totals суммируют параллельные источники, исключают ambiguous email,
  требуют подтверждённого полного node-wide mapping; first/reset/change/gap/
  stale/missing дают null. Docker I/O не держит lock HTTP snapshots.
- Speedtest не создаёт sustained event; пропуск сбрасывает окно; одно событие
  на эпизод. UUID rate-limit возвращает 501, не вызывает interface tc.
- Существующие history/filter/retention/auth/pressure/concurrency regressions
  включены; synthetic large-volume проверка — 30 000 событий, не VPN benchmark.

## ALTLINK

Соседнее рабочее дерево ALTLINK-VPN уже имело незакоммиченные изменения до
начала этой работы. Оно не переписывалось. Проверены совместимые выбранные тесты:

```sh
python -m pytest \
 tests/unit/test_remnawatch_versions.py \
 tests/unit/test_remnawatch_history_setup.py \
 tests/unit/test_remnawatch_diagnostics.py \
 tests/unit/test_remnawatch_client.py \
 tests/integration/test_remnawatch_installer.py \
 tests/integration/test_admin_monitoring_settings.py -q
```

**150 passed, 51.44 s.** Эти тесты не означают deployment UI на действующий сайт.
Дополнительный запуск всего большого ALTLINK suite был остановлен на частичном
прогрессе; полного зелёного результата для всего стороннего проекта нет.
Миграций схемы агентской БД нет. Полная production схема панели 2.7.4 не проверена.

## Реальная нода и контроль источника

Read-only подтверждены Ubuntu 24.04.4 amd64, Xray **26.7.28**, RemnaNode **3.2.0**
по release assignment работающего bundled main.js. Начальное значение 0.0.0
не является релизом. Immutable image ID:
`sha256:bfc0914959f991217dffe1269ad5db83deeb12a297dcbf90bde6d1636ed72747`.
`latest` не использовался как версия. Проверен s6 logger и реальный bind mount.

После сообщения пользователя о тестовом VPN-подключении:

- История включена в старом конфиге агента, но путь `/var/log/xray/access.log`
  отсутствует. Настроена одна mapping row; её принадлежность пользователю панели
  не подтверждалась угадыванием по IP/VLESS ID.
- Mounted `current` существует, 2545 bytes, mtime остаётся 2026-10-15.
- Runtime-конфиг Xray получен локально без вывода payload/config/secrets:
  `loglevel=none`, `access` не задан. При таком loglevel Xray выключает access
  logger; см. [официальный config builder](https://github.com/XTLS/Xray-core/blob/main/infra/conf/log.go).
- Рост файла и свежая UUID history **не подтверждены**. Review-only план
  [deploy/xray-log-plan.example.json](deploy/xray-log-plan.example.json) готов;
  профиль Xray/панели не изменялся, debug не включался, пустой лог не создавался.

Источник Node версии проверялся без вывода полного JS, env, токенов, IP клиентов
или строк access.log. На сервер передавались только исходники/тесты в /tmp.
Production config/private keys не экспортировались, RemnaNode/Xray/панель не
обновлялись. Проверка опубликованного релиза и переключение production агента
не выполнялись: эта рабочая версия ещё не опубликована доверенным release.
В конце проверки `remnawatch.service` active, RemnaNode running=true с тем же
image digest. Временный каталог исходников/тестов и три добавленных тестовых
Docker-образа удалены; production container не пересоздавался.

Локальный `.test-ssh-lint` (отдельное окружение статического анализатора)
остался: автоматическая проверка заблокировала его удаление с сообщением
`blocked by policy`. Каталог игнорируется Git и не входит в поставку.

## Security review и остаточные ограничения

Проверены границы auth, отсутствие secret в diagnostic/error/metadata responses,
Bearer только в headers, отключение redirects/proxy для control/health, TLS
verification, root-only config/backups/manifests, archive/SSRF ограничения,
lock/идемпотентность и безопасные отдельные откаты. Новые endpoints наследуют
старую авторизацию; публичный probe не имеет доступа к API или БД.
URL paths/HTTPS content/cookies/пароли/HWID не собираются новыми адаптерами.

Не проверены/не реализованы без отдельного источника или среды:

1. Чистые systemd VM каждой OS/architecture, реальные arm64 и все сочетания
   firewall/Caddy/external networks; fixtures не сертифицируют их.
2. End-to-end панель 2.7.4 + Node 2.7.x, продакшен UI/installer rollout ALTLINK.
3. Fresh real-user history до согласованного включения логирования и
   авторитетного mapping из панели; настоящее VPN throughput/impact измерение.
4. Public TLS issuance/renewal, реальный браузер/mobile WebView/public IPv6.
5. Точное aggregate shaping по UUID, его TTL/persistence/revoke/migration:
   backend не найден, API честно unsupported, фиктивных тестов expiry нет.
6. Полная задержка ingest на центральном backend: transfer_seconds измеряет
   control request, а не весь pipeline. Missing measurement остаётся null.

Сопоставление источников и доступные API:
[INSTALLATION.md](INSTALLATION.md), [API.md](API.md), [LIMITATIONS.md](LIMITATIONS.md).
