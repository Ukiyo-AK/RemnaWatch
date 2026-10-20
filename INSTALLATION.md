# Установка и обновление RemnaWatch 0.2.0

Матрица и границы проверки: [COMPATIBILITY.md](COMPATIBILITY.md).
Рекомендуемый запуск — `sh deploy/install.sh`; он работает и без заранее
установленного Python. Без `--apply`/`--install-deps` ничего не устанавливает.
При `--apply` автоматически устанавливает недостающие зависимости из настроенных
репозиториев ОС. Debian 11/12/13 и Ubuntu LTS 20.04/22.04/24.04/26.04,
amd64/arm64, systemd PID 1, Python 3.8+. Не требует UFW и не изменяет Docker,
Xray, панель, Caddy, SSH или firewall. Реальные arm64 VM пока не проверены.

## Подготовка релиза на основном сервере

Сначала опубликуйте **проверенный commit с этой реализацией** в своём открытом
репозитории. Версия 0.2.0 в рабочем дереве сама по себе не создаёт GitHub release.
Создайте архив этого commit, вычислите SHA256 и сохраните digest, URL, SemVer,
минимальную/рекомендуемую версии и changelog в аутентифицированной политике
администратора. Digest из того же непроверенного скачивания не является
независимым подтверждением. Нода никогда не объявляет свою версию «последней».

Существующий генератор токена выполняется на основном сервере:

```sh
python3 -m remnawatch.auth issue-token --node-id UUID_НОДЫ
```

Выдаёт `node_id` и `rw_node_v1.<UUID>.<32 random bytes base64url>`. Сохраните
credential в защищённом хранилище backend и вручную в `auth` конфигурации
ноды. Это отдельный токен RemnaWatch, а не токен API Remnawave. Не передавайте
его в URL скачивания, аргументах процесса, именах файлов или списках версий.
Полный контракт генерации: [NODE_ENROLLMENT.md](NODE_ENROLLMENT.md).

## Первый запуск

Bootstrap выполняйте из исходников доверенного commit. Например, клонируйте
свой HTTPS-репозиторий и сделайте `git checkout --detach TRUSTED_COMMIT`.
Зависимости ОС, если отсутствуют: `python3`, `python3-venv`, `ca-certificates`,
`systemd`, `iproute2`. Bootstrap устанавливает их через APT после проверки ОС,
архитектуры, systemd и свободного места. Запуск с обычной учётной записью
при установке переключается через sudo. Команда `python` не требуется.
Глобальный pip не используется; агент работает в venv с `with_pip=False`.

Только подготовка зависимостей, без установки агента:

```sh
sudo sh deploy/install.sh --install-deps
```

Политика пакетов: фиксированный allowlist, `--no-upgrade`, `--no-remove`,
`--no-install-recommends`, предварительная APT simulation. Если resolver требует
обновить/удалить существующие пакеты, установка останавливается до выполнения
плана. Конфиги сохраняются (`--force-confold`), needrestart не перезапускает
службы. Нет dist-upgrade, reboot, добавления PPA, смены зеркал или отключения
проверки подписей/TLS. Для отсутствующего Python есть shell-этап до импорта
Python-модулей. Повторная проверка не переустанавливает исправные компоненты.
Ошибки APT/DNS/репозитория/блокировки дают безопасный код; lock-файлы не удаляются.
Установленные зависимости остаются после отказа последующего этапа агента.

`--no-install-deps` запрещает управление пакетами даже вместе с `--apply`.
Debian 10, Ubuntu 18.04 и неизвестные/interim-релизы не принимаются автоматически.
Совместимость старой ОС не заменяет поддержку безопасности её поставщиком:
ESM/ELTS и доступность подписанных репозиториев обеспечивает оператор.

```sh
sudo sh deploy/install.sh --container ACTUAL_CONTAINER_NAME
sudo install -d -m 700 /etc/remnawatch
sudo install -m 600 config.example.json /etc/remnawatch/config.json
sudoedit /etc/remnawatch/config.json
```

В конфиге задайте `auth`, абсолютный `database`, при необходимости
`runtime.container` (фактическое имя) и `network_origin: "host"`.
Новый пример выключает историю и live-сокеты. Не копируйте пример поверх
существующего рабочего конфига: используйте его как образец полей.
Для прямого HTTPS API задайте `tls.enabled=true`, `certificate`, `private_key`,
`server_name` и при частном CA `ca_file`. Без TLS оставьте loopback; доступ
основного сервера организуйте существующим проверенным TLS proxy/туннелем.

```sh
sudo sh deploy/install.sh \
  --config /etc/remnawatch/config.json \
  --release-url https://codeload.github.com/OWNER/REPO/tar.gz/TRUSTED_COMMIT

sudo sh deploy/install.sh --apply \
  --config /etc/remnawatch/config.json \
  --release-url https://codeload.github.com/OWNER/REPO/tar.gz/TRUSTED_COMMIT \
  --sha256 TRUSTED_SHA256 --version 0.2.0
```

URL без query/credentials; HTTPS и hostname verification обязательны,
redirect не допускается. Проверка digest предшествует извлечению/исполнению.
Архив ограничен по размеру и числу файлов, links/traversal отвергаются.
Существующие произвольные systemd units автоматически не принимаются:
`unmanaged_unit` требует отдельно проверенной миграции. Старый сервис остаётся
рабочим. При миграции сохраните прежние units, конфиг, WorkingDirectory и
абсолютный путь прежней БД; сначала проверьте новую поставку в тестовой среде.

Повтор с тем же digest проверяет manifest и переиспользует релиз. Если версия,
конфиг и health совпадают, сервис не перезапускается. Неизменённые настройки
сохраняются; изменённый оператором managed unit не перезаписывается.
Обновление выполняется той же командой с новым доверенным digest/версией.
Предыдущие релизы и защищённые backups остаются в `/opt/remnawatch`.
Неуспешный health восстанавливает предыдущие config/unit/current и состояние
service. `rollback_failed` требует ручной проверки systemd, путь backup выдаётся.
Это откат агента, не откат БД между несовместимыми схемами: данная версия схему
БД не меняет. Перед будущими миграциями нужна отдельная стратегия backup.

## История: отдельный этап

`--history --container ACTUAL_CONTAINER_NAME` проверяет реальный running
контейнер, immutable image ID, s6 или Supervisor, точный mount и доступный
существующий файл. Не требует Compose для чтения mounted-логов. При отсутствии
mount/логгера/UUID mapping этап завершается отдельно; контейнер не пересоздаётся.
Включайте `domains.enabled` и `access_logs` только после настройки источника.
Маппинг `(node_id,inbound,email)` должен приходить из панели и содержать
постоянный Remnawave UUID. VLESS ID и IP клиента его не заменяют.

План изменения только полей `log` в отдельном профиле ноды:
[deploy/xray-log-plan.example.json](deploy/xray-log-plan.example.json).
Он **не исполняется автоматически**: нужны backup и явное согласие оператора.
`loglevel: none` выключает и access logging; warning не включает debug.
После реального подключения проверьте рост реального файла и
`last_event_at`/UUID history. `awaiting_real_connection` не означает успешный
end-to-end тест. Первое чтение по умолчанию начинается с EOF, чтобы не импортировать
старый backlog с новым mapping; при его изменении backlog также пропускается явно.

## Браузерный probe: отдельный opt-in

Скопируйте [deploy/probe.example.json](deploy/probe.example.json) в защищённый
`/etc/remnawatch/probe.json`, задайте реальный домен и имеющиеся публично
доверенные certificate chain/key. Выполните ту же команду установки с
`--probe-config /etc/remnawatch/probe.json`. Совместимый GET+HEAD probe
сохраняется; несовместимый listener/сертификат не заменяется. При неудаче
возвращается прежняя конфигурация/состояние probe, агент остаётся работать.
Новый listener — отдельный `remnawatch-probe.service`, без БД и авторизации,
GET/HEAD `/ping` → 204, no-store; URL query отвергается, access logging нет.
Другие пути не раскрывают API. Renewal сертификата и рестарт после renewal
настраивает оператор; автоматической выдачи сертификатов/Caddy rewrites нет.

Публичный порт открывайте только осознанно. Установщик **не меняет правила**.
Для активного UFW при выбранном контракте: `sudo ufw allow 44443/tcp`.
При firewalld/nftables/внешнем firewall добавьте эквивалентный TCP ingress,
проверьте IPv4 и IPv6. Не включайте/не сбрасывайте firewall и не меняйте SSH/VPN.
Приватный 18443 разрешайте только IP/CIDR основного сервера; при UFW:
`sudo ufw allow from PRIMARY_SERVER_IP to any port 18443 proto tcp`, затем
проверьте отсутствие широких allow на этот порт. Inactive/absent UFW не даёт
никакой защиты: сначала настройте реально действующий firewall.

```sh
curl -I https://node.example.com:44443/ping
```

ALTLINK: `latency_probe_scheme=https`, `latency_probe_port=44443`,
`latency_probe_path=/ping`. Существующий формат URL сохраняется. Это browser
HTTPS RTT, отдельно от ICMP, server TCP и скорости трафика. Мобильный WebView
и публичный IPv6 проверяются с клиентских устройств, loopback-тест их не заменяет.

## Опциональные измерения

`user_metrics`: `enabled`, `node_id` (ID в mapping), `container`,
`server: "127.0.0.1:PORT"`. `mapping_verified=true` допускается только после
проверки полного маппинга всех активных inbound ноды и отсутствия повторного
использования email при ещё активных старых соединениях. Сам StatsService не
содержит inbound/Remnawave UUID; неполного списка пользователей недостаточно.
Без этого подтверждения источник возвращает `user_mapping_not_verified`, не
выполняет запросы и не показывает скорость. Используется только **уже существующий** доступный
StatsService. Опрос раз в 5 секунд, timeout 3 секунды, `-reset=false`.
Если API/политики не настроены, их автоматически не включаем. `sustained_load`:
`enabled=false` по умолчанию; `capacity_mbps`, `fraction=0.5`,
`window_seconds=600`, `minimum_bytes=100000000`, `consecutive_samples=3`.
События только для непрерывного измеренного превышения, без автоматических
санкций или отправки в Telegram. RX/TX здесь — uplink/downlink proxy, а не
сумма физических NIC. Ограничение UUID в текущей сборке unsupported.

Для диагностики центрального history endpoint: `central_history.enabled=true`,
`url: "https://PRIMARY/api/remnawatch/agents/NODE_UUID"`, необязательный
`ca_file`. Агент раз в минуту делает безопасный GET history-plan; не импортирует
маппинг и не меняет профиль. Для probe health используйте `probe_monitor` с
`enabled=true` и теми же полями, что у probe JSON. Полные HTTP/DNS/TLS/timeout
ошибки доступны как безопасные коды в diagnostics, без сырых ответов/секретов.
