# Добавление ноды через токен основного сервера

Основной сервер выдаёт отдельный секрет для каждой ноды. Оператор вручную вставляет его в config.json RemnaWatch, после чего основной сервер обращается к API ноды с этим секретом. Нода не обращается к панели за разрешением при каждом запросе. Это ручное provisioning постоянного API credential, не одноразовый код активации и не встроенная интеграция с внутренним API Remnawave.

## Генерация на основном сервере

Для новой записи ноды:

1. Создать постоянный node_id — UUID в canonical lowercase формате. Он используется для проверки, что ответила ожидаемая нода. Если ID уже существует и является UUID, использовать его.
2. Получить **32 криптографически случайных байта** (256 бит), закодировать Base64URL без `=` padding.
3. Сформировать `rw_node_v1.<node_id>.<secret>`, где secret — ровно 43 Base64URL символа. UUID — идентификатор, а не секрет. Не использовать UUID, пароль пользователя, timestamp или hash IP вместо random secret.
4. Сохранить endpoint, node_id и **исходный token** в защищённом хранилище основного сервера. Для автоматических запросов hash-only недостаточен: backend должен иметь возможность восстановить токен. Использовать encrypted database field/secret manager, не отдавать секрет в списке нод, не писать в access/application logs. Показывать оператору для копирования при выдаче; UI панели и его RBAC реализуются в backend панели отдельно.

Готовый генератор Python, запускаемый **на основном сервере** после установки/клонирования RemnaWatch:

```bash
cd /opt/remnawatch
python3 -m remnawatch.auth issue-token
```

Он выводит JSON `{ "node_id": "...", "token": "..." }`. Для замены токена существующей ноды:

```bash
python3 -m remnawatch.auth issue-token --node-id EXISTING_LOWERCASE_UUID
```

Библиотечный вызов для Python backend:

```python
from remnawatch.auth import generate_node_credentials

credentials = generate_node_credentials()  # либо generate_node_credentials(existing_uuid)
# Сохранить credentials["node_id"] и credentials["token"] в записи ноды.
# Показать token оператору только в защищённом окне выдачи.
```

Тот же алгоритм для Node.js backend без сторонних зависимостей:

```javascript
import { randomBytes, randomUUID } from 'node:crypto';

export function issueNodeCredentials(nodeId = randomUUID()) {
  const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!canonicalUuid.test(nodeId) || nodeId === '00000000-0000-0000-0000-000000000000') {
    throw new Error('nodeId must be a nonzero canonical lowercase UUID');
  }
  const secret = randomBytes(32).toString('base64url');
  return { node_id: nodeId, token: `rw_node_v1.${nodeId}.${secret}` };
}
```

JWT и общий signing key здесь не используются. Нода доверяет **только полному токену из своего конфига**, а не любому токену с похожим UUID/форматом. Уникальный секрет каждой ноды ограничивает последствия компрометации одной ноды. Основной сервер не должен выдавать один token нескольким нодам.

## Конфигурация ноды

В `/etc/remnawatch/config.json` добавить/изменить секцию:

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "auth": {
    "token": "ВСТАВЬТЕ_ПОЛНЫЙ_ТОКЕН_ОСНОВНОГО_СЕРВЕРА"
  }
}
```

Это фрагмент: остальные параметры доступа к логам, mapping пользователей, управления и защиты ресурсов сохраняются. UUID извлекается из токена; дополнительно можно вставить `auth.node_id`, но при несовпадении с токеном запуск будет отклонён. Identity API-ноды не меняет существующий node_id исторических collectors автоматически. Для новой однонодовой установки рекомендуется использовать тот же node_id в users/access_logs/network; при изменении старых collectors учитывайте существующие cursors и mapping, не переименовывайте их без плана миграции.

Защитить файл и перезапустить службу:

```bash
sudo chmod 600 /etc/remnawatch/config.json
sudo systemctl restart remnawatch
```

Для новой установки достаточно секрета в JSON; secrets.env не обязателен. Обновлённый deploy/remnawatch.service использует optional EnvironmentFile. Если на сервере ещё установлен старый unit с обязательным secrets.env, замените его файлом из deploy/, выполните daemon-reload и restart. При необходимости оставьте существующий env-файл: непустой auth.token имеет приоритет над REMNAWATCH_API_TOKEN. Неверный непустой токен в JSON не подменяется env-токеном незаметно: startup завершается ошибкой до открытия/очистки истории.

Для старых установок без auth или с auth.token="" остаётся fallback REMNAWATCH_API_TOKEN, включая прежний обычный Bearer token длиной 32..512 printable ASCII символов. Это legacy режим, у него нет node_id. Миграция не включает управление сервером: management.enabled остаётся отдельным opt-in.

## Проверка подключения с основного сервера

Backend делает запрос:

```http
GET /v1/node HTTP/1.1
Authorization: Bearer <полный токен записи этой ноды>
```

Ожидаемый ответ 200:

```json
{
  "node_id": "59cf9ada-b568-4513-8582-923576b05ef3",
  "authentication": "node_token_v1",
  "service": "remnawatch",
  "api_version": "v1"
}
```

Основной сервер проверяет service, api_version, authentication и точное совпадение node_id со своей записью, затем отмечает ноду доступной. При timeout/401/mismatch — ошибка подключения; не заменять автоматически ожидаемый UUID значением из ответа. Отдельно опросить /v1/server для ресурсов, alerts и capabilities. В legacy режиме /v1/node возвращает authentication=legacy_bearer, node_id=null; его нельзя считать новым paired node без миграции токена.

Все запросы доменной истории и управления используют тот же Bearer header. Секрет не принимается из query, cookie, body или двойного Authorization header. Ответы не раскрывают token и имеют Cache-Control: no-store. Токен даёт полный доступ к API своей ноды, включая управление при enabled=true: административные права конечного пользователя проверяет backend панели.

Для прямого доступа по IP используйте UFW allowlist основного сервера и нужный host/port. Токен сам по себе не открывает firewall и не шифрует HTTP. Через публичный интернет нужен HTTPS/TLS proxy или защищённый VPN-канал; исходный HTTP server TLS автоматически не включает. По умолчанию адрес всё ещё 127.0.0.1, чтобы обновление не открыло порт существующим установкам.

## Ротация и отзыв

Токен долгоживущий, без встроенного expiry. Основной сервер генерирует новый secret для прежнего node_id; оператор заменяет auth.token на ноде, перезапускает её, основной сервер начинает использовать новый secret и проверяет /v1/node. Старый токен нода больше не принимает. Простое удаление записи/секрета только на основном сервере **не отзывает** ранее установленный токен ноды: для отзыва измените конфиг самой ноды либо закройте доступ firewall/остановите сервис. Одновременного grace period для двух токенов нет.

Не храните production config/tokens в публичном GitHub. config.example.json содержит пустой auth.token; генератор запускается оператором/основным backend, не при старте агента. Генератор намеренно выводит новый секрет для provisioning, поэтому не запускайте его вывод в общий CI/job log.
