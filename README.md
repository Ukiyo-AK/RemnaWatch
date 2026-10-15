# RemnaWatch

Пассивный Domain Activity Monitoring для Xray/Remnawave Node: история пользователей, топ доменов, временная аналитика и REST API. Python 3.11+, без runtime-зависимостей.

Скопируйте `config.example.json` в `config.json`, задайте node/inbound/Xray-email → Remnawave ID и путь существующего access.log. На основном сервере выполните `python3 -m remnawatch.auth issue-token`, вставьте выданный token в `auth.token` конфига ноды и запустите:

```sh
python -m remnawatch --config config.json
python -m unittest discover -s tests -v
```

API по умолчанию: `127.0.0.1:8080`, отдельный Bearer token для каждой ноды. Проверка подключения: `GET /v1/node`. Старый REMNAWATCH_API_TOKEN остаётся fallback при пустом/отсутствующем auth.token. Генерация для Python/Node.js backend и настройка: [NODE_ENROLLMENT.md](NODE_ENROLLMENT.md). Детальные события 7 дней, агрегаты 30; сроки и отключение/удаление настраиваются.

См. [ARCHITECTURE.md](ARCHITECTURE.md), [API.md](API.md), [PROJECT_MAP.md](PROJECT_MAP.md), [INTEGRATION_FOR_PANEL_AGENT.md](INTEGRATION_FOR_PANEL_AGENT.md), [LIMITATIONS.md](LIMITATIONS.md) и [openapi.yaml](openapi.yaml).

Добавлены характеристики/нагрузка сервера, memory/disk alerts, ранняя очистка истории/rotated logs и Linux управление: OS reboot, Xray/node restart/update, OS kernel upgrade, TX/RX limits, OOM protection. Управление по умолчанию выключено; действия поддерживают dry-run и журнал jobs. Полная инструкция и примеры: [SERVER_MANAGEMENT.md](SERVER_MANAGEMENT.md), systemd/sysctl примеры — [deploy/](deploy/).

Модуль не изменяет Xray и не перехватывает payload. Полнота доменов ограничена источниками; универсальный экспорт sniffed domain в исследованном штатном Xray отсутствует. Соединение не означает посещение веб-страницы.

