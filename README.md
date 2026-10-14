# RemnaWatch

Пассивный Domain Activity Monitoring для Xray/Remnawave Node: история пользователей, топ доменов, временная аналитика и REST API. Python 3.11+, без runtime-зависимостей.

Скопируйте `config.example.json` в `config.json`, задайте node/inbound/Xray-email → Remnawave ID и путь существующего access.log. Установите секрет `REMNAWATCH_API_TOKEN` (минимум 32 символа), запустите:

```sh
python -m remnawatch --config config.json
python -m unittest discover -s tests -v
```

API по умолчанию: `127.0.0.1:8080`, общий Bearer token. Детальные события 7 дней, агрегаты 30; сроки и отключение/удаление настраиваются.

См. [ARCHITECTURE.md](ARCHITECTURE.md), [API.md](API.md), [PROJECT_MAP.md](PROJECT_MAP.md), [INTEGRATION_FOR_PANEL_AGENT.md](INTEGRATION_FOR_PANEL_AGENT.md), [LIMITATIONS.md](LIMITATIONS.md) и [openapi.yaml](openapi.yaml).

Модуль не изменяет Xray и не перехватывает payload. Полнота доменов ограничена источниками; универсальный экспорт sniffed domain в исследованном штатном Xray отсутствует. Соединение не означает посещение веб-страницы.

