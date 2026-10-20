# RemnaWatch

Пассивный Domain Activity Monitoring для Xray/Remnawave Node: история пользователей, топ доменов, временная аналитика и REST API. Python 3.8+, без сторонних Python runtime-зависимостей. Запуск установщика: `sudo sh deploy/install.sh --install-deps` для подготовки системы; `--apply` автоматически устанавливает недостающие зависимости. Поддерживаемые версии Debian/Ubuntu перечислены в [COMPATIBILITY.md](COMPATIBILITY.md).

Установка, доверенный digest, изолированный venv, обновление с откатом, история и HTTPS probe: [INSTALLATION.md](INSTALLATION.md). Матрица: [COMPATIBILITY.md](COMPATIBILITY.md), результаты: [TEST_REPORT_INSTALLATION.md](TEST_REPORT_INSTALLATION.md). История в новом примере выключена; её включают после проверки реального лога и UUID mapping. Для разработки скопируйте `config.example.json` в `config.json`, задайте локальный путь БД и auth. На основном сервере выполните `python3 -m remnawatch.auth issue-token`, вставьте выданный token в `auth.token` конфига ноды и запустите:

```sh
python -m remnawatch --config config.json
python -m unittest discover -s tests -v
```

API по умолчанию: `127.0.0.1:8080`, отдельный Bearer token для каждой ноды. Проверка подключения: `GET /v1/node`. Старый REMNAWATCH_API_TOKEN остаётся fallback при пустом/отсутствующем auth.token. Генерация для Python/Node.js backend и настройка: [NODE_ENROLLMENT.md](NODE_ENROLLMENT.md). Детальные события 7 дней, агрегаты 30; сроки и отключение/удаление настраиваются.

См. [ARCHITECTURE.md](ARCHITECTURE.md), [API.md](API.md), [PROJECT_MAP.md](PROJECT_MAP.md), [INTEGRATION_FOR_PANEL_AGENT.md](INTEGRATION_FOR_PANEL_AGENT.md), [LIMITATIONS.md](LIMITATIONS.md) и [openapi.yaml](openapi.yaml).

Добавлены характеристики/нагрузка сервера, memory/disk alerts, ранняя очистка истории/rotated logs и Linux управление: OS reboot, Xray/node restart/update, OS kernel upgrade, TX/RX limits, OOM protection. Управление по умолчанию выключено; действия поддерживают dry-run и журнал jobs. Полная инструкция и примеры: [SERVER_MANAGEMENT.md](SERVER_MANAGEMENT.md), systemd/sysctl примеры — [deploy/](deploy/).

Диагностика источников: `GET /v1/capabilities`, `GET /v1/diagnostics/sources`, `GET /v1/network/interfaces`. Optional live adapter `linux_inet_diag` выключен по умолчанию и показывает **сокеты ОС**, без вымышленной привязки к пользователям Xray. Снимки/changes имеют stable ID, bounded polling и явный resync. Настройка, compatibility matrix и rollback: [LIVE_DIAGNOSTICS.md](LIVE_DIAGNOSTICS.md). Реальные Linux и synthetic результаты: [TEST_REPORT_LIVE.md](TEST_REPORT_LIVE.md).

Модуль не изменяет Xray и не перехватывает payload. Полнота доменов ограничена источниками; универсальный экспорт sniffed domain в исследованном штатном Xray отсутствует. Соединение не означает посещение веб-страницы.

