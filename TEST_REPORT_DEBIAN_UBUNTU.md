# Совместимость Debian/Ubuntu и подготовка зависимостей

Дата: 2026-10-20. Дополнение к [TEST_REPORT_INSTALLATION.md](TEST_REPORT_INSTALLATION.md).
Изменения находятся в рабочем дереве; публикация релиза и замена production
агента не выполнялись.

## Что исправлено

1. Убран прежний отказ для всех версий кроме Debian 12 и Ubuntu 22.04/24.04.
   Матрица принимает Debian 11/12/13 и Ubuntu LTS 20.04/22.04/24.04/26.04,
   amd64/arm64, systemd PID 1. Остальные релизы не принимаются наугад.
2. `deploy/install.sh` запускается без Python. После проверки платформы при
   `--apply` или `--install-deps` ставит недостающие distro dependencies.
   Наличие команды `python`, UFW, Docker или Caddy для установки агента не нужно.
3. `dependencies.py` проверяет dpkg status и реальные tools/modules/CA bundle,
   устанавливает только фиксированный набор недостающих пакетов. Healthy повтор
   не вызывает APT install. Конфликт upgrade/remove останавливается до транзакции;
   конфиги сохраняются, needrestart приостановлен, lock-файлы не удаляются.
4. Python 3.8 compatibility: отложенные type annotations, нет вызовов новых
   `str.removeprefix/removesuffix`, dict merging работает на 3.8. Действительные
   ошибки найдены прогоном Ubuntu 20.04, а не только статическим анализом.
5. Старый SQLite требует conflict target в UPSERT. Указаны существующие PK
   columns; схема и смысл dedup/агрегации не изменились. Устранён реальный
   `near UPDATE: syntax error` на системном SQLite Ubuntu 20.04.
6. APT ошибки DNS/lock/disk/repository/trust разделены. Update с частично
   недоступными индексами не используется как успешный. URL/proxy credentials
   и raw package output не попадают в сообщения установщика.
7. `.gitattributes` фиксирует LF для shell-файлов при checkout из Windows.

## Прогоны текущего набора

```text
python -m unittest discover -s tests -q
python -m compileall -q remnawatch tests
ruff check remnawatch tests --select E9,F63,F7,F82 --target-version py38
ruff check remnawatch/dependencies.py tests/test_dependencies.py --select F --target-version py38
python tests/check_openapi.py
sh -n deploy/install.sh
shellcheck -s sh deploy/install.sh
```

| Среда | Результат |
|---|---|
| Windows / Python 3.13 | 133 tests, OK, 6 skipped; финальный повтор 15.845 s |
| Реальный Ubuntu 24.04 amd64 / Python 3.12.3 | 133 tests, OK, без пропусков, 16.150 s |
| Ubuntu 20.04 / Python 3.8.10 / SQLite 3.31.1 | Bootstrap и повтор прошли; 133 tests, OK, без пропусков, 23.819 s |
| Ubuntu 22.04 / Python 3.10.12 / SQLite 3.37.2 | Bootstrap и повтор прошли; 133 tests, OK, без пропусков, 22.732 s |
| Ubuntu 24.04 / Python 3.12.3 / SQLite 3.45.1 | Bootstrap и повтор прошли; 133 tests, OK, без пропусков, 20.472 s |
| Debian 12 / Python 3.11.2 / SQLite 3.40.1 | Bootstrap и повтор прошли; финальный shell + полный повтор 133 tests, OK, без пропусков, 22.070 s |
| Debian 13 / Python 3.13.5 / SQLite 3.46.1 | Bootstrap и повтор прошли; 133 tests, OK, без пропусков, 20.143 s |
| Ubuntu 26.04 / Python 3.14.4 / SQLite 3.46.1 | Bootstrap и повтор прошли; 133 tests, OK, без пропусков, 20.433 s; ResourceWarning от тестовых HTTPError fixtures |
| Чистый Debian 11 | Подготовительный прогон: пакеты security mirror возвращают 404, установка зависимостей отказала; зеркала/подписи не менялись |
| Debian 11 / официальный Python 3.9.23 image / SQLite 3.34.1 | 133 tests, OK, без пропусков, 25.794 s; runtime без APT bootstrap |

Шесть Windows skips: native inet_diag, POSIX atomic symlink replacement, FIFO,
IPv6 (WinError 10013), два POSIX shell tests. На Linux эти проверки исполняются.
Предварительный неуспешный прогон Ubuntu 20.04 исправлен; это не зелёный результат.
На Debian 12 полный suite и bootstrap прошли, но общий exit code первого прогона
был 1 из-за замечаний ShellCheck. Shell-условия переписаны явно: повторный
ShellCheck 0.9.0 и `sh -n` прошли без замечаний; 12 dependency tests прошли.
Изменения не затрагивают пакетную политику. SHA256 финального shell-файла
`ba9cc246933d13ac7ac2ea6a438e3514f0b31fd835297ec01b95957f4eabf4aa`;
совпадение исходника Windows и Linux подтверждено.
После shell-правки на Debian 12 заново прошли bootstrap с отсутствующим Python,
идемпотентный повтор и полный suite (exit 0).

## Как проверяется bootstrap

Каждый контейнер ограничен `--cpus=0.5 --memory=384m --pids-limit=128`,
`--security-opt=no-new-privileges`, исходники mounted read-only. В чистом base
image Python отсутствует; shell bootstrap действительно ставит пакеты, затем
повторный запуск проверяется на отсутствие повторной установки.

В отдельной копии внутри disposable контейнера **только пути проверки PID 1**
заменены fixture-файлами: это позволяет исполнить пакетный этап в обычном
Docker без запуска systemd и без privileged containers. Этот bypass не входит
в поставку. После этого весь suite запускается с неизменённого read-only
исходника, а настоящий shell entry point обязан отказать без systemd.
Контейнерный тест не сертифицирует установку unit на чистой systemd VM.
Для этой host fixture пакет systemd предварительно устанавливается тестовым
стендом, как на настоящем systemd-хосте; Python при старте bootstrap отсутствует.
Эта подготовка контейнера не является частью рабочего installer и не меняет
пакеты production-хоста. Неподготовленные base images без systemd/PID 1
отвергаются; их конфликты установки init не означают поддержку container install.

Debian 11 security mirror возвращал HTTP 404 на пакеты python3.9/openssl/CA.
Installer сообщает `dependencies_repository_unavailable`. Автоматическое
переключение на архивы, снятие TLS/GPG проверки или обновление дистрибутива не
используется. Для Debian 11 нужны действующие подписанные repositories,
при необходимости vendor ELTS; наличие подходящего Python само по себе не
исправляет APT sources. Поддержка безопасности старых ОС остаётся у поставщика:
[Debian releases](https://www.debian.org/releases/),
[Ubuntu releases](https://ubuntu.com/project/docs/release-team/list-of-releases/).

## Остаточные границы

После прогонов `remnawatch.service` остался active, production RemnaNode running
с прежним immutable image ID. Host APT, конфигурация и службы Node/Xray не
менялись. Тестовых контейнеров не осталось; временный каталог исходников
`/tmp/remnawatch-os-deps-m481m8s2` удалён после проверки абсолютного пути.

Реальные arm64 и чистые systemd VM этой расширенной матрицы недоступны.
Автоматически не устанавливаются Docker Engine, Caddy, UFW: они необязательны
для core agent, а их установка могла бы изменить сетевой доступ или службы.
History/probe по-прежнему проверяются отдельно. Старый скачанный clipboard
installer ALTLINK не обновляется от появления этого файла: используйте новый
shell entry point или обновлённый генератор после публикации проверенного релиза.

Команды и параметры: [INSTALLATION.md](INSTALLATION.md).
