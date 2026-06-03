# Xray Manager

Web UI для управления Xray Core и mixed proxy. Интерфейс похож на v2rayN-lite: VLESS-профили, подписки, выбор активного узла, проверка задержки, routing presets, direct-домены, логи и статус core.

## Возможности

- Импорт одной или нескольких `vless://` ссылок.
- Подписки с обновлением профилей.
- Выбор активного профиля одной кнопкой.
- Mixed proxy: SOCKS/HTTP на одном порту, UDP, sniffing, optional auth.
- Проверка задержки одного профиля или всех профилей.
- Автовыбор самого быстрого профиля после проверки задержек.
- Исключение отдельных профилей из автовыбора.
- Фоновый автопилот: обновление подписок, проверка задержек и переключение по расписанию.
- Failover активного профиля: частая проверка текущего узла и переключение после серии ошибок.
- Массовое выделение и удаление профилей.
- Routing modes: global, bypass RU, bypass private, direct, block.
- Direct-домены, включая IDN вроде `*.рф`.
- HTTPS UI с self-signed сертификатом из коробки.
- Persistent login session с опцией "Запомнить вход".
- Docker mode: UI и Xray Core запускаются в одном контейнере.

## Быстрый старт через Docker Compose

На Debian не ставьте пакет `docker`: это не Docker Engine. Нужен Docker с Compose plugin.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

```bash
git clone https://github.com/nepushkin00/xray-manager.git
cd xray-manager
printf 'PUBLIC_IP=%s\n' 'SERVER_IP' > .env
docker compose up -d --build
```

Открыть UI:

```text
https://SERVER_IP:8443/
```

Браузер предупредит о self-signed сертификате. Это нормально для первого запуска.

Посмотреть сгенерированные креды:

```bash
docker compose exec xray-manager cat /etc/xray-manager/credentials.txt
```

Mixed proxy будет доступен на хосте:

```text
HTTP/SOCKS: SERVER_IP:10808
```

Если нужно слушать стандартные 80/443, поменяйте ports в `docker-compose.yml`:

```yaml
ports:
  - "80:80"
  - "443:443"
  - "10808:10808"
```

После изменения портов:

```bash
docker compose up -d
```

## Переменные окружения

| Переменная | Значение по умолчанию | Описание |
| --- | --- | --- |
| `MANAGER_MODE` | `docker` в Dockerfile | `docker` запускает Xray как child-process, `systemd` управляет systemd-сервисом |
| `PUBLIC_IP` | `127.0.0.1` | IP/host, который пишется в credentials и self-signed cert CN/SAN |
| `HTTP_PORT` | `80` | HTTP порт внутри контейнера |
| `HTTPS_PORT` | `443` | HTTPS порт внутри контейнера |
| `XRAY_BIN` | `/opt/xray-codex/xray` | Путь к Xray binary |
| `XRAY_CONFIG` | `/etc/xray-codex/config.json` | Генерируемый Xray config |
| `STATE_PATH` | `/var/lib/xray-manager/state.json` | State UI |
| `LATENCY_TEST_CONCURRENCY` | `6` | Сколько профилей проверять параллельно в "Проверить все" |

## Данные и бэкапы

В Docker Compose используются named volumes:

- `/etc/xray-manager`: secrets, TLS certs, credentials.
- `/etc/xray-codex`: текущий Xray config.
- `/var/lib/xray-manager`: profiles, subscriptions, sessions.
- `/var/log/xray-codex`: access/error logs.
- `/var/backups/xray-codex`: backup config перед apply.

Перед каждым применением manager:

1. генерирует новый JSON;
2. валидирует его через `xray run -test`;
3. сохраняет backup старого config;
4. перезапускает Xray.

## Автовыбор

В настройках есть блок `Автовыбор`. Он может:

- обновлять подписки;
- проверять задержки параллельно;
- выбирать профиль с минимальной успешной задержкой;
- применять выбранный профиль к mixed proxy.
- отдельно проверять активный профиль через watchdog и переключаться при падении.

Профили с флагом `Исключить из автовыбора` не участвуют в выборе. Это удобно для стран или узлов, на которые нельзя переключаться автоматически, например `RU`.

## Локальная разработка

```bash
npm test
node --check server.js
node --check public/app.js
```

Запуск без Docker для разработки:

```bash
MANAGER_MODE=docker \
PUBLIC_IP=127.0.0.1 \
HTTP_PORT=8080 \
HTTPS_PORT=8443 \
XRAY_BIN=/path/to/xray \
node server.js
```

## Systemd установка

В репозитории есть unit-файлы:

- `systemd/xray-codex.service`
- `systemd/xray-manager.service`

Для systemd-режима нужны:

- Xray binary и assets в `/opt/xray-codex`;
- приложение в `/opt/xray-manager`;
- конфиги и state в `/etc/xray-*`, `/var/lib/xray-manager`, `/var/log/xray-codex`;
- `MANAGER_MODE=systemd` или отсутствие `MANAGER_MODE`.

Docker-режим обычно проще и рекомендуется для новых установок.

Минимальный systemd-вариант:

```bash
sudo mkdir -p /opt/xray-manager /etc/xray-manager
sudo cp -a . /opt/xray-manager/
printf 'PUBLIC_IP=%s\nMANAGER_MODE=systemd\n' 'SERVER_IP' | sudo tee /etc/xray-manager/manager.env
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xray-codex.service xray-manager.service
```

Перед systemd-запуском установите Node.js 22+ и Xray Core в `/opt/xray-codex`. Unit-файл ожидает бинарник `/opt/xray-codex/xray` и assets в той же директории.

Проверка:

```bash
systemctl status xray-manager xray-codex
journalctl -u xray-manager -n 100 --no-pager
```

## Безопасность

- UI пароль хранится как `scrypt` hash.
- Session cookie: `HttpOnly`, `Secure`, `SameSite=Lax`.
- Запомненный вход хранится в `/var/lib/xray-manager/sessions.json`.
- Не публикуйте `credentials.txt`, `secrets.json`, state и Docker volumes.
