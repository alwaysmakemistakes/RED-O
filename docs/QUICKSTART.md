# Развёртывание RED-O

## Подготовка

1. Linux amd64/arm64, Go 1.23+, доступ к Kubernetes/K3s, готовые Pod Tetragon и `kubectl` (либо `k3s kubectl`).
2. У пользователя должны быть права на список Pod и выполнение `kubectl exec` в Tetragon; Docker и ClickHouse необязательны.
3. Python 3.9+ нужен для тестового инструментария.
4. Исходники можно распаковать в произвольный каталог. Готовых бинарников в архиве нет.

```bash
cd RED-O
./build.sh
./bin/red-o up
./bin/red-o status
./bin/red-o doctor -require-sensors -kubernetes
```

На первом запуске создаются `configs/sensors.json`, `data/` и приватный `.env`. Если локальный Kubernetes Audit log доступен, автоконфигурация добавит второй сенсор. В противном случае RED-O собирает Tetragon без API Audit. Правило R016 требует Audit.

## Web и безопасность

`./bin/red-o credentials` показывает учётную запись, созданную локально при настройке. Web слушает `127.0.0.1:8088`. Для удалённого просмотра:

```bash
ssh -L 8088:127.0.0.1:8088 USER@SERVER_IP
```

Не пробрасывайте порт 8088 в Интернет без TLS/VPN. `./bin/red-o credentials rotate` меняет Web-пароль; затем выполните `./bin/red-o web stop && ./bin/red-o web start`. Не пересылайте `.env` и вывод `credentials` в отчёты.

## Хранилище

По умолчанию `./bin/red-o up` выбирает ClickHouse, если локальный HTTP-пинг доступен, иначе JSONL-only Web. Для отдельного локального ClickHouse при наличии Docker Compose можно использовать:

```bash
docker compose --env-file .env -f deployments/clickhouse/compose.yaml up -d
./bin/red-o down
./bin/red-o up
```

В режиме ClickHouse Detector пишет JSONL; независимый Ingester импортирует его в ClickHouse; Web читает базу. Не запускайте два Ingester с разными checkpoint одновременно. В JSONL-режиме доступна только текущая ограниченная история.

## TracingPolicy и Audit

Разрешённый лабораторный кластер может использовать YAML из `deployments/tracing-policies/`:

```bash
kubectl apply -f deployments/tracing-policies/network-connect.yaml
kubectl apply -f deployments/tracing-policies/file-access.yaml
kubectl apply -f deployments/tracing-policies/serviceaccount-token.yaml
kubectl apply -f deployments/tracing-policies/privilege-capset.yaml
kubectl apply -f deployments/tracing-policies/runtime-sockets.yaml
kubectl get tracingpolicies
```

Изучите каждую политику перед применением: не все kprobe и пути доступны на каждом ядре; широкие политики могут увеличивать поток событий. Для проверки загрузки найдите Ready Pod Tetragon (`kubectl -n kube-system get pods`) и запустите `tetra tracingpolicy list` в его контейнере.

Kubernetes Audit не включается автоматически; для K3s имеется пример `deployments/k3s-audit/policy.yaml`. Подключение журнала к control plane зависит от административной конфигурации конкретного кластера. `doctor` проверяет только доступность и конфигурацию, но не подтверждает end-to-end отправку событий.

## Проверка и управление

```bash
./bin/red-o doctor -require-sensors -kubernetes -clickhouse
curl -fsS http://127.0.0.1:9095/metrics | grep '^redo_'
wc -l data/live-events.jsonl data/live-alerts.jsonl
./bin/red-o status
./bin/red-o down
```

Тестовые правила по умолчанию ориентированы на namespace `security-lab`; при необходимости создайте его отдельно. Для повторного обнаружения Pod Tetragon остановите систему и выполните `./bin/red-o setup -refresh-sensors`, затем `./bin/red-o up`.

## Использование на уже работающей VM

Не распаковывайте новую копию поверх каталога с работающим RED-O. Остановите прежние управляемые процессы, отдельно сохраните `.env`, `configs/sensors.json`, `data/` (включая checkpoint Ingester), реальные контекстные политики и настройки ClickHouse. Новую исходную копию соберите в **отдельном каталоге**. При переносе конфигурации проверьте права `.env` (`0600`), пути и ownership; не запускайте два Detector/Ingester параллельно на общих данных. Никогда не удаляйте хранилище ClickHouse ради обновления исходников.
