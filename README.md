# RED-O

**RED-O** - система обнаружения подозрительной активности в работающих контейнерах Kubernetes на базе телеметрии **Tetragon/eBPF**.

Система собирает события запуска процессов, доступа к файлам, сетевых соединений и действий с Kubernetes API; нормализует их; применяет сигнатурные и корреляционные правила; сохраняет события и предупреждения в JSONL. Независимый Ingester записывает данные в ClickHouse, а Web UI предоставляет доступ к событиям и алертам. Для лабораторных экспериментов предусмотрены метрики, проверка правил и инструменты оценки качества обнаружения.

## Возможности

- **Более 20 правил детектирования:** конфигурация в [`configs/rules.json`](configs/rules.json) и [`configs/correlations.json`](configs/correlations.json).
- **Источники:** Tetragon/eBPF, Kubernetes Audit (опционально), JSONL для офлайн-анализа.
- **Нормализация и корреляция:** унифицированные события и работа с несколькими сенсорами.
- **Хранение:** JSONL с ротацией; ClickHouse и отдельный Ingester; Web может работать по текущим JSONL без ClickHouse.
- **Web:** просмотр алертов, событий, состояния агентов и метрик.
- **Диагностика и тесты:** `doctor`, метрики Detector, синтетический Replay всех правил, контролируемые Live-тесты в Kubernetes и Quality Benchmark на размеченных действиях.
- **Контекстный анализ (опционально):** рекомендательные пометки к алертам без изменения исходных сигналов и их severity.

## Быстрый старт

### Требования

- Linux **amd64** или **arm64**, установленный **Go 1.23+** для локальной сборки.
- Доступ к Kubernetes через `kubectl`, работающий Tetragon и права на чтение Pod и `exec` в Pod Tetragon.
- Python **3.9+** - для расширенных тестов в `tools/`; обычный запуск Detector/Web от Python не зависит.

### 1. Сборка

```bash
cd RED-O
./build.sh
# То же самое вручную:
# mkdir -p bin && go build -o bin/red-o ./cmd/red-o
```

### 2. Запуск

```bash
./bin/red-o up
./bin/red-o status
./bin/red-o doctor -require-sensors -kubernetes
```

При первом запуске `up` находит готовые Pod Tetragon в Kubernetes, создаёт локальный файл `configs/sensors.json`, настраивает Detector и Web, а также создаёт приватный `.env` со случайным паролем администратора. Если обнаружен читаемый локальный Audit log, добавляет Audit-сенсор. При доступном ClickHouse запускается Ingester; иначе Web читает недавние JSONL-события. 
**`up` не устанавливает Tetragon, TracingPolicy или Kubernetes Audit.**

### 3. Web UI

```bash
./bin/red-o credentials
```

- URL на сервере: **http://127.0.0.1:8088**
- Логин: `admin`
- Пароль: индивидуальный пароль из `./bin/red-o credentials`

Для открытия с рабочего компьютера используйте SSH-туннель:

```bash
ssh -L 8088:127.0.0.1:8088 USER@SERVER_IP
```

### 4. Управление

```bash
./bin/red-o status                    # состояние компонентов
./bin/red-o doctor -require-sensors -kubernetes -clickhouse
./bin/red-o detector logs
./bin/red-o ingester logs
./bin/red-o web logs
./bin/red-o credentials rotate       # смена пароля, затем перезапустите Web
./bin/red-o down                     # остановка управляемых процессов
```

Если Pod Tetragon изменились, после остановки можно обновить обнаруженные сенсоры:

```bash
./bin/red-o down
./bin/red-o setup -refresh-sensors
./bin/red-o up
```

Подробности: [установка и настройка](docs/QUICKSTART.md).

## Подготовка телеметрии и лабораторного namespace

Для правил, использующих файловые и сетевые kprobe-события, необходимо **отдельно** установить соответствующие Tetragon TracingPolicy. Пример для контролируемого стенда:

```bash
kubectl apply -f deployments/tracing-policies/network-connect.yaml
kubectl apply -f deployments/tracing-policies/file-access.yaml
kubectl apply -f deployments/tracing-policies/serviceaccount-token.yaml
kubectl apply -f deployments/tracing-policies/privilege-capset.yaml
kubectl apply -f deployments/tracing-policies/runtime-sockets.yaml
kubectl get tracingpolicies
```

Политики затрагивают наблюдение на уровне ядра и могут увеличить объём телеметрии.

Для теста правил, создайте лабораторный namespace:

```bash
kubectl create namespace security-lab --dry-run=client -o yaml | kubectl apply -f -
```

Стандартные правила предназначены для лабораторного `security-lab`. Детектор может собирать и прочие события; это не означает, что все они формируют алерты.

## Проверка всех правил

В проект включён единый скрипт проверки правил, не требующий сторонних Python-библиотек:

**Replay** - все правила, положительный и отрицательный синтетический пример на каждое. Запускается через собранный Detector, но **не проверяет реальную eBPF-телеметрию**:

```bash
python3 tools/check_rules.py --project . --mode replay
```

**Live** - контролируемые действия в `security-lab`, реальные события Tetragon/Audit, строгая привязка алертов к `event_id`:

```bash
python3 tools/check_rules.py --project . --mode live --execute --wait-seconds 15
```

Для сетевых тестов с TCP-попытками к внешнему `1.1.1.1` добавьте **явное разрешение**:

```bash
python3 tools/check_rules.py --project . --mode live --execute \
  --allow-external --wait-seconds 15
```

Проверка конкретных правил:

```bash
python3 tools/check_rules.py --project . --mode live --execute \
  --only R011,R017 --wait-seconds 15
```

Результаты сохраняются в `benchmark-results/all-rules-<UTC>/` (`replay/summary.csv`, `live/summary.csv`, JSON-диагностика каждого правила). Live создаёт временные Pod/Service и удаляет их по завершении. Режим `--execute` обязателен; для внешних соединений отдельно требуется `--allow-external`.

**Интерпретация:** `PASS` означает обнаружение тестового индикатора, `SKIP` - отсутствие предпосылок или отдельного безопасного сценария, `FAIL_TELEMETRY` - недоставленную телеметрию, `FAIL_PRECONDITION` - недействительную цепочку и `FAIL_RULE` - отсутствие ожидаемого алерта при наличии соответствующих событий. 

Детали и границы результатов: [проверка правил](docs/TESTING.md).

## Тесты, качество обнаружения и производительность

```bash
go test -count=1 ./...
go vet ./...
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/release_smoke.py --project .
./bin/red-o benchmark quality run -runs 1 -output benchmark-results/quality-synthetic
```

Синтетические наборы показывают корректность логики и воспроизводимость, **но не измеряют реальную Precision/Recall на атакующих действиях**. Для этого применяйте размеченные Live-испытания, независимый журнал действий, `event_id` и `benchmark quality evaluate`; сравнение контекста с базовыми сигналами - через `benchmark quality compare`. Подробности: [протокол измерений](docs/TESTING.md).

## Архитектура проекта

```text
Tetragon/eBPF ──────┐
Kubernetes Audit ────┼──► Multi-Sensor Collector ─► Normalizer
JSONL replay ───────┘                            │
                                                 ▼
                                     Event-Time Merger
                                                 │
                                    Rule Engine + Correlator
                                                 │
                                             JSONL
                                          events/alerts
                                                 │
                                    ┌────────────┴────────────┐
                                    ▼                         ▼
                             Independent Ingester       Web JSONL fallback
                                    │
                                    ▼
                                ClickHouse ───────────────► Web UI
```

Исходники: `cmd/` (CLI и процессы), `internal/` (ядро системы), `configs/` (правила и образцы настроек), `deployments/` (ClickHouse, Kubernetes Audit, TracingPolicy), `tools/` (проверки и бенчмарки), `tests/` (фикстуры и Go-тесты), `docs/` (руководства). См. [архитектуру](docs/ARCHITECTURE.md).