# Архитектура RED-O

## Компоненты

- **Collector:** Tetragon Pod (события через `kubectl exec`) и необязательный локальный Kubernetes Audit log; возможен JSONL replay.
- **Normalizer:** перевод форматов источников в события `process.exec`, `process.exit`, `file.access`, `network.connect`, `kernel.hook`, `k8s.audit` с полями origin и Kubernetes context.
- **Event-Time Merger:** упорядочивание разных сенсоров с ограниченным ожиданием; есть метрики поздних, принудительно выданных и ожидающих событий.
- **Rule Engine:** 17 сигнатурных правил из `configs/rules.json`.
- **Correlator:** 5 правил из `configs/correlations.json`, связывающих события по процессу, контейнеру и времени. Алерты содержат `related_event_ids`.
- **JSONL storage:** отдельные журналы событий, предупреждений и сырых записей с ротацией.
- **Ingester:** отдельный процесс импортирования JSONL и метрик в ClickHouse; свои checkpoint и наблюдение за состоянием хранилища.
- **Web UI:** просмотр алертов, событий и метрик через ClickHouse; при его отсутствии — ограниченный read-only JSONL fallback.
- **Context Policy:** необязательная рекомендательная аннотация на основании лабораторных approval-политик; исходные алерты не подавляются и `severity` не меняется.

## Потоки и границы доверия

```text
Kubernetes API (Audit) ─┐
Tetragon/eBPF ───────────┼─► Normalizer ─► Event-Time Merger
JSONL (offline) ─────────┘                         │
                                                   ▼
                                          Rules / Correlator
                                                   │
                                        JSONL events + alerts
                                                   │
                                            Independent Ingester
                                                   │
                                                ClickHouse
                                                   │
                                                 Web UI
```

Для сохранения исходных данных Web не импортирует JSONL самостоятельно. Рабочая директория `data/` не предназначена для Git, исходный архив не включает секреты. Важны `event_id`, `related_event_ids`, `detected_at` и `emitted_at`: они позволяют оценивать покрытие и задержки отдельно от времени события в ядре.

## Ограничения наблюдения

Срабатывание сигнатуры — индикатор, не факт успешной атаки. Отсутствие сигналов может означать недостаточное покрытие TracingPolicy. В частности, `security_file_open` сообщает о доступе к пути, но не гарантирует наблюдение за соединением с Unix-сокетом, а `security_capset` — об операции, но не об успешном повышении прав. R022 Live требует отдельного специально разрешённого стендового эксперимента.
