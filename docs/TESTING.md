# Проверка правил и измерения RED-O

## 1. Базовые проверки

```bash
./build.sh
go test -count=1 ./...
go vet ./...
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/release_smoke.py --project .
```

`release_smoke.py` проводит офлайн-проверку сборки, CLI, тестов, качества на заранее построенной синтетической выборке, контекстного сравнения, watermark и автономного запуска. Для реальных выводов о K3s нужна отдельная Live-серия.

## 2. Replay всех правил

```bash
python3 tools/check_rules.py --project . --mode replay
```

Генерирует по одному ожидаемому положительному и отрицательному JSONL-случаю для каждого R001–R022 и проверяет обработку настоящим бинарником. Всего **44 синтетических случая**. Результаты: `benchmark-results/all-rules-<UTC>/replay/summary.csv`, `summary.json`, `normalized-events.jsonl`, `alerts.jsonl`. Это проверка движка на контролируемом входе, **не Precision/Recall живых атак**.

## 3. Live-проверка сигнатур и корреляций

```bash
kubectl create namespace security-lab --dry-run=client -o yaml | kubectl apply -f -
./bin/red-o up
python3 tools/check_rules.py --project . --mode live --execute --wait-seconds 15
```

Внешние TCP-попытки включаются только отдельным `--allow-external` (адрес `1.1.1.1`), если политика стенда это разрешает. Для конкретных правил: `--only R007,R011,R017,R021`. С помощью `--keep-resources` можно оставить тестовые ресурсы для расследования; по умолчанию скрипт удаляет созданные Pod и сервисы.

Результаты: `benchmark-results/all-rules-<UTC>/live/summary.csv`, `summary.json`, `trial-plan.json`, `diagnostic-RNNN.json`. Для R007 диагностика содержит путь, временные метки, `exec_id` и проверки принадлежности контейнеру. Для R021 проверяется полный набор пяти связанных IP. Корреляционные алерты атрибутируются по `related_event_ids`, а не только имени Pod.

**Расшифровка статусов:** `PASS` — сработало ожидаемое правило на связанных событиях; `SKIP` — тест неприменим; `FAIL_TELEMETRY` — не все ожидаемые события получены; `FAIL_PRECONDITION` — события не образуют допустимую цепочку; `FAIL_RULE` — требуемые события есть, а целевого алерта нет; `ERROR` — ошибка команды/среды.

**Предупреждение:** Live — положительная smoke-проверка индикаторов, а не серия атак. Для R012/R014/R018/R019 используются безопасные копии Python с заданными именами; это проверяет правило по имени binary, а не функциональность настоящих утилит. R017 проверяет файловый путь, но не Unix-socket connect. R011 проверяет вызов capset, не успех повышения прав. R022 по умолчанию `SKIP`. Отдельные TracingPolicy устанавливаются вручную до теста; тест не меняет их.

## 4. Измерение Precision / Recall / F1

Для независимой оценки необходимо создать **до тестов** список действий с метками positive/negative, временем начала/конца, namespace, PodUID и ожидаемыми событиями. Затем соотнести реальные `event_id` с действиями и использовать:

```bash
./bin/red-o benchmark quality evaluate \
  -manifest path/to/trials.json \
  -events data/live-events.jsonl \
  -alerts data/live-alerts.jsonl \
  -strict-attribution=true \
  -output benchmark-results/quality-live/evaluation
```

Отчёты содержат TP/FP/FN/TN, coverage, end-to-end recall и задержки action-to-alert/event-to-detection. Не смешивайте пропуск телеметрии с TN и не рассчитывайте P95/P99 как устойчивые показатели по одному-двум измерениям.

Контекстную политику нужно зафиксировать до held-out набора; сопоставление базового и контекстного triage выполняется через `benchmark quality compare`. Оно не изменяет исходные предупреждения и не свидетельствует об автоматическом блокировании угроз.

## 5. Воспроизводимость

Сохраняйте `./bin/red-o version -json`, SHA256 конфигураций `rules.json`/`correlations.json` и TracingPolicy, имена временных Pod, сырые анонимизированные журналы действий и JSONL с event IDs. Отделяйте выводы с реальной VM от синтетических результатов и указывайте объём выборки. Не публикуйте Web-пароль, `.env` и ServiceAccount Token.
