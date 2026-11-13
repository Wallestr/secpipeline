# secpipeline

Небольшой набор утилит под shift-left проверки в CI.

Что умеет сейчас:
- искать секреты в коде
- смотреть зависимости через OSV (SCA)
- валить пайплайн по severity (`--fail-on`)
- отдавать summary через простое FastAPI
- отвечать по локальным заметкам про Secure SDLC / AI security (очень простой RAG без внешних LLM)

Не претендует на замену Semgrep/Trivy/etc. Скорее черновик инструмента, который можно докручивать под свою платформу.

## Run

```bash
python -m venv .venv
source .venv/bin/activate   # windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

# демо на fixtures
python -m secpipeline scan fixtures/sample_app --out .reports --fail-on high

# вопрос по knowledge/
python -m secpipeline ask "чем SAST отличается от DAST"

# метрики из последнего report.json
python -m secpipeline serve
# GET http://127.0.0.1:8088/metrics/summary
```

## CI

Примеры лежат в `ci/`:
- `ci/github-actions.yml` — скопируй в `.github/workflows/` у себя
- `ci/bitbucket-pipelines.yml` — Bitbucket

Идея одна: прогнал скан → сохранил report → при необходимости упал job.

## Layout

```
secpipeline/     cli + scanners + api
knowledge/       заметки для ask
fixtures/        специально грязный sample
ci/              примеры пайплайнов
```

## Notes

Deps-сканер ходит в `api.osv.dev`. Если оффлайн — `--skip-deps`.
Для ask никакой OpenAI/HF ключ не нужен, там локальный cosine по markdown.
