# Secure SDLC

## Shift Left

Shift Left значит тащить проверки безопасности ближе к разработке: линтеры секретов,
зависимости, базовый SAST ещё на PR, а не после релиза. Дешевле чинить рано.

## SAST

Static Application Security Testing — анализ кода без запуска. Ловит типовые дыры
в исходниках, но шумит и не видит runtime-конфиг.

## DAST

Dynamic Application Security Testing — проверки уже живого приложения/API.
Хорошо для authz, injection через реальные запросы. Нужен стенд.

## SCA

Software Composition Analysis — смотрим сторонние пакеты и известные CVE.
Для Python удобно опираться на OSV / advisory базы.

## Secrets scanning

Отдельный быстрый слой: ключи, токены, private key в git. Обычно ставят в pre-commit и CI.
