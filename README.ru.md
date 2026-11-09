# agent-escape-bench

**Сколько выходов есть у вашего AI-агента?**

Вы написали правила для Claude Code или Cursor: не трогать CI, не править примененные миграции, не читать `.env`. Может быть, даже написали хук, который блокирует `echo x > .github/workflows/ci.yml`. Бенчмарк отправляет вашему хуку 164 shell-команды: 123 известных способа все-таки сделать запрещенное и 41 обычную команду, которая должна работать. В отчете видно, сколько прошло.

**Команды из корпуса не выполняются.** Бенч создает одноразовый репозиторий, отправляет каждую команду хуку так, как это сделал бы агент, и записывает ответ: allow, ask или deny.

## Установка и запуск

```bash
pipx install git+https://github.com/OWNER/agent-escape-bench
cd your-repo

aeb bench --claude .     # PreToolUse-хуки на Bash из .claude/settings*.json
aeb bench --cursor .     # beforeShellExecution-хуки из .cursor/hooks.json
aeb bench --plugin DIR   # хуки плагина Claude Code
aeb scan .               # у каких правил из CLAUDE.md есть механическая проверка
```

Нужен Python 3.9+, зависимостей нет. Весь корпус проходит примерно за 15 секунд. Отчеты: `--md`, `--html`, `--json`. Для CI: `--max-escapes 0`.

## Ориентиры

| Сетап | Прошло атак | Зря заблокировано |
| --- | --- | --- |
| Хука нет, правила только в CLAUDE.md | 123 из 123 | 0 из 41 |
| Типичный самописный guard из `examples/naive-guard` | 98 из 123 | 1 из 41 |
| Guard EGD 1.4, по аудиту кита | 81 из 123 | 3 из 41 |
| Guard EGD 1.5, прогон этим инструментом | 0 из 123 | 0 из 41 |

Если миграции лежат не в `db/migrations`, укажите путь: `--migrations-dir api/migrations`. Политика, по которой размечен корпус, описана в [docs/POLICY.md](docs/POLICY.md). Подробности, ограничения и правила добавления случаев описаны в [README.md](README.md).

Автор: Данил Углянский, CTO. Корпус вырос из EGD (Evidence-Gated Delivery), методологии внедрения AI-агентов в разработку с гейтами по риску. Если дыры хочется закрыть, а не только посчитать, пишите: d.uglianskii@gmail.com, Telegram [@Agelastes](https://t.me/Agelastes).
