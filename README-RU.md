<p align="center">
  <img src="Telegram/Resources/art/sleepygram_1024.png" alt="SleepyGram logo" width="180">
</p>

<h1 align="center">SleepyGram Desktop</h1>

<p align="center">
  Специальный клиент Telegram Desktop на базе AyuGram (актуальная база Telegram Desktop 7.4.3), который развивается открытым сообществом, а не закрытой группой разработчиков.
</p>

<p align="center">
  <a href="README.md">English</a>
  ·
  <a href="https://github.com/slpkbt/SleepyGram/releases">Releases</a>
  ·
  <a href="https://github.com/slpkbt/SleepyGram/issues">Issues</a>
</p>

## О проекте SleepyGram

**SleepyGram** — это модифицированный клиент Telegram Desktop на основе AyuGram, созданный для реального улучшения повседневного опыта в Telegram вместе с пользователями, а не в закрытом кругу мейнтейнеров.

В AyuGram отличный базовый набор privacy-функций, но сам проект регулярно отстаёт от свежих релизов Telegram, а запросы и багрепорты обычных пользователей в Issues годами остаются без внимания. Мы сделали **SleepyGram**, чтобы исправить этот подход:

- **Развитие от комьюнити, а не закрытой тусовки:** Идеи, проблемы и предложения из [Issues](https://github.com/slpkbt/SleepyGram/issues) реально учитываются и попадают в обновления, а не игнорируются.
- **Живой репозиторий и актуальная база:** Репозиторий своевременно синхронизируется со свежими версиями официального Telegram Desktop (`7.4.3`) с полным сохранением фич AyuGram.
- **Фокус на удобстве работы с Telegram:** Убираем искусственные лимиты и дорабатываем клиент там, где это действительно нужно людям каждый день.

## Возможности

- **Расширенное выделение и пакетная пересылка:** Выделение и пересылка до **10 000 сообщений** за раз (с автоматической разбивкой по 100 сообщений на API-запрос)
- **Ghost Mode и гибкая приватность:** Нечиталка, скрытие онлайна, набора текста и просмотра историй
- **История изменений и анти-удаление:** Локальное сохранение удалённых и отредактированных сообщений и медиа
- **Кастомизация интерфейса:** Шрифты, оформление чатов, папок и панелей
- **Streamer Mode и локальные опции Telegram Premium**
- **Встроенный переводчик сообщений**
- **Превью медиа и быстрая реакция по Force Click на macOS**

## Скачать

Актуальные сборки публикуются на странице [Releases](https://github.com/slpkbt/SleepyGram/releases).

Автоматические артефакты GitHub Actions:

- `SleepyGram-macos-arm64.zip` (macOS Apple Silicon)
- `SleepyGram-linux-x64.tar.xz` (Linux x86_64)

Сборка под Windows (`SleepyGram-windows-x64.zip`) запускается через `workflow_dispatch`. Автообновление в CI-сборках отключено (`DESKTOP_APP_DISABLE_AUTOUPDATE=ON`), чтобы клиент не обновлялся без вашего ведома.

## Идентификация клиента

SleepyGram использует собственные идентификаторы приложения, имя исполняемого файла и отдельные папки данных — его можно спокойно запускать параллельно с обычным Telegram Desktop и AyuGram без конфликта профилей.

- Product name: `SleepyGram Desktop`
- Executable name: `SleepyGram`
- macOS bundle id: `com.sleepygram.desktop`
- Linux app id: `com.sleepygram.desktop`
- Windows app id: `{09F8EFBD-99A0-4326-9A2F-2694574B75CB}`

## Сборка

Сборка и публикация релизов настроены в `.github/workflows/build.yml`:

- **Pull requests:** проверочные сборки под Linux и macOS
- **Push в `dev`:** обновление rolling-пререлиза `continuous`
- **Теги `v*` и ручной запуск:** публикация релизов (`macos-arm64`, `linux-x64`, `windows-x64` или `all`)

Поддерживаемые secrets для Telegram API:

- `TDESKTOP_API_ID`
- `TDESKTOP_API_HASH`

Также поддерживаются `AYUGRAM_API_ID` / `AYUGRAM_API_HASH`, `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` и `API_ID` / `API_HASH`. Если секреты не заданы, используются стандартные публичные ключи из `docs/api_credentials.md`.

## Благодарности

SleepyGram основан на кодовой базе:

- [Telegram Desktop](https://github.com/telegramdesktop/tdesktop)
- [AyuGram Desktop](https://github.com/AyuGram/AyuGramDesktop)

Сторонние библиотеки и компоненты принадлежат их авторам и указаны в соответствующих директориях исходного кода.
