<div align="center">
  <img src="Telegram/Resources/art/sleepygram_1024.png" alt="SleepyGram" width="144" />

  <h1>SleepyGram Desktop</h1>

  <p>
    <strong>Быстрый и приватный клиент Telegram Desktop на базе AyuGram, развиваемый сообществом.</strong><br />
    Актуальная база Telegram, открытая разработка и реальное внимание к запросам пользователей — без закрытой тусовки мейнтейнеров.
  </p>

  <p>
    <a href="https://github.com/slpkbt/SleepyGram/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/slpkbt/SleepyGram/build.yml?branch=dev&style=flat-square&label=build" alt="Build Status" /></a>
    <a href="https://github.com/telegramdesktop/tdesktop/releases/tag/v7.4.3"><img src="https://img.shields.io/badge/telegram_base-v7.4.3-26A5E4?style=flat-square&logo=telegram&logoColor=white" alt="Telegram Base v7.4.3" /></a>
    <a href="https://github.com/slpkbt/SleepyGram/releases"><img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-181717?style=flat-square" alt="Platforms" /></a>
    <a href="https://github.com/slpkbt/SleepyGram/issues"><img src="https://img.shields.io/badge/PRs%20%26%20Issues-welcome-10B981?style=flat-square" alt="PRs & Issues Welcome" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-blue?style=flat-square" alt="License GPLv3" /></a>
  </p>

  <p>
    <a href="#скачать"><strong>Скачать</strong></a>
    &nbsp;·&nbsp;
    <a href="#почему-sleepygram"><strong>О проекте</strong></a>
    &nbsp;·&nbsp;
    <a href="#возможности"><strong>Возможности</strong></a>
    &nbsp;·&nbsp;
    <a href="https://github.com/slpkbt/SleepyGram/issues"><strong>Предложить идею / Багрепорт</strong></a>
    &nbsp;·&nbsp;
    <a href="README.md"><strong>English</strong></a>
  </p>
</div>

---

## Почему SleepyGram

AyuGram дал десктопному Telegram отличные инструменты приватности и сохранения истории, но со временем обновления стали выходить редко, база начала отставать от официального клиента, а идеи и багрепорты пользователей в Issues годами оставались без ответа.

**SleepyGram** создан, чтобы исправить именно это:

- **Развивается сообществом, а не закрытым кругом разработчиков.** Запросы и проблемы из [Issues](https://github.com/slpkbt/SleepyGram/issues) напрямую влияют на следующие релизы, а не лежат мёртвым грузом.
- **Своевременные обновления базы Telegram.** Репозиторий поддерживается на актуальном `tdesktop` (`v7.4.3`) со всеми новыми функциями мессенджера и полным сохранением возможностей AyuGram.
- **Упор на реальный ежедневный опыт.** Снятие искусственных ограничений, продуманные мелочи интерфейса, отключённое принудительное автообновление и полностью отдельный профиль приложения.

---

## Возможности

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>👻 Ghost Mode и приватность</h3>
      <p>Гибкое управление прочтением сообщений, онлайном, статусом набора текста и просмотром историй — читайте чаты незаметно и отправляйте отметку о прочтении только тогда, когда нужно вам.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🕓 Анти-удаление и история правок</h3>
      <p>Локальное сохранение удалённых сообщений, исчезающих медиафайлов и полной истории редактирования — ни один собеседник не сотрёт контекст задним числом.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>⚡ Снятие искусственных лимитов</h3>
      <p>Выделение и пересылка до <strong>10 000 сообщений</strong> за одно действие с автоматической разбивкой на безопасные батчи по 100 сообщений без потери порядка и зависаний.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🎨 Кастомизация и удобство</h3>
      <p>Свои шрифты, Streamer Mode, локальные интерфейсные опции, встроенный переводчик, настройка папок и быстрый предпросмотр по Force Click на macOS.</p>
    </td>
  </tr>
</table>

---

## Скачать

Готовые сборки публикуются в разделе [**Releases**](https://github.com/slpkbt/SleepyGram/releases). SleepyGram использует собственные идентификаторы и отдельную директорию данных — его можно устанавливать рядом с обычным Telegram и AyuGram.

| Платформа | Архитектура | Архив | Статус |
| :--- | :--- | :--- | :--- |
| **macOS** | Apple Silicon (`arm64`) | [`SleepyGram-macos-arm64.zip`](https://github.com/slpkbt/SleepyGram/releases) | Официальный релиз |
| **Linux** | 64-bit (`x86_64`) | [`SleepyGram-linux-x64.tar.xz`](https://github.com/slpkbt/SleepyGram/releases) | Официальный релиз |
| **Windows** | 64-bit (`x86_64`) | [`SleepyGram-windows-x64.zip`](https://github.com/slpkbt/SleepyGram/releases) | Архив релиза |

<details>
<summary><strong>Первый запуск на macOS (Gatekeeper)</strong></summary>

<br />

Сборки подписываются ad-hoc подписью в GitHub Actions без платного сертификата Apple Developer. Если после переноса `SleepyGram.app` в `/Applications` система блокирует первый запуск, снимите карантин одной командой в Терминале:

```bash
xattr -cr /Applications/SleepyGram.app
```

</details>

---

## Участие в развитии

SleepyGram делается для тех, кто живёт в Telegram каждый день. Если вас раздражает старое ограничение клиента, игнорируемый месяцами тикет в AyuGram или у вас готов полезный патч:

1. **Создайте тикет** с идеей или багрепортом в [GitHub Issues](https://github.com/slpkbt/SleepyGram/issues).
2. **Отправьте Pull Request** в ветку `dev` — улучшения UX, фиксы и патчи приветствуются.
3. **Соберите проект самостоятельно** по инструкциям в [`docs/`](docs/) ([macOS](docs/building-mac.md) · [Linux](docs/building-linux.md) · [Windows](docs/building-win.md)).

---

## Благодарности и лицензия

Проект опирается на открытый исходный код:

- [**Telegram Desktop**](https://github.com/telegramdesktop/tdesktop) — официальный клиент и кодовая база мессенджера
- [**AyuGram Desktop**](https://github.com/AyuGram/AyuGramDesktop) — оригинальная реализация Ghost Mode, истории сообщений и кастомизации

Распространяется под лицензией [**GPLv3**](LICENSE) с исключением OpenSSL. Подробности приведены в файле [LEGAL](LEGAL).
