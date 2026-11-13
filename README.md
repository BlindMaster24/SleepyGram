<p align="center">
  <img src="Telegram/Resources/art/sleepygram_1024.png" alt="SleepyGram logo" width="180">
</p>

<h1 align="center">SleepyGram Desktop</h1>

<p align="center">
  A community-driven Telegram Desktop client based on AyuGram and synced with Telegram Desktop 7.4.3 — built openly with users to make daily Telegram genuinely better.
</p>

<p align="center">
  <a href="README-RU.md">Русский</a>
  ·
  <a href="https://github.com/slpkbt/SleepyGram/releases">Releases</a>
  ·
  <a href="https://github.com/slpkbt/SleepyGram/issues">Issues</a>
</p>

## About SleepyGram

**SleepyGram** is a specialized Telegram Desktop client built on top of AyuGram, shaped and improved together with the community rather than behind a closed group of maintainers.

AyuGram introduced great privacy and history tools, but upstream releases lagged behind and community feature requests and issues were routinely ignored. SleepyGram was created to fix that:

- **Community-driven, not closed-door:** Real user pain points, bug reports, and ideas from [Issues](https://github.com/slpkbt/SleepyGram/issues) directly drive what ships next instead of sitting unanswered.
- **Actively maintained & up to date:** The repository stays properly synced with current official Telegram Desktop releases (`7.4.3`) while keeping AyuGram's core toolset intact.
- **Focused on everyday Telegram UX:** Practical quality-of-life upgrades that remove artificial limits and improve daily workflows without bloat.

## Features

- **Extended multi-select & batched forwarding:** Select and forward up to **10,000 messages** at once (automatically split into safe 100-message API batches)
- **Ghost mode & privacy controls:** Flexible read, online, typing, and story-view stealth options
- **Message history & anti-recall:** Preserve edited and deleted messages and media locally
- **Customization:** Fonts, chat appearance, folders, and interface tweaks
- **Streamer mode & local Telegram Premium options**
- **Built-in message translation**
- **macOS force-click media preview & quick reactions**

## Downloads

Linux and macOS builds are published on the [Releases](https://github.com/slpkbt/SleepyGram/releases) page.

GitHub Actions produces these release archives:

- `SleepyGram-macos-arm64.zip` (Apple Silicon macOS)
- `SleepyGram-linux-x64.tar.xz` (Linux x86_64)

Windows builds (`SleepyGram-windows-x64.zip`) can be triggered via `workflow_dispatch`. CI builds disable automatic self-updates (`DESKTOP_APP_DISABLE_AUTOUPDATE=ON`) so you stay in control of client versions.

## App Identity

SleepyGram uses dedicated application identifiers, executable names, and local data directories, running completely side-by-side with Telegram Desktop and AyuGram without touching existing profiles.

- Product name: `SleepyGram Desktop`
- Executable name: `SleepyGram`
- macOS bundle id: `com.sleepygram.desktop`
- Linux app id: `com.sleepygram.desktop`
- Windows app id: `{09F8EFBD-99A0-4326-9A2F-2694574B75CB}`

## Building

Artifacts are built through `.github/workflows/build.yml`:

- **Pull requests:** Linux and macOS verification builds
- **Pushes to `dev`:** Rolling `continuous` prerelease builds
- **`v*` tags & manual dispatch:** Tagged GitHub Releases (`macos-arm64`, `linux-x64`, `windows-x64`, or `all`)

Preferred Telegram API credential secrets:

- `TDESKTOP_API_ID`
- `TDESKTOP_API_HASH`

The workflow also accepts `AYUGRAM_API_ID` / `AYUGRAM_API_HASH`, `TELEGRAM_API_ID` / `TELEGRAM_API_HASH`, or `API_ID` / `API_HASH`, falling back to the public test credentials in `docs/api_credentials.md` if unset.

## Credits

SleepyGram builds upon:

- [Telegram Desktop](https://github.com/telegramdesktop/tdesktop)
- [AyuGram Desktop](https://github.com/AyuGram/AyuGramDesktop)

Third-party libraries and components are credited in their respective source directories.
