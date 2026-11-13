<div align="center">
  <img src="Telegram/Resources/art/sleepygram_1024.png" alt="SleepyGram" width="144" />

  <h1>SleepyGram Desktop</h1>

  <p>
    <strong>Fast, privacy-first, community-driven Telegram Desktop client built on top of AyuGram.</strong><br />
    Up to date with upstream Telegram, shaped openly by users — not locked behind a closed developer circle.
  </p>

  <p>
    <a href="https://github.com/slpkbt/SleepyGram/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/slpkbt/SleepyGram/build.yml?branch=dev&style=flat-square&label=build" alt="Build Status" /></a>
    <a href="https://github.com/telegramdesktop/tdesktop/releases/tag/v7.4.3"><img src="https://img.shields.io/badge/telegram_base-v7.4.3-26A5E4?style=flat-square&logo=telegram&logoColor=white" alt="Telegram Base v7.4.3" /></a>
    <a href="https://github.com/slpkbt/SleepyGram/releases"><img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-181717?style=flat-square" alt="Platforms" /></a>
    <a href="https://github.com/slpkbt/SleepyGram/issues"><img src="https://img.shields.io/badge/PRs%20%26%20Issues-welcome-10B981?style=flat-square" alt="PRs & Issues Welcome" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-blue?style=flat-square" alt="License GPLv3" /></a>
  </p>

  <p>
    <a href="#downloads"><strong>Download</strong></a>
    &nbsp;·&nbsp;
    <a href="#why-sleepygram"><strong>Why SleepyGram</strong></a>
    &nbsp;·&nbsp;
    <a href="#highlights"><strong>Features</strong></a>
    &nbsp;·&nbsp;
    <a href="#comparison"><strong>Comparison</strong></a>
    &nbsp;·&nbsp;
    <a href="https://github.com/slpkbt/SleepyGram/issues"><strong>Report Issue / Request Feature</strong></a>
    &nbsp;·&nbsp;
    <a href="README-RU.md"><strong>Русский</strong></a>
  </p>
</div>

---

## Why SleepyGram

AyuGram brought some of the best privacy and message-preservation features to Telegram Desktop — and then slowed down, fell behind official Telegram updates, and started leaving community bug reports and feature requests unanswered.

**SleepyGram** was started to fix that from the ground up:

- **Shaped by the community, not a closed inner circle.** User feedback in [Issues](https://github.com/slpkbt/SleepyGram/issues) isn't background noise — requested workflow fixes, limit removals, and UX improvements actually make it into releases.
- **Synced with modern Telegram Desktop.** Maintained cleanly against upstream `tdesktop` (`v7.4.3`) so you don't have to choose between privacy tools and new Telegram features.
- **Built for heavy daily use.** Practical power-user upgrades, no forced self-updates, and an independent app profile that runs safely alongside official Telegram or AyuGram.

---

## Highlights

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>👻 Stealth & Ghost Controls</h3>
      <p>Granular control over read receipts, online status, typing/upload indicators, and story views — read on your own terms and explicitly send read marks only when you choose.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🕓 Anti-Recall & Edit History</h3>
      <p>Locally preserve deleted messages, disappearing media, and full message edit timelines so context never vanishes mid-conversation.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>⚡ Power-User Limits Unlocked</h3>
      <p>Select and forward up to <strong>10,000 messages</strong> in one action — automatically dispatched in safe 100-message API batches without silent drops or client freezes.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🎨 Clean UX & Customization</h3>
      <p>Custom fonts, streamer mode, local interface unlocks, built-in translation, folder tweaks, and macOS Force Click media previews & quick reactions.</p>
    </td>
  </tr>
</table>

---

## Comparison

| Capability | Telegram Desktop | AyuGram Desktop | **SleepyGram Desktop** |
| :--- | :---: | :---: | :---: |
| **Upstream Telegram Base** | `v7.4.3` | Lags behind upstream | **`v7.4.3` (Actively Synced)** |
| **Ghost Mode & Anti-Recall** | — | Yes | **Yes** |
| **Edit History & Deleted Media Vault** | — | Yes | **Yes** |
| **Max Multi-Select & Batch Forward** | 100 messages | 100 messages | **10,000 messages (Auto-Batched)** |
| **Community Feature Requests** | Official roadmap only | Closed maintainer group | **Open & Community-Driven** |
| **Runs Alongside Other Clients** | Separate profile | Separate profile | **Isolated (`SleepyGram`)** |

---

## Downloads

Prebuilt binaries are published on the [**Releases**](https://github.com/slpkbt/SleepyGram/releases) page. SleepyGram uses its own bundle identifier and data folder, so your existing Telegram or AyuGram session stays untouched.

| Platform | Architecture | Package | Status |
| :--- | :--- | :--- | :--- |
| **macOS** | Apple Silicon (`arm64`) | [`SleepyGram-macos-arm64.zip`](https://github.com/slpkbt/SleepyGram/releases) | Official Release |
| **Linux** | 64-bit (`x86_64`) | [`SleepyGram-linux-x64.tar.xz`](https://github.com/slpkbt/SleepyGram/releases) | Official Release |
| **Windows** | 64-bit (`x86_64`) | [`SleepyGram-windows-x64.zip`](https://github.com/slpkbt/SleepyGram/releases) | Release Archive |

<details>
<summary><strong>macOS First-Launch Note (Gatekeeper)</strong></summary>

<br />

SleepyGram builds are ad-hoc signed in CI without an Apple Developer notarization certificate. If macOS displays an unverified developer prompt after moving `SleepyGram.app` to `/Applications`, clear the quarantine attribute once in Terminal:

```bash
xattr -cr /Applications/SleepyGram.app
```

</details>

---

## Community & Contributing

SleepyGram exists for the people who actually use it every day. If something annoys you in Telegram, if an AyuGram issue has been sitting ignored for months, or if you have a clean patch ready:

1. **Request a feature or report a bug** via [GitHub Issues](https://github.com/slpkbt/SleepyGram/issues).
2. **Open a Pull Request** against `dev` — clean UX improvements, bug fixes, and upstream sync helpers are always welcome.
3. **Build from source** using platform guides in [`docs/`](docs/) ([macOS](docs/building-mac.md) · [Linux](docs/building-linux.md) · [Windows](docs/building-win.md)).

---

## Acknowledgements & License

SleepyGram stands on the shoulders of open-source work from:

- [**Telegram Desktop**](https://github.com/telegramdesktop/tdesktop) — official desktop client and upstream foundation
- [**AyuGram Desktop**](https://github.com/AyuGram/AyuGramDesktop) — original Ghost Mode, message history, and customization implementation

Licensed under [**GPLv3**](LICENSE) with OpenSSL exception. See [LEGAL](LEGAL) for full licensing details.
