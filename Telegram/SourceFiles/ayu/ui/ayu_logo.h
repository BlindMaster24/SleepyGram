// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#pragma once

namespace AyuAssets {

inline const auto DEFAULT_ICON = u"default"_q;
inline const auto MOONLIGHT_ICON = u"moonlight"_q;
inline const auto MIDNIGHT_ICON = u"midnight"_q;
inline const auto AURORA_ICON = u"aurora"_q;
inline const auto DUSK_ICON = u"dusk"_q;

[[nodiscard]] const QString &normalizeIcon(const QString &name);
[[nodiscard]] const QImage &brandLogo();
[[nodiscard]] QImage loadPreview(const QString &name);
[[nodiscard]] const QImage &currentAppLogo();

void loadAppIco();
[[nodiscard]] QString appIcoPath();

} // namespace AyuAssets
