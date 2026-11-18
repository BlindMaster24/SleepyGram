// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/ui/ayu_logo.h"

#include "ayu/ayu_settings.h"
#include "styles/style_ayu_styles.h"

#include <QtCore/QFile>
#include <QtCore/QSaveFile>

namespace AyuAssets {
namespace {

[[nodiscard]] QString resourcePath(const QString &name, const QString &extension) {
	return u":/gui/art/sleepygram/"_q + name + extension;
}

} // namespace

const QString &normalizeIcon(const QString &name) {
	if (name == MOONLIGHT_ICON) {
		return MOONLIGHT_ICON;
	} else if (name == MIDNIGHT_ICON) {
		return MIDNIGHT_ICON;
	} else if (name == AURORA_ICON) {
		return AURORA_ICON;
	} else if (name == DUSK_ICON) {
		return DUSK_ICON;
	}
	return DEFAULT_ICON;
}

const QImage &brandLogo() {
	static const auto logo = QImage(u":/gui/art/sleepygram_1024.png"_q);
	return logo;
}

QString appIcoPath() {
	return cWorkingDir()
		+ u"tdata/SleepyGram-"_q
		+ AyuSettings::getInstance().appIcon()
		+ u".ico"_q;
}

void loadAppIco() {
	const auto &name = AyuSettings::getInstance().appIcon();
	auto source = QFile(name == DEFAULT_ICON
		? u":/gui/art/icon256.ico"_q
		: resourcePath(name, u".ico"_q));
	if (!source.open(QIODevice::ReadOnly)) {
		return;
	}
	const auto bytes = source.readAll();
	auto destination = QSaveFile(appIcoPath());
	if (bytes.isEmpty()
		|| !destination.open(QIODevice::WriteOnly)
		|| destination.write(bytes) != bytes.size()
		|| !destination.commit()) {
		LOG(("Could not save SleepyGram taskbar icon."));
	}
}

QImage loadPreview(const QString &name) {
	const auto image = (name == DEFAULT_ICON)
		? brandLogo()
		: QImage(resourcePath(name, u".png"_q));
	const auto size = st::iconPickerIconSize * style::DevicePixelRatio();
	return image.scaled(size, size, Qt::KeepAspectRatio, Qt::SmoothTransformation);
}

const QImage &currentAppLogo() {
	const auto &name = AyuSettings::getInstance().appIcon();
	static auto loadedName = QString();
	static auto loadedImage = QImage();
	if (name != loadedName) {
		loadedName = name;
		loadedImage = (name == DEFAULT_ICON)
			? brandLogo()
			: QImage(resourcePath(name, u".png"_q));
	}
	return loadedImage.isNull() ? brandLogo() : loadedImage;
}

} // namespace AyuAssets
