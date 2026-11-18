// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/ui/components/icon_picker.h"

#include "tray.h"
#include "ayu/ayu_settings.h"
#include "ayu/ui/ayu_logo.h"
#include "core/application.h"
#include "lang/lang_keys.h"
#include "main/main_domain.h"
#include "styles/style_ayu_styles.h"
#include "ui/painter.h"
#include "window/main_window.h"

#ifdef Q_OS_WIN
#include "ayu/utils/windows_utils.h"
#endif

#include <QtGui/QHelpEvent>
#include <QtWidgets/QToolTip>

namespace {

const auto icons = std::array{
	AyuAssets::DEFAULT_ICON,
	AyuAssets::MOONLIGHT_ICON,
	AyuAssets::MIDNIGHT_ICON,
	AyuAssets::AURORA_ICON,
	AyuAssets::DUSK_ICON,
};

const auto names = std::array{
	u"SleepyGram"_q,
	u"Moonlight"_q,
	u"Midnight"_q,
	u"Aurora"_q,
	u"Dusk"_q,
};

void applyIcon() {
#ifdef Q_OS_WIN
	AyuAssets::loadAppIco();
	reloadAppIconFromTaskBar();
#endif

	Window::OverrideApplicationIcon(AyuAssets::currentAppLogo());
	Core::App().refreshApplicationIcon();
	Core::App().tray().updateIconCounters();
	Core::App().domain().notifyUnreadBadgeChanged();
}

} // namespace

IconPicker::IconPicker(QWidget *parent)
: RpWidget(parent) {
	setFocusPolicy(Qt::StrongFocus);
	setAccessibleName(tr::ayu_AppIconHeader(tr::now));
	for (auto i = 0; i != kIconCount; ++i) {
		_images[i] = AyuAssets::loadPreview(icons[i]);
	}
	widthValue() | rpl::on_next([=](int width) {
		resize(width, iconRect(0).height() + 2 * st::iconPickerImagePadding);
	}, lifetime());
}

QRect IconPicker::iconRect(int index) const {
	const auto cell = width() / kIconCount;
	const auto padding = st::iconPickerImagePadding;
	const auto side = std::clamp(cell - 2 * padding, 0, st::iconPickerIconSize);
	return QRect(index * cell + (cell - side) / 2, padding, side, side);
}

int IconPicker::iconAt(QPoint position) const {
	for (auto i = 0; i != kIconCount; ++i) {
		if (iconRect(i).contains(position)) {
			return i;
		}
	}
	return -1;
}

bool IconPicker::eventHook(QEvent *e) {
	if (e->type() == QEvent::ToolTip) {
		const auto help = static_cast<QHelpEvent*>(e);
		if (const auto index = iconAt(help->pos()); index >= 0) {
			QToolTip::showText(help->globalPos(), names[index], this);
			return true;
		}
	}
	return RpWidget::eventHook(e);
}

void IconPicker::paintEvent(QPaintEvent *e) {
	auto p = Painter(this);
	const auto smooth = PainterHighQualityEnabler(p);
	const auto &selected = AyuSettings::getInstance().appIcon();
	const auto pad = st::iconPickerSelectedPadding;
	const auto radius = st::iconPickerSelectedRounding;
	for (auto i = 0; i != kIconCount; ++i) {
		const auto icon = iconRect(i);
		if (icons[i] == selected) {
			p.setPen(hasFocus() ? QPen(st::windowFgActive) : QPen(Qt::NoPen));
			p.setBrush(st::boxDividerBg);
			p.drawRoundedRect(icon.adjusted(-pad, -pad, pad, pad), radius, radius);
		}
		p.drawImage(icon, _images[i]);
	}
}

void IconPicker::mousePressEvent(QMouseEvent *e) {
	if (e->button() == Qt::LeftButton) {
		if (const auto index = iconAt(e->pos()); index >= 0) {
			selectIcon(index);
			return;
		}
	}
	RpWidget::mousePressEvent(e);
}

void IconPicker::keyPressEvent(QKeyEvent *e) {
	const auto key = e->key();
	if (key != Qt::Key_Left && key != Qt::Key_Right) {
		RpWidget::keyPressEvent(e);
		return;
	}
	const auto &selected = AyuSettings::getInstance().appIcon();
	const auto index = int(std::find(icons.begin(), icons.end(), selected)
		- icons.begin());
	const auto step = (key == Qt::Key_Left) ? -1 : 1;
	selectIcon((index + step + kIconCount) % kIconCount);
}

void IconPicker::selectIcon(int index) {
	const auto &name = icons[index];
	auto &settings = AyuSettings::getInstance();
	if (settings.appIcon() == name) {
		return;
	}
	settings.setAppIcon(name);
	applyIcon();
	update();
}
