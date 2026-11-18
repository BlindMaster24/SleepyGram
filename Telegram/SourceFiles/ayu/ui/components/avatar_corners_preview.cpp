// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/ui/components/avatar_corners_preview.h"

#include "ayu/ui/ayu_logo.h"
#include "ayu/ui/ayu_userpic.h"
#include "lang/lang_keys.h"
#include "styles/style_dialogs.h"
#include "styles/style_settings.h"
#include "ui/painter.h"

AvatarCornersPreview::AvatarCornersPreview(QWidget *parent)
: RpWidget(parent) {
	setFixedHeight(st::defaultDialogRow.height);
}

void AvatarCornersPreview::paintEvent(QPaintEvent *e) {
	auto p = Painter(this);

	const auto &row = st::defaultDialogRow;
	const auto size = row.photoSize;
	const auto xShift = st::settingsButtonNoIcon.padding.left()
		- row.padding.left();
	const auto x = row.padding.left() + xShift;
	const auto y = (height() - size) / 2;

	p.fillRect(rect(), st::windowBg);
	{
		const auto smooth = PainterHighQualityEnabler(p);
		p.setPen(Qt::NoPen);
		p.setBrush(st::dialogsBgOver);
		AyuUserpic::PaintShape(p, x, y, size);
		p.drawImage(QRect(x, y, size, size), AyuAssets::brandLogo());
	}

	p.setPen(st::dialogsNameFg);
	p.setFont(st::semiboldFont);
	p.drawText(
		row.nameLeft + xShift,
		row.nameTop + st::semiboldFont->ascent,
		tr::sleepy_releases(tr::now));

	p.setPen(st::dialogsTextFg);
	p.setFont(st::dialogsTextFont);
	p.drawText(
		row.textLeft + xShift,
		row.textTop + st::dialogsTextFont->ascent,
		tr::sleepy_avatar_preview(tr::now));
}
