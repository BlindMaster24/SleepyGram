// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#pragma once

#include "ui/rp_widget.h"

class IconPicker final : public Ui::RpWidget {
public:
	explicit IconPicker(QWidget *parent);

protected:
	bool event(QEvent *e) override;
	void paintEvent(QPaintEvent *e) override;
	void mousePressEvent(QMouseEvent *e) override;
	void keyPressEvent(QKeyEvent *e) override;

private:
	static constexpr auto kIconCount = 5;

	[[nodiscard]] QRect iconRect(int index) const;
	[[nodiscard]] int iconAt(QPoint position) const;
	void selectIcon(int index);

	std::array<QImage, kIconCount> _images;

};
