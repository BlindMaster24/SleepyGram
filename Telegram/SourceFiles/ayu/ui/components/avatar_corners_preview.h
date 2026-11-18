// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#pragma once

#include "ui/rp_widget.h"

class AvatarCornersPreview final : public Ui::RpWidget {
public:
	explicit AvatarCornersPreview(QWidget *parent);

protected:
	void paintEvent(QPaintEvent *e) override;

};
