/*
This file is part of SleepyGram Desktop,
an unofficial client based on AyuGram Desktop and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_peer_id.h"
#include "ui/rp_widget.h"

#include <QtGui/QColor>
#include <QtCore/QString>
#include <memory>
#include <vector>

class PeerData;

namespace Main {
class Session;
} // namespace Main

namespace Ui {
class Show;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace Ayu::SendGuard {

enum class ActionKind : uchar {
	Files,
	Forward,
};

[[nodiscard]] QString AccountShortLabel(
	not_null<Main::Session*> session,
	PeerData *sendAsPeer = nullptr);
[[nodiscard]] QColor AccountAccentColor(not_null<Main::Session*> session);
[[nodiscard]] QString AccountCustomLabel(not_null<Main::Session*> session);
[[nodiscard]] QString AccountCustomColorHex(not_null<Main::Session*> session);
void SetAccountBadge(
	not_null<Main::Session*> session,
	const QString &label,
	const QString &colorHex);

[[nodiscard]] bool IsWorkChat(
	not_null<Main::Session*> session,
	PeerId peerId);
void SetWorkChat(
	not_null<Main::Session*> session,
	PeerId peerId,
	bool workChat);

[[nodiscard]] bool NeedsConfirmation(
	not_null<Main::Session*> session,
	PeerId peerId,
	ActionKind kind);

void ConfirmIfNeeded(
	std::shared_ptr<Ui::Show> show,
	not_null<Main::Session*> session,
	not_null<PeerData*> peer,
	ActionKind kind,
	Fn<void()> proceed);

void ConfirmManyIfNeeded(
	std::shared_ptr<Ui::Show> show,
	not_null<Main::Session*> session,
	const std::vector<not_null<PeerData*>> &peers,
	ActionKind kind,
	Fn<void()> proceed);

void ShowAccountBadgeBox(not_null<Window::SessionController*> controller);

[[nodiscard]] rpl::producer<not_null<Main::Session*>> Changes();

class AccountBadgeWidget final : public Ui::RpWidget {
public:
	AccountBadgeWidget(
		QWidget *parent,
		not_null<Main::Session*> session);

	void updateContent(PeerData *targetPeer = nullptr);

protected:
	void paintEvent(QPaintEvent *e) override;

private:
	const not_null<Main::Session*> _session;
	QString _label;
	QColor _color;

};

} // namespace Ayu::SendGuard
