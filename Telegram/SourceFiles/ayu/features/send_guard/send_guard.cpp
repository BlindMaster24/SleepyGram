/*
This file is part of SleepyGram Desktop,
an unofficial client based on AyuGram Desktop and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/send_guard/send_guard.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "data/data_peer.h"
#include "data/data_user.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "main/session/send_as_peers.h"
#include "storage/storage_account.h"
#include "styles/style_boxes.h"
#include "styles/style_chat_helpers.h"
#include "styles/style_layers.h"
#include "ui/boxes/confirm_box.h"
#include "ui/empty_userpic.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/painter.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <QtGui/QPainterPath>

#include <set>

namespace Ayu::SendGuard {
namespace {

constexpr auto kLabelPrefKey = std::string_view("sleepygram.account.label");
constexpr auto kColorPrefKey = std::string_view("sleepygram.account.color");
constexpr auto kWorkPeersPrefKey = std::string_view("sleepygram.sendGuard.workPeers");

rpl::event_stream<not_null<Main::Session*>> &ChangesStream() {
	static auto stream = rpl::event_stream<not_null<Main::Session*>>();
	return stream;
}

[[nodiscard]] std::set<uint64> LoadWorkPeers(not_null<Main::Session*> session) {
	auto result = std::set<uint64>();
	const auto raw = session->local().readPref<QString>(kWorkPeersPrefKey);
	for (const auto &part : raw.split(',', Qt::SkipEmptyParts)) {
		auto ok = false;
		const auto value = part.trimmed().toULongLong(&ok);
		if (ok && value != 0) {
			result.insert(value);
		}
	}
	return result;
}

void SaveWorkPeers(
		not_null<Main::Session*> session,
		const std::set<uint64> &peers) {
	if (peers.empty()) {
		session->local().clearPref(kWorkPeersPrefKey);
	} else {
		auto list = QStringList();
		list.reserve(int(peers.size()));
		for (const auto value : peers) {
			list.push_back(QString::number(value));
		}
		session->local().writePref<QString>(
			kWorkPeersPrefKey,
			list.join(','));
	}
	ChangesStream().fire_copy(session);
}

[[nodiscard]] QString TrimLabel(QString text, int maxLen = 14) {
	text = text.simplified();
	if (text.size() > maxLen) {
		return text.left(maxLen - 1) + QChar(0x2026);
	}
	return text;
}

} // namespace

QString AccountCustomLabel(not_null<Main::Session*> session) {
	return session->local().readPref<QString>(kLabelPrefKey).trimmed();
}

QString AccountCustomColorHex(not_null<Main::Session*> session) {
	return session->local().readPref<QString>(kColorPrefKey).trimmed();
}

QString AccountShortLabel(
		not_null<Main::Session*> session,
		PeerData *sendAsPeer) {
	auto base = AccountCustomLabel(session);
	if (base.isEmpty()) {
		base = session->user()->shortName();
	}
	if (base.isEmpty()) {
		base = session->user()->name();
	}
	base = TrimLabel(base, 12);
	if (sendAsPeer && sendAsPeer != session->user()) {
		const auto asName = TrimLabel(
			sendAsPeer->shortName().isEmpty()
				? sendAsPeer->name()
				: sendAsPeer->shortName(),
			10);
		if (!asName.isEmpty()) {
			return base + u" / "_q + asName;
		}
	}
	return base;
}

QColor AccountAccentColor(not_null<Main::Session*> session) {
	const auto hex = AccountCustomColorHex(session);
	if (!hex.isEmpty()) {
		const auto parsed = QColor(hex);
		if (parsed.isValid()) {
			return parsed;
		}
	}
	return Ui::EmptyUserpic::UserpicColor(
		session->user()->colorIndex()).color2->c;
}

void SetAccountBadge(
		not_null<Main::Session*> session,
		const QString &label,
		const QString &colorHex) {
	const auto cleanLabel = label.trimmed();
	if (cleanLabel.isEmpty()) {
		session->local().clearPref(kLabelPrefKey);
	} else {
		session->local().writePref<QString>(kLabelPrefKey, cleanLabel);
	}
	const auto cleanHex = colorHex.trimmed();
	if (cleanHex.isEmpty() || !QColor(cleanHex).isValid()) {
		session->local().clearPref(kColorPrefKey);
	} else {
		session->local().writePref<QString>(
			kColorPrefKey,
			QColor(cleanHex).name(QColor::HexRgb));
	}
	ChangesStream().fire_copy(session);
}

bool IsWorkChat(not_null<Main::Session*> session, PeerId peerId) {
	return LoadWorkPeers(session).contains(peerId.value);
}

void SetWorkChat(
		not_null<Main::Session*> session,
		PeerId peerId,
		bool workChat) {
	auto peers = LoadWorkPeers(session);
	const auto changed = workChat
		? peers.insert(peerId.value).second
		: (peers.erase(peerId.value) > 0);
	if (changed) {
		SaveWorkPeers(session, peers);
	}
}

bool NeedsConfirmation(
		not_null<Main::Session*> session,
		PeerId peerId,
		ActionKind kind) {
	const auto prefKey = (kind == ActionKind::Files)
		? Core::kConfirmFilesToWorkChatsKey
		: Core::kConfirmForwardsToWorkChatsKey;
	if (!Core::App().settings().readPref<bool>(prefKey, true)) {
		return false;
	}
	return IsWorkChat(session, peerId);
}

void ConfirmIfNeeded(
		std::shared_ptr<Ui::Show> show,
		not_null<Main::Session*> session,
		not_null<PeerData*> peer,
		ActionKind kind,
		Fn<void()> proceed) {
	if (!show || !NeedsConfirmation(session, peer->id, kind)) {
		proceed();
		return;
	}
	const auto sendAs = session->sendAsPeers().resolveChosen(peer).get();
	const auto from = AccountShortLabel(session, sendAs);
	const auto text = (kind == ActionKind::Files)
		? tr::lng_send_guard_confirm_files(
			tr::now,
			lt_chat,
			peer->name(),
			lt_from,
			from)
		: tr::lng_send_guard_confirm_forward(
			tr::now,
			lt_chat,
			peer->name(),
			lt_from,
			from);
	show->show(Ui::MakeConfirmBox({
		.text = rpl::single(text),
		.confirmed = [=](Fn<void()> close) {
			close();
			proceed();
		},
		.confirmText = tr::lng_send_button(),
	}));
}

void ConfirmManyIfNeeded(
		std::shared_ptr<Ui::Show> show,
		not_null<Main::Session*> session,
		const std::vector<not_null<PeerData*>> &peers,
		ActionKind kind,
		Fn<void()> proceed) {
	if (!show) {
		proceed();
		return;
	}
	auto workNames = QStringList();
	for (const auto &peer : peers) {
		if (NeedsConfirmation(session, peer->id, kind)) {
			workNames.push_back(peer->name());
		}
	}
	if (workNames.isEmpty()) {
		proceed();
		return;
	}
	const auto from = AccountShortLabel(session);
	const auto joined = workNames.join(u", "_q);
	const auto text = (kind == ActionKind::Files)
		? tr::lng_send_guard_confirm_files(
			tr::now,
			lt_chat,
			joined,
			lt_from,
			from)
		: tr::lng_send_guard_confirm_forward(
			tr::now,
			lt_chat,
			joined,
			lt_from,
			from);
	show->show(Ui::MakeConfirmBox({
		.text = rpl::single(text),
		.confirmed = [=](Fn<void()> close) {
			close();
			proceed();
		},
		.confirmText = tr::lng_send_button(),
	}));
}

void ShowAccountBadgeBox(not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(tr::lng_send_guard_badge_title());
		const auto labelField = box->addRow(
			object_ptr<Ui::InputField>(
				box,
				st::defaultInputField,
				tr::lng_send_guard_badge_label_ph(),
				AccountCustomLabel(session)));
		const auto colorField = box->addRow(
			object_ptr<Ui::InputField>(
				box,
				st::defaultInputField,
				tr::lng_send_guard_badge_color_ph(),
				AccountCustomColorHex(session)));
		box->addRow(
			object_ptr<Ui::FlatLabel>(
				box,
				tr::lng_send_guard_badge_about(),
				st::boxDividerLabel),
			style::margins(
				st::boxRowPadding.left(),
				st::defaultVerticalListSkip,
				st::boxRowPadding.right(),
				0));
		const auto save = [=] {
			SetAccountBadge(
				session,
				labelField->getLastText(),
				colorField->getLastText());
			box->closeBox();
		};
		box->addButton(tr::lng_settings_save(), save);
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
		box->setFocusCallback([=] { labelField->setFocusFast(); });
	}));
}

rpl::producer<not_null<Main::Session*>> Changes() {
	return ChangesStream().events();
}

AccountBadgeWidget::AccountBadgeWidget(
		QWidget *parent,
		not_null<Main::Session*> session)
: RpWidget(parent)
, _session(session) {
	setAttribute(Qt::WA_TransparentForMouseEvents);
	hide();
}

void AccountBadgeWidget::updateContent(PeerData *targetPeer) {
	const auto sendAs = targetPeer
		? _session->sendAsPeers().resolveChosen(targetPeer).get()
		: nullptr;
	_label = AccountShortLabel(_session, sendAs);
	_color = AccountAccentColor(_session);

	const auto &font = st::normalFont;
	const auto dotSize = style::ConvertScale(8);
	const auto hPad = style::ConvertScale(8);
	const auto gap = style::ConvertScale(5);
	const auto textWidth = font->width(_label);
	const auto badgeWidth = std::min(
		hPad + dotSize + gap + textWidth + hPad,
		style::ConvertScale(140));
	const auto badgeHeight = style::ConvertScale(24);
	resize(badgeWidth, badgeHeight);
	update();
}

void AccountBadgeWidget::paintEvent(QPaintEvent *e) {
	if (_label.isEmpty()) {
		return;
	}
	auto p = Painter(this);
	auto hq = PainterHighQualityEnabler(p);

	auto bg = _color;
	bg.setAlphaF(0.18);
	auto border = _color;
	border.setAlphaF(0.55);

	const auto r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
	const auto radius = r.height() / 2.0;
	p.setBrush(bg);
	p.setPen(QPen(border, 1.0));
	p.drawRoundedRect(r, radius, radius);

	const auto dotSize = style::ConvertScale(8);
	const auto hPad = style::ConvertScale(8);
	const auto gap = style::ConvertScale(5);
	p.setPen(Qt::NoPen);
	p.setBrush(_color);
	p.drawEllipse(
		hPad,
		(height() - dotSize) / 2,
		dotSize,
		dotSize);

	p.setPen(st::windowFg);
	p.setFont(st::normalFont);
	const auto textLeft = hPad + dotSize + gap;
	const auto textWidth = std::max(0, width() - textLeft - hPad);
	const auto elided = st::normalFont->elided(_label, textWidth);
	p.drawText(
		textLeft,
		(height() - st::normalFont->height) / 2 + st::normalFont->ascent,
		elided);
}

} // namespace Ayu::SendGuard
