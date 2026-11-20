/*
This file is part of SleepyGram Desktop,
an unofficial client based on AyuGram Desktop and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/forward/forward_prefs.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "storage/storage_account.h"

#include <string>

namespace Ayu::ForwardPrefs {
namespace {

constexpr auto kLastKey = std::string_view("sleepygram.forward.lastOptions");

[[nodiscard]] std::string PeerPrefKey(PeerId peerId) {
	return "sleepygram.forward.peer." + std::to_string(peerId.value);
}

[[nodiscard]] std::optional<Data::ForwardOptions> ParseValue(
		const QString &raw) {
	if (raw == u"preserve"_q) {
		return Data::ForwardOptions::PreserveInfo;
	} else if (raw == u"no_names"_q) {
		return Data::ForwardOptions::NoSenderNames;
	} else if (raw == u"no_captions"_q) {
		return Data::ForwardOptions::NoNamesAndCaptions;
	}
	return std::nullopt;
}

[[nodiscard]] QString SerializeValue(Data::ForwardOptions options) {
	switch (options) {
	case Data::ForwardOptions::PreserveInfo:
		return u"preserve"_q;
	case Data::ForwardOptions::NoSenderNames:
		return u"no_names"_q;
	case Data::ForwardOptions::NoNamesAndCaptions:
		return u"no_captions"_q;
	}
	return u"preserve"_q;
}

} // namespace

bool Enabled() {
	return Core::App().settings().readPref<bool>(
		Core::kRememberForwardModeKey,
		true);
}

std::optional<Data::ForwardOptions> PeerPreset(
		not_null<Main::Session*> session,
		PeerId peerId) {
	return ParseValue(session->local().readPref<QString>(PeerPrefKey(peerId)));
}

void SetPeerPreset(
		not_null<Main::Session*> session,
		PeerId peerId,
		std::optional<Data::ForwardOptions> options) {
	const auto key = PeerPrefKey(peerId);
	if (!options) {
		session->local().clearPref(key);
	} else {
		session->local().writePref<QString>(key, SerializeValue(*options));
	}
}

void RememberLast(
		not_null<Main::Session*> session,
		Data::ForwardOptions options) {
	if (!Enabled()) {
		return;
	}
	session->local().writePref<QString>(kLastKey, SerializeValue(options));
}

Data::ForwardOptions ResolveForSession(
		not_null<Main::Session*> session,
		std::optional<PeerId> targetPeer) {
	if (targetPeer) {
		if (const auto preset = PeerPreset(session, *targetPeer)) {
			return *preset;
		}
	}
	if (!Enabled()) {
		return Data::ForwardOptions::PreserveInfo;
	}
	if (const auto last = ParseValue(
			session->local().readPref<QString>(kLastKey))) {
		return *last;
	}
	return Data::ForwardOptions::PreserveInfo;
}

QString ShortLabel(Data::ForwardOptions options) {
	switch (options) {
	case Data::ForwardOptions::PreserveInfo:
		return tr::lng_forward_preset_preserve(tr::now);
	case Data::ForwardOptions::NoSenderNames:
		return tr::lng_forward_preset_no_sender(tr::now);
	case Data::ForwardOptions::NoNamesAndCaptions:
		return tr::lng_forward_preset_no_captions(tr::now);
	}
	return tr::lng_forward_preset_preserve(tr::now);
}

} // namespace Ayu::ForwardPrefs
