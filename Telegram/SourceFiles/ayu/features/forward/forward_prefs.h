/*
This file is part of SleepyGram Desktop,
an unofficial client based on AyuGram Desktop and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_peer_id.h"
#include "data/data_types.h"

#include <QtCore/QString>
#include <optional>

namespace Main {
class Session;
} // namespace Main

namespace Ayu::ForwardPrefs {

[[nodiscard]] bool Enabled();

[[nodiscard]] Data::ForwardOptions ResolveForSession(
	not_null<Main::Session*> session,
	std::optional<PeerId> targetPeer = std::nullopt);

[[nodiscard]] std::optional<Data::ForwardOptions> PeerPreset(
	not_null<Main::Session*> session,
	PeerId peerId);

void SetPeerPreset(
	not_null<Main::Session*> session,
	PeerId peerId,
	std::optional<Data::ForwardOptions> options);

void RememberLast(
	not_null<Main::Session*> session,
	Data::ForwardOptions options);

[[nodiscard]] QString ShortLabel(Data::ForwardOptions options);

} // namespace Ayu::ForwardPrefs
