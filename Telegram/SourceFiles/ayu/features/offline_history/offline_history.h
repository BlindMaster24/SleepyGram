// This is the source code of AyuGram for Desktop.
#pragma once

#include "base/basic_types.h"
#include "data/data_peer_id.h"

namespace Main {
class Session;
} // namespace Main

namespace Window {
class SessionController;
} // namespace Window

namespace Ayu::OfflineHistory {

[[nodiscard]] bool Available(not_null<Main::Session*> session);
void Open(
	not_null<Window::SessionController*> controller,
	PeerId peerId);
void CloseForChat(uint64 accountId, PeerId peerId);

} // namespace Ayu::OfflineHistory
