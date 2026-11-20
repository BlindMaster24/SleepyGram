#pragma once

#include "base/basic_types.h"
#include "base/required.h"
#include "data/data_peer_id.h"

namespace Data {
struct ItemNotification;
} // namespace Data

namespace Main {
class Session;
} // namespace Main

namespace Ayu::NotifyBatch {

[[nodiscard]] bool IsEnabledForPeer(
	not_null<Main::Session*> session,
	PeerId peerId);
void SetEnabledForPeer(
	not_null<Main::Session*> session,
	PeerId peerId,
	bool enabled);

[[nodiscard]] int QuietSeconds();
void SetQuietSeconds(int seconds);
[[nodiscard]] int MaxWaitSeconds();
void SetMaxWaitSeconds(int seconds);

[[nodiscard]] crl::time QuietWindowMs();
[[nodiscard]] crl::time MaxWaitMs();

[[nodiscard]] bool ShouldBypass(const Data::ItemNotification &notification);

} // namespace Ayu::NotifyBatch
