#include "ayu/features/notify_batch/notify_batch.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "data/data_thread.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "main/main_session.h"
#include "storage/storage_account.h"

#include <algorithm>
#include <string>

namespace Ayu::NotifyBatch {
namespace {

constexpr auto kDefaultQuietSec = 30;
constexpr auto kDefaultMaxWaitSec = 180;

[[nodiscard]] std::string PeerPrefKey(PeerId peerId) {
	return "sleepygram.notifyBatch." + std::to_string(peerId.value);
}

} // namespace

bool IsEnabledForPeer(not_null<Main::Session*> session, PeerId peerId) {
	return session->local().readPref<bool>(PeerPrefKey(peerId), false);
}

void SetEnabledForPeer(
		not_null<Main::Session*> session,
		PeerId peerId,
		bool enabled) {
	const auto key = PeerPrefKey(peerId);
	if (!enabled) {
		session->local().clearPref(key);
	} else {
		session->local().writePref<bool>(key, true);
	}
}

int QuietSeconds() {
	const auto raw = Core::App().settings().readPref<QString>(
		Core::kNotifyBatchQuietSecKey);
	auto ok = false;
	const auto parsed = raw.toInt(&ok);
	return ok ? std::clamp(parsed, 5, 300) : kDefaultQuietSec;
}

void SetQuietSeconds(int seconds) {
	const auto clamped = std::clamp(seconds, 5, 300);
	Core::App().settings().writePref<QString>(
		Core::kNotifyBatchQuietSecKey,
		QString::number(clamped));
	Core::App().saveSettingsDelayed();
}

int MaxWaitSeconds() {
	const auto raw = Core::App().settings().readPref<QString>(
		Core::kNotifyBatchMaxWaitSecKey);
	auto ok = false;
	const auto parsed = raw.toInt(&ok);
	return ok
		? std::clamp(parsed, std::max(QuietSeconds(), 15), 900)
		: std::max(kDefaultMaxWaitSec, QuietSeconds());
}

void SetMaxWaitSeconds(int seconds) {
	const auto clamped = std::clamp(seconds, 15, 900);
	Core::App().settings().writePref<QString>(
		Core::kNotifyBatchMaxWaitSecKey,
		QString::number(clamped));
	Core::App().saveSettingsDelayed();
}

crl::time QuietWindowMs() {
	return crl::time(QuietSeconds()) * crl::time(1000);
}

crl::time MaxWaitMs() {
	return crl::time(MaxWaitSeconds()) * crl::time(1000);
}

bool ShouldBypass(const Data::ItemNotification &notification) {
	if (notification.type != Data::ItemNotificationType::Message) {
		return true;
	}
	if (notification.keywordOverride) {
		return true;
	}
	const auto item = notification.item;
	if (item->out() || item->mentionsMe()) {
		return true;
	}
	if (const auto media = item->media(); media && media->call()) {
		return true;
	}
	if (const auto reply = item->Get<HistoryMessageReply>()) {
		if (const auto message = reply->resolvedMessage.get()) {
			if (message->out()) {
				return true;
			}
		}
	}
	return false;
}

} // namespace Ayu::NotifyBatch
