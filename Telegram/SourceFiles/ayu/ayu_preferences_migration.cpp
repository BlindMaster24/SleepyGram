// This is the source code of AyuGram for Desktop.
#include "ayu/ayu_preferences_migration.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <algorithm>
#include <array>
#include <charconv>
#include <filesystem>
#include <limits>
#include <set>
#include <string_view>

namespace Ayu::Preferences {
namespace {

using Json = nlohmann::json;
using namespace std::string_view_literals;

constexpr auto kMaximumBytes = 16 * 1024 * 1024;
constexpr auto kMaximumDepth = 16;
constexpr auto kMaxUserId = quint64(0xFFFFFFFFFFFFULL);
constexpr auto kAccountVersion = 1;
constexpr auto kGhostBooleans = std::array{
	"sendReadMessages"sv,
	"sendReadStories"sv,
	"sendOnlinePackets"sv,
	"sendUploadProgress"sv,
	"sendOfflinePacketAfterOnline"sv,
	"markReadAfterAction"sv,
	"useScheduledMessages"sv,
	"suggestGhostModeBeforeViewingStory"sv,
	"rememberGhostRead"sv,
	"sendReadMessagesLocked"sv,
	"sendReadStoriesLocked"sv,
	"sendOnlinePacketsLocked"sv,
	"sendUploadProgressLocked"sv,
	"sendOfflinePacketAfterOnlineLocked"sv,
};

constexpr auto kGlobalBooleans = std::array{
	"useGlobalGhostMode"sv,
	"saveDeletedMessages"sv,
	"saveMessagesHistory"sv,
	"saveForBots"sv,
	"filtersEnabled"sv,
	"filtersEnabledInChats"sv,
	"hideFromBlocked"sv,
	"semiTransparentDeletedMessages"sv,
	"disableAds"sv,
	"disableStories"sv,
	"disableCustomBackgrounds"sv,
	"hidePremiumStatuses"sv,
	"showOnlyAddedEmojisAndStickers"sv,
	"collapseSimilarChannels"sv,
	"hideSimilarChannels"sv,
	"disableOpenLinkWarning"sv,
	"spoofWebviewAsAndroid"sv,
	"increaseWebviewHeight"sv,
	"increaseWebviewWidth"sv,
	"materialSwitches"sv,
	"removeMessageTail"sv,
	"disableNotificationsDelay"sv,
	"showChannelReactions"sv,
	"showGroupReactions"sv,
	"showPrivateChatReactions"sv,
	"simpleQuotesAndReplies"sv,
	"hideFastShare"sv,
	"replaceBottomInfoWithIcons"sv,
	"unlimitedRecentStickers"sv,
	"showAttachButtonInMessageField"sv,
	"showCommandsButtonInMessageField"sv,
	"showEmojiButtonInMessageField"sv,
	"showMicrophoneButtonInMessageField"sv,
	"showAutoDeleteButtonInMessageField"sv,
	"showGiftButtonInMessageField"sv,
	"showAiEditorButtonInMessageField"sv,
	"showAttachPopup"sv,
	"showEmojiPopup"sv,
	"showMyProfileInDrawer"sv,
	"showBotsInDrawer"sv,
	"showNewGroupInDrawer"sv,
	"showNewChannelInDrawer"sv,
	"showContactsInDrawer"sv,
	"showCallsInDrawer"sv,
	"showSavedMessagesInDrawer"sv,
	"showLReadToggleInDrawer"sv,
	"showSReadToggleInDrawer"sv,
	"showNightModeToggleInDrawer"sv,
	"showGhostToggleInDrawer"sv,
	"showStreamerToggleInDrawer"sv,
	"showGhostToggleInTray"sv,
	"showStreamerToggleInTray"sv,
	"hideNotificationCounters"sv,
	"hideNotificationBadge"sv,
	"hideAllChatsFolder"sv,
	"quickAdminShortcuts"sv,
	"disableGreetingSticker"sv,
	"showMessageSeconds"sv,
	"showMessageShot"sv,
	"filterZalgo"sv,
	"stickerConfirmation"sv,
	"gifConfirmation"sv,
	"voiceConfirmation"sv,
	"roundConfirmation"sv,
	"adaptiveCoverColor"sv,
	"improveLinkPreviews"sv,
	"crashReporting"sv,
	"singleCornerRadius"sv,
	"streamerMode"sv,
};

constexpr auto kGlobalEnums = std::array{
	"showReactionsPanelInContextMenu"sv,
	"showViewsPanelInContextMenu"sv,
	"showHideMessageInContextMenu"sv,
	"showUserMessagesInContextMenu"sv,
	"showMessageDetailsInContextMenu"sv,
	"showRepeatMessageInContextMenu"sv,
	"showAddFilterInContextMenu"sv,
	"channelBottomButton"sv,
	"showPeerId"sv,
};

constexpr auto kGlobalStrings = std::array{
	"appIcon"sv,
	"deletedMark"sv,
	"editedMark"sv,
	"monoFont"sv,
};

constexpr auto kShotBooleans = std::array{
	"showBackground"sv,
	"showDate"sv,
	"showReactions"sv,
	"showHeaderDecorations"sv,
	"showColorfulReplies"sv,
	"revealSpoilers"sv,
};

constexpr auto kShotCloudNumbers = std::array{
	"cloudThemeId"sv,
	"cloudThemeAccessHash"sv,
	"cloudThemeDocumentId"sv,
	"cloudThemeAccountId"sv,
};

constexpr auto kOldGhostFields = std::array{
	"sendReadMessages"sv,
	"sendReadStories"sv,
	"sendOnlinePackets"sv,
	"sendUploadProgress"sv,
	"sendOfflinePacketAfterOnline"sv,
	"markReadAfterAction"sv,
	"useScheduledMessages"sv,
	"sendWithoutSound"sv,
};

bool In(const auto &range, std::string_view key) {
	return std::ranges::find(range, key) != range.end();
}

std::optional<Json> Parse(QByteArrayView payload) {
	if (payload.isEmpty() || payload.size() > kMaximumBytes) {
		return std::nullopt;
	}
	auto valid = true;
	auto keys = std::map<int, std::set<std::string>>();
	const auto filter = [&](int depth, Json::parse_event_t event, Json &value) {
		if (depth > kMaximumDepth) {
			valid = false;
		} else if (event == Json::parse_event_t::object_start) {
			keys[depth].clear();
		} else if (event == Json::parse_event_t::key
			&& !keys[depth - 1].insert(value.get<std::string>()).second) {
			valid = false;
		}
		return valid;
	};
	auto result = Json::parse(payload.begin(), payload.end(), filter, false);
	return (valid && result.is_object())
		? std::optional(std::move(result))
		: std::nullopt;
}

QByteArray Bytes(const Json &json) {
	auto result = QByteArray::fromStdString(json.dump());
	return (result.size() <= kMaximumBytes) ? std::move(result) : QByteArray();
}

std::optional<quint64> Unsigned(const Json &value) {
	if (value.is_number_unsigned()) {
		return value.get<quint64>();
	} else if (value.is_number_integer() && value.get<qint64>() >= 0) {
		return quint64(value.get<qint64>());
	}
	return std::nullopt;
}

std::optional<qint64> Signed(const Json &value) {
	if (!value.is_number_integer()
		|| (value.is_number_unsigned()
			&& value.get<quint64>() > quint64(std::numeric_limits<qint64>::max()))) {
		return std::nullopt;
	}
	return value.get<qint64>();
}

bool InRange(const Json &value, qint64 min, qint64 max) {
	const auto number = Signed(value);
	return number && *number >= min && *number <= max;
}

std::optional<quint64> UserFromKey(std::string_view key) {
	auto user = quint64(0);
	const auto parsed = std::from_chars(key.data(), key.data() + key.size(), user);
	return (parsed.ec == std::errc() && parsed.ptr == key.data() + key.size()
		&& std::to_string(user) == key && user <= kMaxUserId)
		? std::optional(user)
		: std::nullopt;
}

bool ValidGhost(const Json &ghost) {
	return ghost.is_object() && std::ranges::all_of(ghost.items(), [](const auto &field) {
		const auto &key = field.key();
		const Json &value = field.value();
		return (key == "sendWithoutSound")
			? (value.is_boolean() || InRange(value, 0, 2))
			: (In(kGhostBooleans, key) && value.is_boolean());
	});
}

bool ValidMessageShot(const Json &shot) {
	return shot.is_object() && std::ranges::all_of(shot.items(), [](const auto &field) {
		const auto &key = field.key();
		const Json &value = field.value();
		if (In(kShotBooleans, key)) {
			return value.is_boolean();
		} else if (In(kShotCloudNumbers, key)) {
			return Unsigned(value) == quint64(0);
		} else if (key == "cloudThemeTitle") {
			return value.is_string() && value.get_ref<const std::string&>().empty();
		} else if (key == "embeddedThemeType" || key == "themeType") {
			return InRange(value, -1, 3);
		} else if (key == "embeddedThemeAccentColor" || key == "themeAccentColor") {
			return InRange(value, 0, std::numeric_limits<quint32>::max());
		}
		return false;
	});
}

bool ValidGlobalField(const std::string &key, const Json &value) {
	if (In(kGlobalBooleans, key)) {
		return value.is_boolean();
	} else if (In(kGlobalEnums, key)) {
		return InRange(value, 0, 2);
	} else if (In(kGlobalStrings, key)) {
		return value.is_string();
	} else if (key == "messageBubbleRadius") {
		return InRange(value, 0, 16);
	} else if (key == "avatarCorners") {
		return InRange(value, 0, std::numeric_limits<int>::max());
	} else if (key == "wideMultiplier") {
		return value.is_number() && value.get<double>() >= 0.5
			&& value.get<double>() <= 4.0;
	} else if (key == "translationProvider") {
		return value.is_string() && In(
			std::array{ "telegram"sv, "google"sv, "yandex"sv, "native"sv },
			value.get_ref<const std::string&>());
	} else if (key == "shadowBanIds") {
		return value.is_array() && value.empty();
	} else if (key == "messageShotSettings") {
		return ValidMessageShot(value);
	} else if (key == "ghostModeSettings") {
		return value.is_object() && (value.empty()
			|| (value.size() == 1 && value.contains("0") && ValidGhost(value["0"])));
	}
	return false;
}

std::optional<std::vector<Watermark>> DecodeWatermarks(const Json &value) {
	if (!value.is_array()) {
		return std::nullopt;
	}
	auto result = std::vector<Watermark>();
	auto unique = std::set<std::pair<quint64, quint64>>();
	for (const auto &entry : value) {
		if (!entry.is_object() || entry.size() != 4 || !entry.contains("peerId")
			|| !entry.contains("topicRootId") || !entry.contains("readTill")
			|| !entry.contains("manuallyUnread") || !entry["manuallyUnread"].is_boolean()) {
			return std::nullopt;
		}
		const auto peer = Unsigned(entry["peerId"]);
		const auto topic = Unsigned(entry["topicRootId"]);
		const auto readTill = Signed(entry["readTill"]);
		const auto unread = entry["manuallyUnread"].get<bool>();
		if (!peer || !*peer || !topic || !readTill || *readTill < 0
			|| (!*readTill && !unread) || !unique.emplace(*peer, *topic).second) {
			return std::nullopt;
		}
		result.push_back({ *peer, *topic, *readTill, unread });
	}
	return result;
}

bool DecodePolicy(const Json &entry, std::map<quint64, int> &policies) {
	if (!entry.is_object() || entry.size() != 2 || !entry.contains("peerId")
		|| !entry.contains("policy")) {
		return false;
	}
	const auto peer = Unsigned(entry["peerId"]);
	const auto policy = Signed(entry["policy"]);
	return peer && *peer && policy && (*policy == 0 || *policy == 1)
		&& policies.emplace(*peer, int(*policy)).second;
}

bool SplitAccountMap(
		const std::string &key,
		const Json &map,
		Json &globals,
		std::map<quint64, AccountData> &accounts) {
	if (!map.is_object()) {
		return false;
	}
	for (const auto &[identity, value] : map.items()) {
		const auto id = UserFromKey(identity);
		if (!id) {
			return false;
		} else if (!*id && key == "ghostModeSettings" && ValidGhost(value)) {
			globals[key]["0"] = value;
			continue;
		}
		const auto account = accounts.find(*id);
		if (account == accounts.end()) {
			return false;
		}
		if (key == "ghostModeSettings" && ValidGhost(value)) {
			account->second.ghostMode = value;
		} else if (key == "ghostReadState") {
			auto read = DecodeWatermarks(value);
			if (!read) {
				return false;
			}
			account->second.watermarks = std::move(*read);
		} else if (key == "countFilteredUnreadInBadge" && value.is_boolean()) {
			account->second.filteredUnread = value.get<bool>();
		} else {
			return false;
		}
	}
	return true;
}

bool SplitPolicies(const Json &array, std::map<quint64, AccountData> &accounts) {
	if (!array.is_array()) {
		return false;
	}
	for (auto entry : array) {
		if (!entry.is_object() || !entry.contains("accountId")) {
			return false;
		}
		const auto owner = Unsigned(entry["accountId"]);
		const auto account = owner ? accounts.find(*owner) : accounts.end();
		entry.erase("accountId");
		if (account == accounts.end() || !DecodePolicy(entry, account->second.deletedPolicies)) {
			return false;
		}
	}
	return true;
}

} // namespace

bool ValidateScopedGlobalPreferences(QByteArrayView payload) {
	const auto value = Parse(payload);
	return value && std::ranges::all_of(value->items(), [](const auto &field) {
		return ValidGlobalField(field.key(), field.value());
	});
}

QByteArray EncodeAccountData(quint64 user, const AccountData &data) {
	auto watermarks = Json::array();
	for (const auto &mark : data.watermarks) {
		watermarks.push_back({
			{ "peerId", mark.peerId },
			{ "topicRootId", mark.topicRootId },
			{ "readTill", mark.readTill },
			{ "manuallyUnread", mark.manuallyUnread },
		});
	}
	auto policies = Json::array();
	for (const auto &[peer, policy] : data.deletedPolicies) {
		policies.push_back({ { "peerId", peer }, { "policy", policy } });
	}
	return Bytes(Json{
		{ "version", kAccountVersion },
		{ "owner", user },
		{ "ghostMode", data.ghostMode ? *data.ghostMode : Json() },
		{ "watermarks", std::move(watermarks) },
		{ "filteredUnread", data.filteredUnread },
		{ "deletedPolicies", std::move(policies) },
	});
}

std::optional<AccountData> DecodeAccountData(
		QByteArrayView payload,
		quint64 expectedUser) {
	const auto value = Parse(payload);
	if (!value || !expectedUser || expectedUser > kMaxUserId || value->size() != 6
		|| !value->contains("version") || Signed((*value)["version"]) != kAccountVersion
		|| !value->contains("owner") || Unsigned((*value)["owner"]) != expectedUser
		|| !value->contains("ghostMode") || !value->contains("watermarks")
		|| !value->contains("filteredUnread") || !(*value)["filteredUnread"].is_boolean()
		|| !value->contains("deletedPolicies") || !(*value)["deletedPolicies"].is_array()) {
		return std::nullopt;
	}
	auto result = AccountData();
	const auto &ghost = (*value)["ghostMode"];
	if (!ghost.is_null()) {
		if (!ValidGhost(ghost)) {
			return std::nullopt;
		}
		result.ghostMode = ghost;
	}
	auto watermarks = DecodeWatermarks((*value)["watermarks"]);
	if (!watermarks) {
		return std::nullopt;
	}
	result.watermarks = std::move(*watermarks);
	result.filteredUnread = (*value)["filteredUnread"].get<bool>();
	for (const auto &entry : (*value)["deletedPolicies"]) {
		if (!DecodePolicy(entry, result.deletedPolicies)) {
			return std::nullopt;
		}
	}
	return result;
}

std::optional<LegacyPartition> PartitionLegacyPreferences(
		QByteArrayView source,
		std::span<const quint64> verifiedUsers) {
	const auto input = Parse(source);
	if (!input || verifiedUsers.empty() || verifiedUsers.size() > 200) {
		return std::nullopt;
	}
	auto accounts = std::map<quint64, AccountData>();
	for (const auto user : verifiedUsers) {
		if (!user || user > kMaxUserId || !accounts.try_emplace(user).second) {
			return std::nullopt;
		}
	}
	auto globals = Json::object();
	auto oldGhost = Json::object();
	for (const auto &[key, value] : input->items()) {
		if (key == "ghostModeSettings" || key == "ghostReadState"
			|| key == "countFilteredUnreadInBadge") {
			if (!SplitAccountMap(key, value, globals, accounts)) {
				return std::nullopt;
			}
		} else if (key == "deletedMessagePolicies") {
			if (!SplitPolicies(value, accounts)) {
				return std::nullopt;
			}
		} else if (!input->contains("ghostModeSettings") && In(kOldGhostFields, key)) {
			oldGhost[key] = value;
		} else if (ValidGlobalField(key, value)) {
			globals[key] = value;
		} else {
			return std::nullopt;
		}
	}
	if (!input->contains("ghostModeSettings")) {
		if (!ValidGhost(oldGhost)) {
			return std::nullopt;
		}
		globals["ghostModeSettings"]["0"] = std::move(oldGhost);
		globals["useGlobalGhostMode"] = true;
	}
	auto result = LegacyPartition{
		.sourceSha256 = QCryptographicHash::hash(source, QCryptographicHash::Sha256),
		.globals = Bytes(globals),
	};
	if (result.globals.isEmpty()) {
		return std::nullopt;
	}
	for (const auto &[user, values] : accounts) {
		auto record = EncodeAccountData(user, values);
		if (record.isEmpty()) {
			return std::nullopt;
		}
		result.accounts.emplace(user, std::move(record));
	}
	return result;
}

std::optional<LegacyPartition> ReadLegacyPartition(
		const QString &dataDirectory,
		std::span<const quint64> verifiedUsers) {
	const auto root = QFileInfo(dataDirectory);
	if (QDir::cleanPath(dataDirectory) != dataDirectory || root.isSymLink()
		|| root.isJunction() || !root.isDir()
		|| root.canonicalFilePath() != dataDirectory || !QDir(dataDirectory).isReadable()) {
		return std::nullopt;
	}
	const auto path = QDir(dataDirectory).filePath(QString::fromLatin1("ayu_settings.json"));
	const auto info = QFileInfo(path);
	if (info.isSymLink() || info.isJunction()) {
		return std::nullopt;
	} else if (!info.exists()) {
		auto empty = PartitionLegacyPreferences("{}", verifiedUsers);
		if (empty) {
			empty->sourceSha256.clear();
		}
		return empty;
	}
	auto error = std::error_code();
	auto file = QFile(path);
	if (!info.isFile() || info.canonicalFilePath() != path
		|| info.size() <= 0 || info.size() > kMaximumBytes
		|| std::filesystem::hard_link_count(info.filesystemFilePath(), error) != 1
		|| error || !file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	const auto bytes = file.read(kMaximumBytes + 1);
	return file.atEnd() && bytes.size() == info.size()
		? PartitionLegacyPreferences(bytes, verifiedUsers)
		: std::nullopt;
}

} // namespace Ayu::Preferences
