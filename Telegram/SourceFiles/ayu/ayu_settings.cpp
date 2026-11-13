// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/ayu_settings.h"

#include "ayu/ayu_infra.h"
#include "ayu/data/ayu_database.h"
#include "ayu/data/entities.h"
#include "base/timer.h"
#include "lang_auto.h"
#include "tray.h"
#include "ayu/ayu_ui_settings.h"
#include "ayu/ayu_worker.h"
#include "ayu/features/streamer_mode/streamer_mode.h"
#include "ayu/ui/ayu_logo.h"
#include "core/application.h"
#include "data/data_histories.h"
#include "data/data_session.h"
#include "features/filters/filters_cache_controller.h"
#include "features/translator/ayu_translator.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "platform/platform_translate_provider.h"
#include "rpl/combine.h"
#include "window/main_window.h"
#include "window/window_controller.h"

#ifdef Q_OS_WIN
#include "ayu/utils/windows_utils.h"
#endif

#include <charconv>
#include <cmath>
#include <fstream>
#include <ranges>
#include <set>
#include <QApplication>
#include <QFile>
#include <QSaveFile>
#include <QUuid>
#include "unicode/regex.h"

using json = nlohmann::json;

namespace {

std::string getSettingsPath() {
	return (cWorkingDir() + u"tdata/ayu_settings.json"_q).toStdString();
}

QString getSettingsFilePath() {
	return QString::fromStdString(getSettingsPath());
}

const std::vector<std::string> &transferSettingKeys() {
	static const auto keys = std::vector<std::string>{
		"useGlobalGhostMode",
		"saveDeletedMessages",
		"saveMessagesHistory",
		"saveForBots",
		"filtersEnabled",
		"filtersEnabledInChats",
		"hideFromBlocked",
		"semiTransparentDeletedMessages",
		"disableAds",
		"disableStories",
		"disableCustomBackgrounds",
		"hidePremiumStatuses",
		"showOnlyAddedEmojisAndStickers",
		"collapseSimilarChannels",
		"hideSimilarChannels",
		"messageBubbleRadius",
		"wideMultiplier",
		"increaseWebviewHeight",
		"increaseWebviewWidth",
		"materialSwitches",
		"removeMessageTail",
		"disableNotificationsDelay",
		"showChannelReactions",
		"showGroupReactions",
		"showPrivateChatReactions",
		"appIcon",
		"simpleQuotesAndReplies",
		"hideFastShare",
		"replaceBottomInfoWithIcons",
		"deletedMark",
		"editedMark",
		"unlimitedRecentStickers",
		"showReactionsPanelInContextMenu",
		"showViewsPanelInContextMenu",
		"showHideMessageInContextMenu",
		"showUserMessagesInContextMenu",
		"showMessageDetailsInContextMenu",
		"showRepeatMessageInContextMenu",
		"showAddFilterInContextMenu",
		"showAttachButtonInMessageField",
		"showCommandsButtonInMessageField",
		"showEmojiButtonInMessageField",
		"showMicrophoneButtonInMessageField",
		"showAutoDeleteButtonInMessageField",
		"showGiftButtonInMessageField",
		"showAiEditorButtonInMessageField",
		"showAttachPopup",
		"showEmojiPopup",
		"showMyProfileInDrawer",
		"showBotsInDrawer",
		"showNewGroupInDrawer",
		"showNewChannelInDrawer",
		"showContactsInDrawer",
		"showCallsInDrawer",
		"showSavedMessagesInDrawer",
		"showLReadToggleInDrawer",
		"showSReadToggleInDrawer",
		"showNightModeToggleInDrawer",
		"showGhostToggleInDrawer",
		"showStreamerToggleInDrawer",
		"showGhostToggleInTray",
		"showStreamerToggleInTray",
		"monoFont",
		"hideNotificationCounters",
		"hideNotificationBadge",
		"hideAllChatsFolder",
		"channelBottomButton",
		"quickAdminShortcuts",
		"disableGreetingSticker",
		"showPeerId",
		"showMessageSeconds",
		"showMessageShot",
		"filterZalgo",
		"stickerConfirmation",
		"gifConfirmation",
		"voiceConfirmation",
		"roundConfirmation",
		"translationProvider",
		"adaptiveCoverColor",
		"improveLinkPreviews",
		"avatarCorners",
		"singleCornerRadius",
		"streamerMode",
		"messageShotSettings",
	};
	return keys;
}

const std::vector<std::string> &messageShotTransferKeys() {
	static const auto keys = std::vector<std::string>{
		"showBackground",
		"showDate",
		"showReactions",
		"showHeaderDecorations",
		"showColorfulReplies",
		"revealSpoilers",
		"embeddedThemeType",
		"embeddedThemeAccentColor",
	};
	return keys;
}

struct SettingsTransferData {
	json settings;
	json ghostMode;
	std::vector<RegexFilter> filters;
	std::vector<RegexFilterGlobalExclusion> exclusions;
};

bool hasExactKeys(const json &value, const std::vector<std::string> &keys) {
	if (!value.is_object() || value.size() != keys.size()) {
		return false;
	}
	return std::ranges::all_of(keys, [&](const auto &key) {
		return value.contains(key);
	});
}

bool matchesJsonType(const json &value, const json &example) {
	if (example.is_boolean()) return value.is_boolean();
	if (example.is_number_integer()) return value.is_number_integer();
	if (example.is_number_float()) return value.is_number();
	if (example.is_string()) return value.is_string();
	return false;
}

bool validatePreferences(const json &preferences, QString *error) {
	const auto current = json(AyuSettings::getInstance());
	if (!hasExactKeys(preferences, transferSettingKeys())) {
		*error = u"The settings section is incomplete or contains unsupported fields."_q;
		return false;
	}
	for (const auto &key : transferSettingKeys()) {
		if (key == "messageShotSettings") {
			continue;
		}
		if (!matchesJsonType(preferences.at(key), current.at(key))) {
			*error = u"A setting has an invalid value type."_q;
			return false;
		}
	}
	if (!hasExactKeys(preferences.at("messageShotSettings"), messageShotTransferKeys())) {
		*error = u"The message shot settings section is invalid."_q;
		return false;
	}
	for (const auto &key : messageShotTransferKeys()) {
		if (!matchesJsonType(
				preferences.at("messageShotSettings").at(key),
				current.at("messageShotSettings").at(key))) {
			*error = u"A message shot setting has an invalid value type."_q;
			return false;
		}
	}
	const auto numberInRange = [&](const char *key, double min, double max) {
		const auto &value = preferences.at(key);
		return value.is_number()
			&& std::isfinite(value.get<double>())
			&& value.get<double>() >= min
			&& value.get<double>() <= max;
	};
	if (!numberInRange("messageBubbleRadius", 0, 16)
		|| !numberInRange("wideMultiplier", 0.5, 4.0)
		|| !numberInRange("avatarCorners", 0, AyuUiSettings::kMaxAvatarCorners)) {
		*error = u"A numeric setting is outside its supported range."_q;
		return false;
	}
	const auto enumInRange = [&](const char *key, int max) {
		const auto &value = preferences.at(key);
		return value.is_number_integer()
			&& value.get<int64>() >= 0
			&& value.get<int64>() <= max;
	};
	if (!enumInRange("showPeerId", 2)
		|| !enumInRange("channelBottomButton", 2)
		|| !enumInRange("showReactionsPanelInContextMenu", 2)
		|| !enumInRange("showViewsPanelInContextMenu", 2)
		|| !enumInRange("showHideMessageInContextMenu", 2)
		|| !enumInRange("showUserMessagesInContextMenu", 2)
		|| !enumInRange("showMessageDetailsInContextMenu", 2)
		|| !enumInRange("showRepeatMessageInContextMenu", 2)
		|| !enumInRange("showAddFilterInContextMenu", 2)) {
		*error = u"An enum setting has an unsupported value."_q;
		return false;
	}
	const auto &provider = preferences.at("translationProvider");
	if (provider != "telegram" && provider != "google"
		&& provider != "yandex" && provider != "native") {
		*error = u"The translation provider is unsupported."_q;
		return false;
	}
	if (provider == "native" && !Platform::IsTranslateProviderAvailable()) {
		*error = u"The selected translation provider is unavailable on this device."_q;
		return false;
	}
	const auto &icon = preferences.at("appIcon").get_ref<const std::string &>();
	if (icon != "default" && icon != "alt" && icon != "discord"
		&& icon != "spotify" && icon != "extera" && icon != "nothing"
		&& icon != "bard" && icon != "yaplus" && icon != "win95"
		&& icon != "chibi" && icon != "chibi2" && icon != "extera2") {
		*error = u"The selected app icon is unsupported."_q;
		return false;
	}
	const auto &shot = preferences.at("messageShotSettings");
	if (shot.at("embeddedThemeType").get<int>() < -1
		|| shot.at("embeddedThemeType").get<int>() > 3
		|| shot.at("embeddedThemeAccentColor").get<int64>() < 0
		|| shot.at("embeddedThemeAccentColor").get<uint64>() > 0xFFFFFFFFULL) {
		*error = u"The message shot theme settings are invalid."_q;
		return false;
	}
	for (const auto &key : { "appIcon", "deletedMark", "editedMark", "monoFont" }) {
		if (preferences.at(key).get<std::string>().size() > 256) {
			*error = u"A text setting is too long."_q;
			return false;
		}
	}
	return true;
}

bool validateGhostMode(const json &ghostMode, QString *error) {
	GhostModeAccountSettings defaults;
	const auto example = json(defaults);
	std::vector<std::string> keys;
	for (const auto &[key, value] : example.items()) {
		keys.push_back(key);
	}
	if (!hasExactKeys(ghostMode, keys)) {
		*error = u"The account settings section is incomplete or contains unsupported fields."_q;
		return false;
	}
	for (const auto &[key, value] : example.items()) {
		if (!matchesJsonType(ghostMode.at(key), value)) {
			*error = u"An account setting has an invalid value type."_q;
			return false;
		}
	}
	const auto sound = ghostMode.at("sendWithoutSound");
	if (sound.get<int64>() < 0 || sound.get<int64>() > 2) {
		*error = u"The sound option has an unsupported value."_q;
		return false;
	}
	return true;
}

bool parseSettingsTransfer(
		const QByteArray &data,
		SettingsTransferData *result,
		QString *error) {
	if (data.isEmpty() || data.size() > 5 * 1024 * 1024) {
		*error = u"The settings file is empty or too large."_q;
		return false;
	}
	try {
		const auto bundle = json::parse(data.constData(), data.constData() + data.size());
		const auto rootKeys = std::vector<std::string>{
			"format", "version", "settings", "accountSettings", "filters", "exclusions",
		};
		if (!hasExactKeys(bundle, rootKeys)
			|| bundle.at("format") != "SleepyGram.settings"
			|| !bundle.at("version").is_number_integer()
			|| bundle.at("version") != 1) {
			*error = u"This is not a supported SleepyGram settings file."_q;
			return false;
		}
		const auto &preferences = bundle.at("settings");
		if (!validatePreferences(preferences, error)) {
			return false;
		}
		const auto &account = bundle.at("accountSettings");
		const auto accountKeys = std::vector<std::string>{ "ghostMode" };
		if (!hasExactKeys(account, accountKeys)
			|| !validateGhostMode(account.at("ghostMode"), error)) {
			return false;
		}
		if (!bundle.at("filters").is_array()
			|| !bundle.at("exclusions").is_array()
			|| bundle.at("filters").size() > 1000
			|| bundle.at("exclusions").size() > 5000) {
			*error = u"The filter list is invalid or too large."_q;
			return false;
		}
		const auto &filterJson = bundle.at("filters");
		const auto filterKeys = std::vector<std::string>{
			"dialogId", "text", "enabled", "reversed", "caseInsensitive",
		};
		auto filters = std::vector<RegexFilter>();
		filters.reserve(filterJson.size());
		for (const auto &entry : filterJson) {
			if (!hasExactKeys(entry, filterKeys)
				|| !entry.at("text").is_string()
				|| !entry.at("enabled").is_boolean()
				|| !entry.at("reversed").is_boolean()
				|| !entry.at("caseInsensitive").is_boolean()
				|| (!entry.at("dialogId").is_null()
					&& !entry.at("dialogId").is_number_integer())) {
				*error = u"A filter entry has invalid fields."_q;
				return false;
			}
			const auto text = entry.at("text").get<std::string>();
			if (text.empty() || text.size() > 4096) {
				*error = u"A filter pattern is empty or too long."_q;
				return false;
			}
			auto filter = RegexFilter();
			const auto id = QUuid::createUuid().toRfc4122();
			filter.id.assign(id.begin(), id.end());
			filter.text = text;
			filter.enabled = entry.at("enabled").get<bool>();
			filter.reversed = entry.at("reversed").get<bool>();
			filter.caseInsensitive = entry.at("caseInsensitive").get<bool>();
			if (!entry.at("dialogId").is_null()) {
				filter.dialogId = entry.at("dialogId").get<ID>();
			}
			int flags = UREGEX_MULTILINE;
			if (filter.caseInsensitive) {
				flags |= UREGEX_CASE_INSENSITIVE;
			}
			auto status = U_ZERO_ERROR;
			auto pattern = std::unique_ptr<icu::RegexPattern>(icu::RegexPattern::compile(
				icu::UnicodeString::fromUTF8(filter.text),
				flags,
				status));
			if (!pattern || U_FAILURE(status)) {
				*error = u"A filter contains an invalid regular expression."_q;
				return false;
			}
			filters.push_back(std::move(filter));
		}
		auto exclusions = std::vector<RegexFilterGlobalExclusion>();
		auto seen = std::set<std::pair<ID, std::size_t>>();
		const auto exclusionKeys = std::vector<std::string>{ "dialogId", "filterIndex" };
		for (const auto &entry : bundle.at("exclusions")) {
			if (!hasExactKeys(entry, exclusionKeys)
				|| !entry.at("dialogId").is_number_integer()
				|| !entry.at("filterIndex").is_number_integer()) {
				*error = u"A filter exclusion has invalid fields."_q;
				return false;
			}
			const auto dialogId = entry.at("dialogId").get<ID>();
			const auto index = entry.at("filterIndex").get<std::size_t>();
			if (index >= filters.size() || !seen.emplace(dialogId, index).second) {
				*error = u"A filter exclusion points to a missing or duplicate filter."_q;
				return false;
			}
			exclusions.push_back({
				.fakeId = 0,
				.dialogId = dialogId,
				.filterId = filters[index].id,
			});
		}
		result->settings = preferences;
		result->ghostMode = account.at("ghostMode");
		result->filters = std::move(filters);
		result->exclusions = std::move(exclusions);
		return true;
	} catch (const std::exception &) {
		*error = u"The settings file contains invalid JSON data."_q;
		return false;
	}
}

bool writeSettingsFile(const json &contents) {
	auto file = QSaveFile(getSettingsFilePath());
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	const auto bytes = QByteArray::fromStdString(contents.dump(4));
	return file.write(bytes) == bytes.size() && file.commit();
}

bool restoreSettingsFile(bool existed, const QByteArray &previous) {
	if (!existed) {
		return !QFile::exists(getSettingsFilePath())
			|| QFile::remove(getSettingsFilePath());
	}
	auto file = QSaveFile(getSettingsFilePath());
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	return file.write(previous) == previous.size() && file.commit();
}

void repaintApp() {
	for (QWidget *widget : QApplication::allWidgets()) {
		widget->update();
	}
}

rpl::lifetime lifetime; // idk reactivity dies when placed in `GhostModeAccountSettings` as field

base::Timer &ghostReadSaveTimer() {
	static base::Timer timer([] {
		AyuSettings::save();
	});
	return timer;
}

} // namespace

GhostModeAccountSettings::GhostModeAccountSettings() {
	rpl::combine(
		_sendReadMessages.value(),
		_sendReadMessagesLocked.value(),
		_sendReadStories.value(),
		_sendReadStoriesLocked.value(),
		_sendOnlinePackets.value(),
		_sendOnlinePacketsLocked.value(),
		_sendUploadProgress.value(),
		_sendUploadProgressLocked.value(),
		_sendOfflinePacketAfterOnline.value(),
		_sendOfflinePacketAfterOnlineLocked.value()
	) | rpl::on_next([=](
			bool readMsg, bool readMsgLocked,
			bool readStories, bool readStoriesLocked,
			bool online, bool onlineLocked,
			bool upload, bool uploadLocked,
			bool offline, bool offlineLocked) {
		_ghostModeActive = (readMsgLocked || !readMsg)
			&& (readStoriesLocked || !readStories)
			&& (onlineLocked || !online)
			&& (uploadLocked || !upload)
			&& (offlineLocked || offline);
	}, lifetime);
}

void GhostModeAccountSettings::setSendReadMessages(bool val) {
	if (_sendReadMessages.current() == val) return;
	_sendReadMessages = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendReadStories(bool val) {
	if (_sendReadStories.current() == val) return;
	_sendReadStories = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendOnlinePackets(bool val) {
	if (_sendOnlinePackets.current() == val) return;
	_sendOnlinePackets = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendUploadProgress(bool val) {
	if (_sendUploadProgress.current() == val) return;
	_sendUploadProgress = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendOfflinePacketAfterOnline(bool val) {
	if (_sendOfflinePacketAfterOnline.current() == val) return;
	_sendOfflinePacketAfterOnline = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setMarkReadAfterAction(bool val) {
	if (_markReadAfterAction.current() == val) return;
	_markReadAfterAction = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setUseScheduledMessages(bool val) {
	if (_useScheduledMessages.current() == val) return;
	_useScheduledMessages = val;
	AyuSettings::save();
}

bool GhostModeAccountSettings::shouldSendWithoutSound() const {
	switch (_sendWithoutSound.current()) {
	case SendWithoutSoundOption::Never:
		return false;
	case SendWithoutSoundOption::InGhostMode:
		return isGhostModeActive();
	case SendWithoutSoundOption::Always:
		return true;
	}
	Unexpected("Value in GhostModeAccountSettings::shouldSendWithoutSound.");
}

void GhostModeAccountSettings::setSendWithoutSound(
		SendWithoutSoundOption val) {
	if (_sendWithoutSound.current() == val) return;
	_sendWithoutSound = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSuggestGhostModeBeforeViewingStory(bool val) {
	if (_suggestGhostModeBeforeViewingStory.current() == val) return;
	_suggestGhostModeBeforeViewingStory = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setRememberGhostRead(bool val) {
	if (_rememberGhostRead.current() == val) return;
	_rememberGhostRead = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setGhostModeEnabled(bool val) {
	if (!_sendReadMessagesLocked.current()) _sendReadMessages = !val;
	if (!_sendReadStoriesLocked.current()) _sendReadStories = !val;
	if (!_sendOnlinePacketsLocked.current()) _sendOnlinePackets = !val;
	if (!_sendUploadProgressLocked.current()) _sendUploadProgress = !val;
	if (!_sendOfflinePacketAfterOnlineLocked.current()) _sendOfflinePacketAfterOnline = val;
	AyuSettings::save();

	if (val) {
		if (const auto window = Core::App().activeWindow()) {
			if (const auto session = window->maybeSession()) {
				AyuWorker::markAsOnline(session);
			}
		}
	}
}

void GhostModeAccountSettings::setSendReadMessagesLocked(bool val) {
	if (_sendReadMessagesLocked.current() == val) return;
	_sendReadMessagesLocked = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendReadStoriesLocked(bool val) {
	if (_sendReadStoriesLocked.current() == val) return;
	_sendReadStoriesLocked = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendOnlinePacketsLocked(bool val) {
	if (_sendOnlinePacketsLocked.current() == val) return;
	_sendOnlinePacketsLocked = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendUploadProgressLocked(bool val) {
	if (_sendUploadProgressLocked.current() == val) return;
	_sendUploadProgressLocked = val;
	AyuSettings::save();
}

void GhostModeAccountSettings::setSendOfflinePacketAfterOnlineLocked(bool val) {
	if (_sendOfflinePacketAfterOnlineLocked.current() == val) return;
	_sendOfflinePacketAfterOnlineLocked = val;
	AyuSettings::save();
}

void to_json(nlohmann::json &j, const GhostModeAccountSettings &s) {
	j = nlohmann::json{
		{"sendReadMessages", s._sendReadMessages.current()},
		{"sendReadStories", s._sendReadStories.current()},
		{"sendOnlinePackets", s._sendOnlinePackets.current()},
		{"sendUploadProgress", s._sendUploadProgress.current()},
		{"sendOfflinePacketAfterOnline", s._sendOfflinePacketAfterOnline.current()},
		{"markReadAfterAction", s._markReadAfterAction.current()},
		{"useScheduledMessages", s._useScheduledMessages.current()},
		{"sendWithoutSound", s._sendWithoutSound.current()},
		{"suggestGhostModeBeforeViewingStory", s._suggestGhostModeBeforeViewingStory.current()},
		{"rememberGhostRead", s._rememberGhostRead.current()},
		{"sendReadMessagesLocked", s._sendReadMessagesLocked.current()},
		{"sendReadStoriesLocked", s._sendReadStoriesLocked.current()},
		{"sendOnlinePacketsLocked", s._sendOnlinePacketsLocked.current()},
		{"sendUploadProgressLocked", s._sendUploadProgressLocked.current()},
		{"sendOfflinePacketAfterOnlineLocked", s._sendOfflinePacketAfterOnlineLocked.current()}
	};
}

void from_json(const nlohmann::json &j, GhostModeAccountSettings &s) {
	s._sendReadMessages = j.value("sendReadMessages", true);
	s._sendReadStories = j.value("sendReadStories", true);
	s._sendOnlinePackets = j.value("sendOnlinePackets", true);
	s._sendUploadProgress = j.value("sendUploadProgress", true);
	s._sendOfflinePacketAfterOnline = j.value("sendOfflinePacketAfterOnline", false);
	s._markReadAfterAction = j.value("markReadAfterAction", true);
	s._useScheduledMessages = j.value("useScheduledMessages", false);
	const auto sendWithoutSound = j.find("sendWithoutSound");
	s._sendWithoutSound = (sendWithoutSound == j.end())
		? SendWithoutSoundOption::Never
		: sendWithoutSound->is_boolean()
		? (sendWithoutSound->get<bool>()
			? SendWithoutSoundOption::Always
			: SendWithoutSoundOption::Never)
		: sendWithoutSound->get<SendWithoutSoundOption>();
	s._suggestGhostModeBeforeViewingStory = j.value("suggestGhostModeBeforeViewingStory", true);
	s._rememberGhostRead = j.value("rememberGhostRead", true);
	s._sendReadMessagesLocked = j.value("sendReadMessagesLocked", false);
	s._sendReadStoriesLocked = j.value("sendReadStoriesLocked", false);
	s._sendOnlinePacketsLocked = j.value("sendOnlinePacketsLocked", false);
	s._sendUploadProgressLocked = j.value("sendUploadProgressLocked", false);
	s._sendOfflinePacketAfterOnlineLocked = j.value("sendOfflinePacketAfterOnlineLocked", false);
}

void MessageShotSettings::setShowBackground(bool val) {
	if (_showBackground.current() == val) return;
	_showBackground = val;
	AyuSettings::save();
}

void MessageShotSettings::setShowDate(bool val) {
	if (_showDate.current() == val) return;
	_showDate = val;
	AyuSettings::save();
}

void MessageShotSettings::setShowReactions(bool val) {
	if (_showReactions.current() == val) return;
	_showReactions = val;
	AyuSettings::save();
}

void MessageShotSettings::setShowHeaderDecorations(bool val) {
	if (_showHeaderDecorations.current() == val) return;
	_showHeaderDecorations = val;
	AyuSettings::save();
}

void MessageShotSettings::setShowColorfulReplies(bool val) {
	if (_showColorfulReplies.current() == val) return;
	_showColorfulReplies = val;
	AyuSettings::save();
}

void MessageShotSettings::setRevealSpoilers(bool val) {
	if (_revealSpoilers.current() == val) return;
	_revealSpoilers = val;
	AyuSettings::save();
}

bool MessageShotSettings::isCloudThemeEmpty() const {
	return !_cloudThemeId.current()
		&& !_cloudThemeAccessHash.current()
		&& !_cloudThemeDocumentId.current()
		&& _cloudThemeTitle.current().isEmpty();
}

void MessageShotSettings::clearCloudThemeData() {
	_cloudThemeId = uint64(0);
	_cloudThemeAccessHash = uint64(0);
	_cloudThemeDocumentId = uint64(0);
	_cloudThemeTitle = QString();
	_cloudThemeAccountId = uint64(0);
}

void MessageShotSettings::setEmbeddedTheme(int type, uint32 accentColor) {
	if (_embeddedThemeType.current() == type
		&& _embeddedThemeAccentColor.current() == accentColor
		&& isCloudThemeEmpty()) {
		return;
	}
	_embeddedThemeType = type;
	_embeddedThemeAccentColor = accentColor;
	clearCloudThemeData();
	AyuSettings::save();
}

void MessageShotSettings::setCloudTheme(uint64 accountId, uint64 id, uint64 accessHash, uint64 documentId, const QString &title) {
	if (_embeddedThemeType.current() == -1
		&& _embeddedThemeAccentColor.current() == 0
		&& _cloudThemeAccountId.current() == accountId
		&& _cloudThemeId.current() == id
		&& _cloudThemeAccessHash.current() == accessHash
		&& _cloudThemeDocumentId.current() == documentId
		&& _cloudThemeTitle.current() == title) {
		return;
	}
	_embeddedThemeType = -1;
	_embeddedThemeAccentColor = uint32(0);
	_cloudThemeAccountId = accountId;
	_cloudThemeId = id;
	_cloudThemeAccessHash = accessHash;
	_cloudThemeDocumentId = documentId;
	_cloudThemeTitle = title;
	AyuSettings::save();
}

void MessageShotSettings::clearTheme() {
	if (_embeddedThemeType.current() == -1
		&& _embeddedThemeAccentColor.current() == 0
		&& isCloudThemeEmpty()) {
		return;
	}
	_embeddedThemeType = -1;
	_embeddedThemeAccentColor = uint32(0);
	clearCloudThemeData();
	AyuSettings::save();
}

void to_json(nlohmann::json &j, const MessageShotSettings &s) {
	j = nlohmann::json{
		{"showBackground", s._showBackground.current()},
		{"showDate", s._showDate.current()},
		{"showReactions", s._showReactions.current()},
		{"showHeaderDecorations", s._showHeaderDecorations.current()},
		{"showColorfulReplies", s._showColorfulReplies.current()},
		{"revealSpoilers", s._revealSpoilers.current()},
		{"embeddedThemeType", s._embeddedThemeType.current()},
		{"embeddedThemeAccentColor", s._embeddedThemeAccentColor.current()},
		{"cloudThemeId", s._cloudThemeId.current()},
		{"cloudThemeAccessHash", s._cloudThemeAccessHash.current()},
		{"cloudThemeDocumentId", s._cloudThemeDocumentId.current()},
		{"cloudThemeTitle", s._cloudThemeTitle.current()},
		{"cloudThemeAccountId", s._cloudThemeAccountId.current()},
	};
}

void from_json(const nlohmann::json &j, MessageShotSettings &s) {
	s._showBackground = j.value("showBackground", true);
	s._showDate = j.value("showDate", false);
	s._showReactions = j.value("showReactions", false);
	s._showHeaderDecorations = j.value("showHeaderDecorations", true);
	s._showColorfulReplies = j.value("showColorfulReplies", true);
	s._revealSpoilers = j.value("revealSpoilers", true);
	s._embeddedThemeType = j.value("embeddedThemeType", j.value("themeType", -1));
	s._embeddedThemeAccentColor = j.value("embeddedThemeAccentColor", j.value("themeAccentColor", uint32(0)));
	s._cloudThemeId = j.value("cloudThemeId", uint64(0));
	s._cloudThemeAccessHash = j.value("cloudThemeAccessHash", uint64(0));
	s._cloudThemeDocumentId = j.value("cloudThemeDocumentId", uint64(0));
	s._cloudThemeTitle = j.value("cloudThemeTitle", QString());
	s._cloudThemeAccountId = j.value("cloudThemeAccountId", uint64(0));
}

AyuSettings::AyuSettings()
: _appIcon(AyuAssets::DEFAULT_ICON)
, _editedMark(Core::IsAppLaunched() ? tr::lng_edited(tr::now) : QString("edited")) {
}

AyuSettings &AyuSettings::getInstance() {
	static AyuSettings instance;
	return instance;
}

void AyuSettings::load() {
	std::ifstream file(getSettingsPath());
	if (!file.good()) {
		return;
	}

	auto &settings = getInstance();

	try {
		json p;
		file >> p;
		file.close();

		if (!p.contains("ghostModeSettings")) {
			p["ghostModeSettings"] = nlohmann::json::object({
				{"0", {
					{"sendReadMessages", p.value("sendReadMessages", true)},
					{"sendReadStories", p.value("sendReadStories", true)},
					{"sendOnlinePackets", p.value("sendOnlinePackets", true)},
					{"sendUploadProgress", p.value("sendUploadProgress", true)},
					{"sendOfflinePacketAfterOnline", p.value("sendOfflinePacketAfterOnline", false)},
					{"markReadAfterAction", p.value("markReadAfterAction", true)},
					{"useScheduledMessages", p.value("useScheduledMessages", false)},
					{"sendWithoutSound", p.value("sendWithoutSound", false)}
				}}
			});
			p["useGlobalGhostMode"] = true;

			LOG(("AyuGramSettings: migrated ghost mode settings to per-account format"));
		}

		try {
			from_json(p, settings);
		} catch (...) {
			LOG(("AyuGramSettings: failed to parse settings file"));
		}
	} catch (...) {
		LOG(("AyuGramSettings: failed to read settings file (not json-like)"));
	}

	if (cGhost()) {
		auto &ghost = AyuSettings::ghost();
		ghost._sendReadMessages = false;
		ghost._sendReadStories = false;
		ghost._sendOnlinePackets = false;
		ghost._sendUploadProgress = false;
		ghost._sendOfflinePacketAfterOnline = true;
	}

	settings.validate();
}

void AyuSettings::save() {
	auto &settings = getInstance();
	json p = settings;

	std::ofstream file;
	file.open(getSettingsPath());
	file << p.dump(4);
	file.close();
}

QByteArray AyuSettings::exportTransfer(uint64 accountId) {
	const auto current = json(getInstance());
	auto preferences = json::object();
	for (const auto &key : transferSettingKeys()) {
		preferences[key] = current.at(key);
	}
	auto messageShot = json::object();
	for (const auto &key : messageShotTransferKeys()) {
		messageShot[key] = current.at("messageShotSettings").at(key);
	}
	preferences["messageShotSettings"] = std::move(messageShot);

	const auto ghostKey = getInstance().getOverriddenGhostUserId(accountId);
	const auto ghost = getInstance()._ghostAccounts.find(ghostKey);
	const auto ghostSettings = (ghost == end(getInstance()._ghostAccounts))
		? json(GhostModeAccountSettings())
		: json(*ghost->second);

	const auto filters = AyuDatabase::getAllRegexFilters();
	auto filterIndexes = std::map<std::vector<char>, std::size_t>();
	auto filterData = json::array();
	for (const auto &filter : filters) {
		const auto index = filterData.size();
		filterIndexes[filter.id] = index;
		filterData.push_back({
			{ "dialogId", filter.dialogId ? json(*filter.dialogId) : json(nullptr) },
			{ "text", filter.text },
			{ "enabled", filter.enabled },
			{ "reversed", filter.reversed },
			{ "caseInsensitive", filter.caseInsensitive },
		});
	}
	auto exclusions = json::array();
	for (const auto &exclusion : AyuDatabase::getAllFiltersExclusions()) {
		const auto i = filterIndexes.find(exclusion.filterId);
		if (i != end(filterIndexes)) {
			exclusions.push_back({
				{ "dialogId", exclusion.dialogId },
				{ "filterIndex", i->second },
			});
		}
	}
	return QByteArray::fromStdString(json{
		{ "format", "SleepyGram.settings" },
		{ "version", 1 },
		{ "settings", std::move(preferences) },
		{ "accountSettings", {{ "ghostMode", ghostSettings }} },
		{ "filters", std::move(filterData) },
		{ "exclusions", std::move(exclusions) },
	}.dump(4));
}

QString AyuSettings::previewTransfer(
		const QByteArray &data,
		uint64 accountId,
		QString *error) {
	Expects(error != nullptr);
	if (!accountId) {
		*error = u"The active account is unavailable."_q;
		return QString();
	}
	auto parsed = SettingsTransferData();
	if (!parseSettingsTransfer(data, &parsed, error)) {
		return QString();
	}
	const auto chatFilterCount = std::ranges::count_if(
		parsed.filters,
		[](const auto &filter) { return filter.dialogId.has_value(); });
	const auto ghostScope = parsed.settings.at("useGlobalGhostMode").get<bool>()
		? tr::ayu_SettingsImportGhostGlobal(tr::now)
		: tr::ayu_SettingsImportGhostAccount(tr::now);
	return tr::ayu_SettingsImportPreview(tr::now)
		.arg(int(transferSettingKeys().size() - 1 + messageShotTransferKeys().size()))
		.arg(int(parsed.filters.size()))
		.arg(int(chatFilterCount))
		.arg(int(parsed.exclusions.size()))
		.arg(ghostScope);
}

bool AyuSettings::applyTransfer(const QByteArray &data, uint64 accountId) {
	auto error = QString();
	auto parsed = SettingsTransferData();
	if (!accountId || !parseSettingsTransfer(data, &parsed, &error)) {
		return false;
	}

	const auto previousSettingsFileExists = QFile::exists(getSettingsFilePath());
	auto previousSettingsFile = QByteArray();
	if (previousSettingsFileExists) {
		QFile file(getSettingsFilePath());
		if (!file.open(QIODevice::ReadOnly)) {
			return false;
		}
		previousSettingsFile = file.readAll();
		if (file.error() != QFileDevice::NoError) {
			return false;
		}
	}

	const auto previousFilters = AyuDatabase::getAllRegexFilters();
	const auto previousExclusions = AyuDatabase::getAllFiltersExclusions();
	auto stagedJson = json(getInstance());
	for (const auto &key : transferSettingKeys()) {
		if (key == "messageShotSettings") {
			continue;
		}
		stagedJson[key] = parsed.settings.at(key);
	}
	auto stagedMessageShot = stagedJson.at("messageShotSettings");
	for (const auto &key : messageShotTransferKeys()) {
		stagedMessageShot[key] = parsed.settings.at("messageShotSettings").at(key);
	}
	stagedJson["messageShotSettings"] = std::move(stagedMessageShot);
	const auto importedGhostKey = parsed.settings.at("useGlobalGhostMode").get<bool>()
		? uint64(0)
		: accountId;
	stagedJson["ghostModeSettings"][std::to_string(importedGhostKey)] = parsed.ghostMode;
	if (!parsed.ghostMode.at("rememberGhostRead").get<bool>()) {
		if (importedGhostKey) {
			stagedJson["ghostReadState"].erase(std::to_string(accountId));
		} else {
			stagedJson["ghostReadState"] = json::object();
		}
	}

	auto staged = AyuSettings();
	try {
		from_json(stagedJson, staged);
	} catch (const std::exception &) {
		return false;
	}
	const auto stagedDiskJson = json(staged);
	if (!writeSettingsFile(stagedDiskJson)) {
		return false;
	}
	if (!AyuDatabase::replaceAllRegexFilters(parsed.filters, parsed.exclusions)) {
		if (!restoreSettingsFile(previousSettingsFileExists, previousSettingsFile)) {
			LOG(("AyuGramSettings: could not restore settings file after filter import failure"));
		}
		return false;
	}

	auto &settings = getInstance();
	auto previousLiveJson = json(settings);
	auto previousLive = previousLiveJson;
	previousLive.erase("ghostModeSettings");
	previousLive.erase("ghostReadState");
	previousLive.erase("deletedMessagePolicies");
	const auto liveGhostKey = parsed.settings.at("useGlobalGhostMode").get<bool>()
		? uint64(0)
		: accountId;
	const auto previousGhost = settings._ghostAccounts.find(liveGhostKey);
	const auto hadPreviousGhost = previousGhost != end(settings._ghostAccounts);
	const auto previousGhostJson = hadPreviousGhost
		? json(*previousGhost->second)
		: json();
	auto liveImport = stagedDiskJson;
	liveImport.erase("ghostModeSettings");
	liveImport.erase("ghostReadState");
	liveImport.erase("deletedMessagePolicies");
	try {
		from_json(liveImport, settings);
		auto ghost = settings._ghostAccounts.find(liveGhostKey);
		if (ghost == end(settings._ghostAccounts)) {
			ghost = settings._ghostAccounts.emplace(
				liveGhostKey,
				std::make_unique<GhostModeAccountSettings>()).first;
		}
		from_json(parsed.ghostMode, *ghost->second);
		if (!ghost->second->rememberGhostRead()) {
			if (liveGhostKey) {
				settings._ghostReadStates.erase(accountId);
			} else {
				settings._ghostReadStates.clear();
			}
		}
	} catch (const std::exception &) {
		try {
			from_json(previousLive, settings);
			if (hadPreviousGhost) {
				from_json(previousGhostJson, *settings._ghostAccounts.at(liveGhostKey));
			} else {
				settings._ghostAccounts.erase(liveGhostKey);
			}
		} catch (const std::exception &) {
			LOG(("AyuGramSettings: failed to restore live settings after apply failure"));
		}
		if (!AyuDatabase::replaceAllRegexFilters(previousFilters, previousExclusions)) {
			LOG(("AyuGramSettings: failed to restore filters after settings apply failure"));
		}
		if (!restoreSettingsFile(previousSettingsFileExists, previousSettingsFile)) {
			LOG(("AyuGramSettings: failed to restore settings after apply failure"));
		}
		return false;
	}
	AyuInfra::initUiSettings();
	AyuFeatures::StreamerMode::apply(settings.streamerMode());
#ifdef Q_OS_WIN
	AyuAssets::loadAppIco();
	reloadAppIconFromTaskBar();
#endif
	Window::OverrideApplicationIcon(AyuAssets::currentAppLogo());
	Core::App().refreshApplicationIcon();
	Core::App().tray().updateIconCounters();
	Core::App().domain().notifyUnreadBadgeChanged();
	FiltersCacheController::rebuildCache();
	FiltersCacheController::fireUpdate();
	repaintApp();
	return true;
}

void AyuSettings::reset() {
	getInstance() = AyuSettings();
	save();
}

GhostModeAccountSettings &AyuSettings::ghost(not_null<Main::Session*> session) {
	return ghost(session->userId().bare);
}

GhostModeAccountSettings &AyuSettings::ghost(uint64 userId) {
	auto &settings = getInstance();
	auto overriddenId = settings.getOverriddenGhostUserId(userId);

	auto it = settings._ghostAccounts.find(overriddenId);
	if (it == settings._ghostAccounts.end()) {
		auto account = std::make_unique<GhostModeAccountSettings>();
		it = settings._ghostAccounts.emplace(overriddenId, std::move(account)).first;
	}

	return *it->second;
}

GhostModeAccountSettings &AyuSettings::ghost() {
	if (const auto window = Core::App().activeWindow()) {
		if (const auto session = window->maybeSession()) {
			return ghost(session);
		}
	}
	return ghost(0);
}

const GhostReadState &AyuSettings::ghostReadState(uint64 accountId) {
	const auto &states = getInstance()._ghostReadStates;
	const auto i = states.find(accountId);
	if (i != states.end()) {
		return i->second;
	}
	static const auto Empty = GhostReadState();
	return Empty;
}

void AyuSettings::advanceGhostRead(
		uint64 accountId,
		uint64 peerId,
		uint64 topicRootId,
		int64 readTill) {
	if (!accountId || !peerId || readTill <= 0) {
		return;
	}
	auto &state = getInstance()._ghostReadStates[accountId];
	const auto previous = state.find(accountId, peerId, topicRootId);
	if (previous
		&& previous->readTill >= readTill
		&& !previous->manuallyUnread) {
		return;
	}
	state.advance(
		accountId,
		peerId,
		topicRootId,
		readTill);
	ghostReadSaveTimer().callOnce(500);
}

void AyuSettings::markGhostReadManuallyUnread(
		uint64 accountId,
		uint64 peerId,
		uint64 topicRootId) {
	if (!accountId || !peerId) {
		return;
	}
	auto &state = getInstance()._ghostReadStates[accountId];
	const auto previous = state.find(accountId, peerId, topicRootId);
	if (previous && previous->manuallyUnread) {
		return;
	}
	state.markManuallyUnread(
		accountId,
		peerId,
		topicRootId);
	ghostReadSaveTimer().callOnce(500);
}

void AyuSettings::clearGhostRead(
		uint64 accountId,
		uint64 peerId,
		uint64 topicRootId) {
	if (!accountId || !peerId) {
		return;
	}
	auto &states = getInstance()._ghostReadStates;
	const auto i = states.find(accountId);
	if (i == states.end() || !i->second.find(accountId, peerId, topicRootId)) {
		return;
	}
	i->second.clear(
		accountId,
		peerId,
		topicRootId);
	ghostReadSaveTimer().callOnce(500);
}

void AyuSettings::clearGhostReadForPreference(uint64 userId) {
	auto &settings = getInstance();
	const auto key = settings.getOverriddenGhostUserId(userId);
	if (!key) {
		if (settings._ghostReadStates.empty()) {
			return;
		}
		settings._ghostReadStates.clear();
	} else if (const auto i = settings._ghostReadStates.find(key);
		i != settings._ghostReadStates.end()) {
		if (i->second.all().empty()) {
			return;
		}
		i->second.clearAccount(key);
	} else {
		return;
	}
	ghostReadSaveTimer().callOnce(500);
}

void AyuSettings::refreshGhostReadPresentation(uint64 userId) {
	if (!Core::IsAppLaunched()) {
		return;
	}
	const auto key = getInstance().getOverriddenGhostUserId(userId);
	for (const auto &[index, account] : Core::App().domain().accounts()) {
		if (account) {
			if (const auto session = account->maybeSession();
				session
				&& (!key || getInstance().getOverriddenGhostUserId(
					session->userId().bare) == key)) {
				session->data().histories().refreshGhostReadPresentation();
			}
		}
	}
}

void AyuSettings::setUseGlobalGhostMode(bool val) {
	if (_useGlobalGhostMode.current() == val) return;
	_useGlobalGhostMode = val;
	save();
}

void AyuSettings::addShadowBan(int64 id) {
	if (_shadowBanIds.insert(id).second) {
		FiltersCacheController::rebuildCache();
		FiltersCacheController::fireUpdate();
		save();
	}
}

void AyuSettings::removeShadowBan(int64 id) {
	if (_shadowBanIds.erase(id) > 0) {
		FiltersCacheController::rebuildCache();
		FiltersCacheController::fireUpdate();
		save();
	}
}

void AyuSettings::validate() {
	AyuSettings defaults;
	auto modified = false;

	auto validateRange = [&](auto &var, auto min, auto max, const auto &defaultVar) {
		if (var.current() < min || var.current() > max) {
			var = defaultVar.current();
			modified = true;
		}
	};

	auto validateEnum = [&](auto &var, const auto &defaultVar, int max = 2) {
		auto intVal = static_cast<int>(var.current());
		if (intVal < 0 || intVal > max) {
			var = defaultVar.current();
			modified = true;
		}
	};

	validateEnum(_showPeerId, defaults._showPeerId);
	validateEnum(_channelBottomButton, defaults._channelBottomButton);
	validateEnum(_showReactionsPanelInContextMenu, defaults._showReactionsPanelInContextMenu);
	validateEnum(_showViewsPanelInContextMenu, defaults._showViewsPanelInContextMenu);
	validateEnum(_showHideMessageInContextMenu, defaults._showHideMessageInContextMenu);
	validateEnum(_showUserMessagesInContextMenu, defaults._showUserMessagesInContextMenu);
	validateEnum(_showMessageDetailsInContextMenu, defaults._showMessageDetailsInContextMenu);
	validateEnum(_showRepeatMessageInContextMenu, defaults._showRepeatMessageInContextMenu);
	validateEnum(_showAddFilterInContextMenu, defaults._showAddFilterInContextMenu);

	validateEnum(_translationProvider, defaults._translationProvider, 3);
	if ((_translationProvider.current() == TranslationProvider::Native)
		&& !Platform::IsTranslateProviderAvailable()) {
		_translationProvider = defaults._translationProvider.current();
		modified = true;
	}

	validateRange(_messageBubbleRadius, 0, 16, defaults._messageBubbleRadius);
	validateRange(_wideMultiplier, 0.5, 4.0, defaults._wideMultiplier);
	validateRange(_avatarCorners, 0, AyuUiSettings::kMaxAvatarCorners, defaults._avatarCorners);

	const auto embeddedType = _messageShotSettings._embeddedThemeType.current();
	auto embeddedTypeValid = (embeddedType == -1) || (embeddedType >= 0 && embeddedType <= 3); // from Window::Theme::EmbeddedType::DayBlue to Window::Theme::EmbeddedType::NightGreen
	if (!embeddedTypeValid) {
		_messageShotSettings._embeddedThemeType = defaults._messageShotSettings._embeddedThemeType.current();
		_messageShotSettings._embeddedThemeAccentColor = defaults._messageShotSettings._embeddedThemeAccentColor.current();
		modified = true;
	}

	if (modified) {
		save();
	}
}

void AyuSettings::setSaveDeletedMessages(bool val) {
	if (_saveDeletedMessages.current() == val) return;
	_saveDeletedMessages = val;
	save();
}

int AyuSettings::deletedMessagePolicy(uint64 accountId, uint64 peerId) const {
	const auto i = _deletedMessagePolicies.find({ accountId, peerId });
	return (i == end(_deletedMessagePolicies)) ? -1 : i->second;
}

void AyuSettings::setDeletedMessagePolicy(
		uint64 accountId,
		uint64 peerId,
		int policy) {
	const auto key = std::make_pair(accountId, peerId);
	if (policy < 0) {
		if (!_deletedMessagePolicies.erase(key)) {
			return;
		}
	} else {
		const auto i = _deletedMessagePolicies.find(key);
		if (i != end(_deletedMessagePolicies) && i->second == policy) {
			return;
		}
		_deletedMessagePolicies[key] = policy;
	}
	save();
}

void AyuSettings::setSaveMessagesHistory(bool val) {
	if (_saveMessagesHistory.current() == val) return;
	_saveMessagesHistory = val;
	save();
}

void AyuSettings::setSaveForBots(bool val) {
	if (_saveForBots.current() == val) return;
	_saveForBots = val;
	save();
}

void AyuSettings::setFiltersEnabled(bool val) {
	if (_filtersEnabled.current() == val) return;
	_filtersEnabled = val;
	save();
}

void AyuSettings::setFiltersEnabledInChats(bool val) {
	if (_filtersEnabledInChats.current() == val) return;
	_filtersEnabledInChats = val;
	save();
}

void AyuSettings::setHideFromBlocked(bool val) {
	if (_hideFromBlocked.current() == val) return;
	_hideFromBlocked = val;
	save();
}

void AyuSettings::setSemiTransparentDeletedMessages(bool val) {
	if (_semiTransparentDeletedMessages.current() == val) return;
	_semiTransparentDeletedMessages = val;
	save();
}

void AyuSettings::setDisableAds(bool val) {
	if (_disableAds.current() == val) return;
	_disableAds = val;
	save();
}

void AyuSettings::setDisableStories(bool val) {
	if (_disableStories.current() == val) return;
	_disableStories = val;
	save();
}

void AyuSettings::setDisableCustomBackgrounds(bool val) {
	if (_disableCustomBackgrounds.current() == val) return;
	_disableCustomBackgrounds = val;
	save();
}

void AyuSettings::setHidePremiumStatuses(bool val) {
	if (_hidePremiumStatuses.current() == val) return;
	_hidePremiumStatuses = val;
	save();
}

void AyuSettings::setShowOnlyAddedEmojisAndStickers(bool val) {
	if (_showOnlyAddedEmojisAndStickers.current() == val) return;
	_showOnlyAddedEmojisAndStickers = val;
	save();
}

void AyuSettings::setCollapseSimilarChannels(bool val) {
	if (_collapseSimilarChannels.current() == val) return;
	_collapseSimilarChannels = val;
	save();
}

void AyuSettings::setHideSimilarChannels(bool val) {
	if (_hideSimilarChannels.current() == val) return;
	_hideSimilarChannels = val;
	save();
}

void AyuSettings::setMessageBubbleRadius(int val) {
	if (_messageBubbleRadius.current() == val) return;
	_messageBubbleRadius = val;
	save();
}

void AyuSettings::setWideMultiplier(double val) {
	if (_wideMultiplier.current() == val) return;
	_wideMultiplier = val;
	// doesn't work because it should be set before style::StartManager()
	// AyuUiSettings::setWideMultiplier(val);
	// repaintApp();
	save();
}

void AyuSettings::setSpoofWebviewAsAndroid(bool val) {
	if (_spoofWebviewAsAndroid.current() == val) return;
	_spoofWebviewAsAndroid = val;
	save();
}

void AyuSettings::setDisableOpenLinkWarning(bool val) {
	if (_disableOpenLinkWarning.current() == val) return;
	_disableOpenLinkWarning = val;
	save();
}

void AyuSettings::setIncreaseWebviewHeight(bool val) {
	if (_increaseWebviewHeight.current() == val) return;
	_increaseWebviewHeight = val;
	save();
}

void AyuSettings::setIncreaseWebviewWidth(bool val) {
	if (_increaseWebviewWidth.current() == val) return;
	_increaseWebviewWidth = val;
	save();
}

void AyuSettings::setMaterialSwitches(bool val) {
	if (_materialSwitches.current() == val) return;
	_materialSwitches = val;
	AyuUiSettings::setMaterialSwitches(val);
	repaintApp();
	save();
}

void AyuSettings::setRemoveMessageTail(bool val) {
	if (_removeMessageTail.current() == val) return;
	_removeMessageTail = val;
	save();
}

void AyuSettings::setDisableNotificationsDelay(bool val) {
	if (_disableNotificationsDelay.current() == val) return;
	_disableNotificationsDelay = val;
	save();
}

void AyuSettings::setShowChannelReactions(bool val) {
	if (_showChannelReactions.current() == val) return;
	_showChannelReactions = val;
	save();
}

void AyuSettings::setShowGroupReactions(bool val) {
	if (_showGroupReactions.current() == val) return;
	_showGroupReactions = val;
	save();
}

void AyuSettings::setShowPrivateChatReactions(bool val) {
	if (_showPrivateChatReactions.current() == val) return;
	_showPrivateChatReactions = val;
	save();
}

void AyuSettings::setAppIcon(const QString &val) {
	if (_appIcon.current() == val) return;
	_appIcon = val;
	save();
}

void AyuSettings::setSimpleQuotesAndReplies(bool val) {
	if (_simpleQuotesAndReplies.current() == val) return;
	_simpleQuotesAndReplies = val;
	save();
}

void AyuSettings::setHideFastShare(bool val) {
	if (_hideFastShare.current() == val) return;
	_hideFastShare = val;
	save();
}

void AyuSettings::setReplaceBottomInfoWithIcons(bool val) {
	if (_replaceBottomInfoWithIcons.current() == val) return;
	_replaceBottomInfoWithIcons = val;
	save();
}

void AyuSettings::setDeletedMark(const QString &val) {
	if (_deletedMark.current() == val) return;
	_deletedMark = val;
	save();
}

void AyuSettings::setEditedMark(const QString &val) {
	if (_editedMark.current() == val) return;
	_editedMark = val;
	save();
}

void AyuSettings::setUnlimitedRecentStickers(bool val) {
	if (_unlimitedRecentStickers.current() == val) return;
	_unlimitedRecentStickers = val;
	save();
}

void AyuSettings::setShowReactionsPanelInContextMenu(ContextMenuVisibility val) {
	if (_showReactionsPanelInContextMenu.current() == val) return;
	_showReactionsPanelInContextMenu = val;
	save();
}

void AyuSettings::setShowViewsPanelInContextMenu(ContextMenuVisibility val) {
	if (_showViewsPanelInContextMenu.current() == val) return;
	_showViewsPanelInContextMenu = val;
	save();
}

void AyuSettings::setShowHideMessageInContextMenu(ContextMenuVisibility val) {
	if (_showHideMessageInContextMenu.current() == val) return;
	_showHideMessageInContextMenu = val;
	save();
}

void AyuSettings::setShowUserMessagesInContextMenu(ContextMenuVisibility val) {
	if (_showUserMessagesInContextMenu.current() == val) return;
	_showUserMessagesInContextMenu = val;
	save();
}

void AyuSettings::setShowMessageDetailsInContextMenu(ContextMenuVisibility val) {
	if (_showMessageDetailsInContextMenu.current() == val) return;
	_showMessageDetailsInContextMenu = val;
	save();
}

void AyuSettings::setShowRepeatMessageInContextMenu(ContextMenuVisibility val) {
	if (_showRepeatMessageInContextMenu.current() == val) return;
	_showRepeatMessageInContextMenu = val;
	save();
}

void AyuSettings::setShowAddFilterInContextMenu(ContextMenuVisibility val) {
	if (_showAddFilterInContextMenu.current() == val) return;
	_showAddFilterInContextMenu = val;
	save();
}

void AyuSettings::setShowAttachButtonInMessageField(bool val) {
	if (_showAttachButtonInMessageField.current() == val) return;
	_showAttachButtonInMessageField = val;
	save();
}

void AyuSettings::setShowCommandsButtonInMessageField(bool val) {
	if (_showCommandsButtonInMessageField.current() == val) return;
	_showCommandsButtonInMessageField = val;
	save();
}

void AyuSettings::setShowEmojiButtonInMessageField(bool val) {
	if (_showEmojiButtonInMessageField.current() == val) return;
	_showEmojiButtonInMessageField = val;
	save();
}

void AyuSettings::setShowMicrophoneButtonInMessageField(bool val) {
	if (_showMicrophoneButtonInMessageField.current() == val) return;
	_showMicrophoneButtonInMessageField = val;
	save();
}

void AyuSettings::setShowAutoDeleteButtonInMessageField(bool val) {
	if (_showAutoDeleteButtonInMessageField.current() == val) return;
	_showAutoDeleteButtonInMessageField = val;
	save();
}

void AyuSettings::setShowGiftButtonInMessageField(bool val) {
	if (_showGiftButtonInMessageField.current() == val) return;
	_showGiftButtonInMessageField = val;
	save();
}

void AyuSettings::setShowAiEditorButtonInMessageField(bool val) {
	if (_showAiEditorButtonInMessageField.current() == val) return;
	_showAiEditorButtonInMessageField = val;
	save();
}

void AyuSettings::setShowAttachPopup(bool val) {
	if (_showAttachPopup.current() == val) return;
	_showAttachPopup = val;
	save();
}

void AyuSettings::setShowEmojiPopup(bool val) {
	if (_showEmojiPopup.current() == val) return;
	_showEmojiPopup = val;
	save();
}

void AyuSettings::setShowMyProfileInDrawer(bool val) {
	if (_showMyProfileInDrawer.current() == val) return;
	_showMyProfileInDrawer = val;
	save();
}

void AyuSettings::setShowBotsInDrawer(bool val) {
	if (_showBotsInDrawer.current() == val) return;
	_showBotsInDrawer = val;
	save();
}

void AyuSettings::setShowNewGroupInDrawer(bool val) {
	if (_showNewGroupInDrawer.current() == val) return;
	_showNewGroupInDrawer = val;
	save();
}

void AyuSettings::setShowNewChannelInDrawer(bool val) {
	if (_showNewChannelInDrawer.current() == val) return;
	_showNewChannelInDrawer = val;
	save();
}

void AyuSettings::setShowContactsInDrawer(bool val) {
	if (_showContactsInDrawer.current() == val) return;
	_showContactsInDrawer = val;
	save();
}

void AyuSettings::setShowCallsInDrawer(bool val) {
	if (_showCallsInDrawer.current() == val) return;
	_showCallsInDrawer = val;
	save();
}

void AyuSettings::setShowSavedMessagesInDrawer(bool val) {
	if (_showSavedMessagesInDrawer.current() == val) return;
	_showSavedMessagesInDrawer = val;
	save();
}

void AyuSettings::setShowLReadToggleInDrawer(bool val) {
	if (_showLReadToggleInDrawer.current() == val) return;
	_showLReadToggleInDrawer = val;
	save();
}

void AyuSettings::setShowSReadToggleInDrawer(bool val) {
	if (_showSReadToggleInDrawer.current() == val) return;
	_showSReadToggleInDrawer = val;
	save();
}

void AyuSettings::setShowNightModeToggleInDrawer(bool val) {
	if (_showNightModeToggleInDrawer.current() == val) return;
	_showNightModeToggleInDrawer = val;
	save();
}

void AyuSettings::setShowGhostToggleInDrawer(bool val) {
	if (_showGhostToggleInDrawer.current() == val) return;
	_showGhostToggleInDrawer = val;
	save();
}

void AyuSettings::setShowStreamerToggleInDrawer(bool val) {
	if (_showStreamerToggleInDrawer.current() == val) return;
	_showStreamerToggleInDrawer = val;
	save();
}

void AyuSettings::setShowGhostToggleInTray(bool val) {
	if (_showGhostToggleInTray.current() == val) return;
	_showGhostToggleInTray = val;
	save();
}

void AyuSettings::setShowStreamerToggleInTray(bool val) {
	if (_showStreamerToggleInTray.current() == val) return;
	_showStreamerToggleInTray = val;
	save();
}

void AyuSettings::setMonoFont(const QString &val) {
	if (_monoFont.current() == val) return;
	_monoFont = val;
	// doesn't work because `static const auto family = ...`
	// AyuUiSettings::setMonoFont(val);
	// repaintApp();
	save();
}

void AyuSettings::setHideNotificationCounters(bool val) {
	if (_hideNotificationCounters.current() == val) return;
	_hideNotificationCounters = val;
	save();
}

void AyuSettings::setHideNotificationBadge(bool val) {
	if (_hideNotificationBadge.current() == val) return;
	_hideNotificationBadge = val;
	Core::App().refreshApplicationIcon();
	Core::App().tray().updateIconCounters();
	Core::App().domain().notifyUnreadBadgeChanged();
	save();
}

void AyuSettings::setHideAllChatsFolder(bool val) {
	if (_hideAllChatsFolder.current() == val) return;
	_hideAllChatsFolder = val;
	save();
}

void AyuSettings::setChannelBottomButton(ChannelBottomButton val) {
	if (_channelBottomButton.current() == val) return;
	_channelBottomButton = val;
	save();
}

void AyuSettings::setQuickAdminShortcuts(bool val) {
	if (_quickAdminShortcuts.current() == val) return;
	_quickAdminShortcuts = val;
	save();
}

void AyuSettings::setDisableGreetingSticker(bool val) {
	if (_disableGreetingSticker.current() == val) return;
	_disableGreetingSticker = val;
	save();
}

void AyuSettings::setShowPeerId(PeerIdDisplay val) {
	if (_showPeerId.current() == val) return;
	_showPeerId = val;
	save();
}

void AyuSettings::setShowMessageSeconds(bool val) {
	if (_showMessageSeconds.current() == val) return;
	_showMessageSeconds = val;
	save();
}

void AyuSettings::setShowMessageShot(bool val) {
	if (_showMessageShot.current() == val) return;
	_showMessageShot = val;
	save();
}

void AyuSettings::setFilterZalgo(bool val) {
	if (_filterZalgo.current() == val) return;
	_filterZalgo = val;
	save();
}

void AyuSettings::setStickerConfirmation(bool val) {
	if (_stickerConfirmation.current() == val) return;
	_stickerConfirmation = val;
	save();
}

void AyuSettings::setGifConfirmation(bool val) {
	if (_gifConfirmation.current() == val) return;
	_gifConfirmation = val;
	save();
}

void AyuSettings::setVoiceConfirmation(bool val) {
	if (_voiceConfirmation.current() == val) return;
	_voiceConfirmation = val;
	save();
}

void AyuSettings::setRoundConfirmation(bool val) {
	if (_roundConfirmation.current() == val) return;
	_roundConfirmation = val;
	save();
}

void AyuSettings::setTranslationProvider(TranslationProvider val) {
	if ((val == TranslationProvider::Native)
		&& !Platform::IsTranslateProviderAvailable()) {
		val = TranslationProvider::Telegram;
	}
	if (_translationProvider.current() == val) return;
	_translationProvider = val;
	if (const auto manager = Ayu::Translator::TranslateManager::currentInstance()) {
		manager->resetCache();
	}
	save();
}

void AyuSettings::setAdaptiveCoverColor(bool val) {
	if (_adaptiveCoverColor.current() == val) return;
	_adaptiveCoverColor = val;
	save();
}

void AyuSettings::setImproveLinkPreviews(bool val) {
	if (_improveLinkPreviews.current() == val) return;
	_improveLinkPreviews = val;
	save();
}

void AyuSettings::setCrashReporting(bool val) {
	if (_crashReporting.current() == val) return;
	_crashReporting = val;
	save();
}

void AyuSettings::setAvatarCorners(int val) {
	if (_avatarCorners.current() == val) return;
	_avatarCorners = val;
	AyuUiSettings::setAvatarCorners(val);
	save();
}

void AyuSettings::setSingleCornerRadius(bool val) {
	if (_singleCornerRadius.current() == val) return;
	_singleCornerRadius = val;
	repaintApp();
	save();
}

void AyuSettings::setStreamerMode(bool val) {
	if (_streamerMode.current() == val) return;
	_streamerMode = val;
	AyuFeatures::StreamerMode::apply(val);
	save();
}

void to_json(nlohmann::json &j, const AyuSettings &s) {
	auto ghostAccounts = nlohmann::json::object();
	for (const auto &[key, value] : s._ghostAccounts) {
		ghostAccounts[std::to_string(key)] = *value;
	}
	auto ghostReadAccounts = nlohmann::json::object();
	for (const auto &[accountId, state] : s._ghostReadStates) {
		auto watermarks = nlohmann::json::array();
		for (const auto &[scope, watermark] : state.all()) {
			watermarks.push_back({
				{"peerId", scope.peerId},
				{"topicRootId", scope.topicRootId},
				{"readTill", watermark.readTill},
				{"manuallyUnread", watermark.manuallyUnread}
			});
		}
		ghostReadAccounts[std::to_string(accountId)] = std::move(watermarks);
	}
	auto deletedMessagePolicies = nlohmann::json::array();
	for (const auto &[key, policy] : s._deletedMessagePolicies) {
		deletedMessagePolicies.push_back({
			{"accountId", key.first},
			{"peerId", key.second},
			{"policy", policy},
		});
	}

	j = nlohmann::json{
		{"ghostModeSettings", ghostAccounts},
		{"ghostReadState", ghostReadAccounts},
		{"deletedMessagePolicies", deletedMessagePolicies},
		{"useGlobalGhostMode", s._useGlobalGhostMode.current()},
		{"saveDeletedMessages", s._saveDeletedMessages.current()},
		{"saveMessagesHistory", s._saveMessagesHistory.current()},
		{"saveForBots", s._saveForBots.current()},
		{"shadowBanIds", s._shadowBanIds},
		{"filtersEnabled", s._filtersEnabled.current()},
		{"filtersEnabledInChats", s._filtersEnabledInChats.current()},
		{"hideFromBlocked", s._hideFromBlocked.current()},
		{"semiTransparentDeletedMessages", s._semiTransparentDeletedMessages.current()},
		{"disableAds", s._disableAds.current()},
		{"disableStories", s._disableStories.current()},
		{"disableCustomBackgrounds", s._disableCustomBackgrounds.current()},
		{"hidePremiumStatuses", s._hidePremiumStatuses.current()},
		{"showOnlyAddedEmojisAndStickers", s._showOnlyAddedEmojisAndStickers.current()},
		{"collapseSimilarChannels", s._collapseSimilarChannels.current()},
		{"hideSimilarChannels", s._hideSimilarChannels.current()},
		{"messageBubbleRadius", s._messageBubbleRadius.current()},
		{"disableOpenLinkWarning", s._disableOpenLinkWarning.current()},
		{"wideMultiplier", s._wideMultiplier.current()},
		{"spoofWebviewAsAndroid", s._spoofWebviewAsAndroid.current()},
		{"increaseWebviewHeight", s._increaseWebviewHeight.current()},
		{"increaseWebviewWidth", s._increaseWebviewWidth.current()},
		{"materialSwitches", s._materialSwitches.current()},
		{"removeMessageTail", s._removeMessageTail.current()},
		{"disableNotificationsDelay", s._disableNotificationsDelay.current()},
		{"showChannelReactions", s._showChannelReactions.current()},
		{"showGroupReactions", s._showGroupReactions.current()},
		{"showPrivateChatReactions", s._showPrivateChatReactions.current()},
		{"appIcon", s._appIcon.current()},
		{"simpleQuotesAndReplies", s._simpleQuotesAndReplies.current()},
		{"hideFastShare", s._hideFastShare.current()},
		{"replaceBottomInfoWithIcons", s._replaceBottomInfoWithIcons.current()},
		{"deletedMark", s._deletedMark.current()},
		{"editedMark", s._editedMark.current()},
		{"unlimitedRecentStickers", s._unlimitedRecentStickers.current()},
		{"showReactionsPanelInContextMenu", s._showReactionsPanelInContextMenu.current()},
		{"showViewsPanelInContextMenu", s._showViewsPanelInContextMenu.current()},
		{"showHideMessageInContextMenu", s._showHideMessageInContextMenu.current()},
		{"showUserMessagesInContextMenu", s._showUserMessagesInContextMenu.current()},
		{"showMessageDetailsInContextMenu", s._showMessageDetailsInContextMenu.current()},
		{"showRepeatMessageInContextMenu", s._showRepeatMessageInContextMenu.current()},
		{"showAddFilterInContextMenu", s._showAddFilterInContextMenu.current()},
		{"showAttachButtonInMessageField", s._showAttachButtonInMessageField.current()},
		{"showCommandsButtonInMessageField", s._showCommandsButtonInMessageField.current()},
		{"showEmojiButtonInMessageField", s._showEmojiButtonInMessageField.current()},
		{"showMicrophoneButtonInMessageField", s._showMicrophoneButtonInMessageField.current()},
		{"showAutoDeleteButtonInMessageField", s._showAutoDeleteButtonInMessageField.current()},
		{"showGiftButtonInMessageField", s._showGiftButtonInMessageField.current()},
		{"showAiEditorButtonInMessageField", s._showAiEditorButtonInMessageField.current()},
		{"showAttachPopup", s._showAttachPopup.current()},
		{"showEmojiPopup", s._showEmojiPopup.current()},
		{"showMyProfileInDrawer", s._showMyProfileInDrawer.current()},
		{"showBotsInDrawer", s._showBotsInDrawer.current()},
		{"showNewGroupInDrawer", s._showNewGroupInDrawer.current()},
		{"showNewChannelInDrawer", s._showNewChannelInDrawer.current()},
		{"showContactsInDrawer", s._showContactsInDrawer.current()},
		{"showCallsInDrawer", s._showCallsInDrawer.current()},
		{"showSavedMessagesInDrawer", s._showSavedMessagesInDrawer.current()},
		{"showLReadToggleInDrawer", s._showLReadToggleInDrawer.current()},
		{"showSReadToggleInDrawer", s._showSReadToggleInDrawer.current()},
		{"showNightModeToggleInDrawer", s._showNightModeToggleInDrawer.current()},
		{"showGhostToggleInDrawer", s._showGhostToggleInDrawer.current()},
		{"showStreamerToggleInDrawer", s._showStreamerToggleInDrawer.current()},
		{"showGhostToggleInTray", s._showGhostToggleInTray.current()},
		{"showStreamerToggleInTray", s._showStreamerToggleInTray.current()},
		{"monoFont", s._monoFont.current()},
		{"hideNotificationCounters", s._hideNotificationCounters.current()},
		{"hideNotificationBadge", s._hideNotificationBadge.current()},
		{"hideAllChatsFolder", s._hideAllChatsFolder.current()},
		{"channelBottomButton", s._channelBottomButton.current()},
		{"quickAdminShortcuts", s._quickAdminShortcuts.current()},
		{"disableGreetingSticker", s._disableGreetingSticker.current()},
		{"showPeerId", s._showPeerId.current()},
		{"showMessageSeconds", s._showMessageSeconds.current()},
		{"showMessageShot", s._showMessageShot.current()},
		{"filterZalgo", s._filterZalgo.current()},
		{"stickerConfirmation", s._stickerConfirmation.current()},
		{"gifConfirmation", s._gifConfirmation.current()},
		{"voiceConfirmation", s._voiceConfirmation.current()},
		{"roundConfirmation", s._roundConfirmation.current()},
		{"translationProvider", s._translationProvider.current()},
		{"adaptiveCoverColor", s._adaptiveCoverColor.current()},
		{"improveLinkPreviews", s._improveLinkPreviews.current()},
		{"crashReporting", s._crashReporting.current()},
		{"avatarCorners", s._avatarCorners.current()},
		{"singleCornerRadius", s._singleCornerRadius.current()},
		{"streamerMode", s._streamerMode.current()},
		{"messageShotSettings", s._messageShotSettings}
	};
}

void from_json(const nlohmann::json &j, AyuSettings &s) {
	AyuSettings defaults;

	if (j.contains("ghostModeSettings") && j["ghostModeSettings"].is_object()) {
		s._ghostAccounts.clear();
		for (auto &[key, value] : j["ghostModeSettings"].items()) {
			auto account = std::make_unique<GhostModeAccountSettings>();
			value.get_to(*account);
			s._ghostAccounts[std::stoull(key)] = std::move(account);
		}
	}
	if (j.contains("ghostReadState") && j["ghostReadState"].is_object()) {
		s._ghostReadStates.clear();
		for (const auto &[accountKey, watermarks] : j["ghostReadState"].items()) {
			auto accountId = uint64(0);
			const auto parsed = std::from_chars(
				accountKey.data(),
				accountKey.data() + accountKey.size(),
				accountId);
			if (parsed.ec != std::errc()
				|| parsed.ptr != accountKey.data() + accountKey.size()) {
				continue;
			}
			if (!accountId) {
				continue;
			}
			auto entries = std::map<GhostReadScope, GhostReadWatermark>();
			if (!watermarks.is_array()) {
				continue;
			}
			for (const auto &entry : watermarks) {
				try {
					const auto peerId = entry.value("peerId", uint64(0));
					const auto topicRootId = entry.value("topicRootId", uint64(0));
					const auto readTill = entry.value("readTill", int64(0));
					const auto manuallyUnread = entry.value("manuallyUnread", false);
					if (peerId && (readTill > 0 || manuallyUnread)) {
						entries[{ accountId, peerId, topicRootId }] = {
							readTill,
						manuallyUnread
						};
					}
				} catch (...) {
				}
			}
			s._ghostReadStates[accountId].replace(std::move(entries));
		}
	}
	if (j.contains("deletedMessagePolicies") && j["deletedMessagePolicies"].is_array()) {
		for (const auto &entry : j["deletedMessagePolicies"]) {
			try {
				const auto accountId = entry.value("accountId", uint64(0));
				const auto peerId = entry.value("peerId", uint64(0));
				const auto policy = entry.value("policy", -1);
				if (accountId && peerId && (policy == 0 || policy == 1)) {
					s._deletedMessagePolicies[{ accountId, peerId }] = policy;
				}
			} catch (...) {
			}
		}
	}

	s._useGlobalGhostMode = j.value("useGlobalGhostMode", defaults._useGlobalGhostMode.current());
	s._saveDeletedMessages = j.value("saveDeletedMessages", defaults._saveDeletedMessages.current());
	s._saveMessagesHistory = j.value("saveMessagesHistory", defaults._saveMessagesHistory.current());
	s._saveForBots = j.value("saveForBots", defaults._saveForBots.current());
	s._shadowBanIds = j.value("shadowBanIds", defaults._shadowBanIds);
	s._filtersEnabled = j.value("filtersEnabled", defaults._filtersEnabled.current());
	s._filtersEnabledInChats = j.value("filtersEnabledInChats", defaults._filtersEnabledInChats.current());
	s._hideFromBlocked = j.value("hideFromBlocked", defaults._hideFromBlocked.current());
	s._semiTransparentDeletedMessages = j.value("semiTransparentDeletedMessages", defaults._semiTransparentDeletedMessages.current());
	s._disableAds = j.value("disableAds", defaults._disableAds.current());
	s._disableStories = j.value("disableStories", defaults._disableStories.current());
	s._disableCustomBackgrounds = j.value("disableCustomBackgrounds", defaults._disableCustomBackgrounds.current());
	s._hidePremiumStatuses = j.value("hidePremiumStatuses", defaults._hidePremiumStatuses.current());
	s._showOnlyAddedEmojisAndStickers = j.value("showOnlyAddedEmojisAndStickers", defaults._showOnlyAddedEmojisAndStickers.current());
	s._collapseSimilarChannels = j.value("collapseSimilarChannels", defaults._collapseSimilarChannels.current());
	s._hideSimilarChannels = j.value("hideSimilarChannels", defaults._hideSimilarChannels.current());
	s._messageBubbleRadius = j.value("messageBubbleRadius", defaults._messageBubbleRadius.current());
	s._disableOpenLinkWarning = j.value("disableOpenLinkWarning", defaults._disableOpenLinkWarning.current());
	s._wideMultiplier = j.value("wideMultiplier", defaults._wideMultiplier.current());
	s._spoofWebviewAsAndroid = j.value("spoofWebviewAsAndroid", defaults._spoofWebviewAsAndroid.current());
	s._increaseWebviewHeight = j.value("increaseWebviewHeight", defaults._increaseWebviewHeight.current());
	s._increaseWebviewWidth = j.value("increaseWebviewWidth", defaults._increaseWebviewWidth.current());
	s._materialSwitches = j.value("materialSwitches", defaults._materialSwitches.current());
	s._removeMessageTail = j.value("removeMessageTail", defaults._removeMessageTail.current());
	s._disableNotificationsDelay = j.value("disableNotificationsDelay", defaults._disableNotificationsDelay.current());
	s._showChannelReactions = j.value("showChannelReactions", defaults._showChannelReactions.current());
	s._showGroupReactions = j.value("showGroupReactions", defaults._showGroupReactions.current());
	s._showPrivateChatReactions = j.value("showPrivateChatReactions", defaults._showPrivateChatReactions.current());
	s._appIcon = j.value("appIcon", defaults._appIcon.current());
	s._simpleQuotesAndReplies = j.value("simpleQuotesAndReplies", defaults._simpleQuotesAndReplies.current());
	s._hideFastShare = j.value("hideFastShare", defaults._hideFastShare.current());
	s._replaceBottomInfoWithIcons = j.value("replaceBottomInfoWithIcons", defaults._replaceBottomInfoWithIcons.current());
	s._deletedMark = j.value("deletedMark", defaults._deletedMark.current());
	s._editedMark = j.value("editedMark", defaults._editedMark.current());
	s._unlimitedRecentStickers = j.value("unlimitedRecentStickers", defaults._unlimitedRecentStickers.current());
	s._showReactionsPanelInContextMenu = j.value("showReactionsPanelInContextMenu", defaults._showReactionsPanelInContextMenu.current());
	s._showViewsPanelInContextMenu = j.value("showViewsPanelInContextMenu", defaults._showViewsPanelInContextMenu.current());
	s._showHideMessageInContextMenu = j.value("showHideMessageInContextMenu", defaults._showHideMessageInContextMenu.current());
	s._showUserMessagesInContextMenu = j.value("showUserMessagesInContextMenu", defaults._showUserMessagesInContextMenu.current());
	s._showMessageDetailsInContextMenu = j.value("showMessageDetailsInContextMenu", defaults._showMessageDetailsInContextMenu.current());
	s._showRepeatMessageInContextMenu = j.value("showRepeatMessageInContextMenu", defaults._showRepeatMessageInContextMenu.current());
	s._showAddFilterInContextMenu = j.value("showAddFilterInContextMenu", defaults._showAddFilterInContextMenu.current());
	s._showAttachButtonInMessageField = j.value("showAttachButtonInMessageField", defaults._showAttachButtonInMessageField.current());
	s._showCommandsButtonInMessageField = j.value("showCommandsButtonInMessageField", defaults._showCommandsButtonInMessageField.current());
	s._showEmojiButtonInMessageField = j.value("showEmojiButtonInMessageField", defaults._showEmojiButtonInMessageField.current());
	s._showMicrophoneButtonInMessageField = j.value("showMicrophoneButtonInMessageField", defaults._showMicrophoneButtonInMessageField.current());
	s._showAutoDeleteButtonInMessageField = j.value("showAutoDeleteButtonInMessageField", defaults._showAutoDeleteButtonInMessageField.current());
	s._showGiftButtonInMessageField = j.value("showGiftButtonInMessageField", defaults._showGiftButtonInMessageField.current());
	s._showAiEditorButtonInMessageField = j.value("showAiEditorButtonInMessageField", defaults._showAiEditorButtonInMessageField.current());
	s._showAttachPopup = j.value("showAttachPopup", defaults._showAttachPopup.current());
	s._showEmojiPopup = j.value("showEmojiPopup", defaults._showEmojiPopup.current());
	s._showMyProfileInDrawer = j.value("showMyProfileInDrawer", defaults._showMyProfileInDrawer.current());
	s._showBotsInDrawer = j.value("showBotsInDrawer", defaults._showBotsInDrawer.current());
	s._showNewGroupInDrawer = j.value("showNewGroupInDrawer", defaults._showNewGroupInDrawer.current());
	s._showNewChannelInDrawer = j.value("showNewChannelInDrawer", defaults._showNewChannelInDrawer.current());
	s._showContactsInDrawer = j.value("showContactsInDrawer", defaults._showContactsInDrawer.current());
	s._showCallsInDrawer = j.value("showCallsInDrawer", defaults._showCallsInDrawer.current());
	s._showSavedMessagesInDrawer = j.value("showSavedMessagesInDrawer", defaults._showSavedMessagesInDrawer.current());
	s._showLReadToggleInDrawer = j.value("showLReadToggleInDrawer", defaults._showLReadToggleInDrawer.current());
	s._showSReadToggleInDrawer = j.value("showSReadToggleInDrawer", defaults._showSReadToggleInDrawer.current());
	s._showNightModeToggleInDrawer = j.value("showNightModeToggleInDrawer", defaults._showNightModeToggleInDrawer.current());
	s._showGhostToggleInDrawer = j.value("showGhostToggleInDrawer", defaults._showGhostToggleInDrawer.current());
	s._showStreamerToggleInDrawer = j.value("showStreamerToggleInDrawer", defaults._showStreamerToggleInDrawer.current());
	s._showGhostToggleInTray = j.value("showGhostToggleInTray", defaults._showGhostToggleInTray.current());
	s._showStreamerToggleInTray = j.value("showStreamerToggleInTray", defaults._showStreamerToggleInTray.current());
	s._monoFont = j.value("monoFont", defaults._monoFont.current());
	s._hideNotificationCounters = j.value("hideNotificationCounters", defaults._hideNotificationCounters.current());
	s._hideNotificationBadge = j.value("hideNotificationBadge", defaults._hideNotificationBadge.current());
	s._hideAllChatsFolder = j.value("hideAllChatsFolder", defaults._hideAllChatsFolder.current());
	s._channelBottomButton = j.value("channelBottomButton", defaults._channelBottomButton.current());
	s._quickAdminShortcuts = j.value("quickAdminShortcuts", defaults._quickAdminShortcuts.current());
	s._disableGreetingSticker = j.value("disableGreetingSticker", defaults._disableGreetingSticker.current());
	s._showPeerId = j.value("showPeerId", defaults._showPeerId.current());
	s._showMessageSeconds = j.value("showMessageSeconds", defaults._showMessageSeconds.current());
	s._showMessageShot = j.value("showMessageShot", defaults._showMessageShot.current());
	s._filterZalgo = j.value("filterZalgo", defaults._filterZalgo.current());
	s._stickerConfirmation = j.value("stickerConfirmation", defaults._stickerConfirmation.current());
	s._gifConfirmation = j.value("gifConfirmation", defaults._gifConfirmation.current());
	s._voiceConfirmation = j.value("voiceConfirmation", defaults._voiceConfirmation.current());
	s._roundConfirmation = j.value("roundConfirmation", defaults._roundConfirmation.current());
	s._translationProvider = j.value("translationProvider", defaults._translationProvider.current());
	s._adaptiveCoverColor = j.value("adaptiveCoverColor", defaults._adaptiveCoverColor.current());
	s._improveLinkPreviews = j.value("improveLinkPreviews", defaults._improveLinkPreviews.current());
	s._crashReporting = j.value("crashReporting", defaults._crashReporting.current());
	s._avatarCorners = j.value("avatarCorners", defaults._avatarCorners.current());
	s._singleCornerRadius = j.value("singleCornerRadius", defaults._singleCornerRadius.current());
	s._streamerMode = j.value("streamerMode", defaults._streamerMode.current());

	if (j.contains("messageShotSettings") && j["messageShotSettings"].is_object()) {
		j["messageShotSettings"].get_to(s._messageShotSettings);
	}
}
