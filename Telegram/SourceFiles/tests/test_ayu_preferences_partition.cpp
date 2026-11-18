// This is the source code of AyuGram for Desktop.
#include "ayu/ayu_preferences_migration.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

#include <array>
#include <cstdio>
#include <string_view>

namespace {

using namespace Ayu::Preferences;

constexpr auto kUsers = std::array{ quint64(101), quint64(202) };
constexpr auto kPeer = quint64(18446744073709551614ULL);
constexpr auto kSource = R"({
  "showMessageSeconds": true,
  "useGlobalGhostMode": false,
  "shadowBanIds": [],
  "messageShotSettings": {"showBackground": false, "cloudThemeAccountId": 0},
  "ghostModeSettings": {
    "0": {"sendReadMessages": true},
    "101": {"sendReadMessages": false, "sendWithoutSound": 2},
    "202": {"sendReadStories": false}
  },
  "ghostReadState": {
    "101": [
      {"peerId":18446744073709551614,"topicRootId":0,"readTill":420,"manuallyUnread":false}
    ],
    "202": [
      {"peerId":500,"topicRootId":650,"readTill":0,"manuallyUnread":true}
    ]
  },
  "countFilteredUnreadInBadge": {"101": true, "202": false},
  "deletedMessagePolicies": [
    {"accountId":101,"peerId":18446744073709551614,"policy":0},
    {"accountId":202,"peerId":500,"policy":1}
  ]
})";

int Failures = 0;

void Check(bool passed, const char *label) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", label);
	Failures += !passed;
}

void CheckSplit() {
	const auto partition = PartitionLegacyPreferences(kSource, kUsers);
	Check(bool(partition), "strict supported rows partition across both verified accounts");
	if (!partition) {
		return;
	}
	const auto globals = nlohmann::json::parse(partition->globals.toStdString());
	Check(ValidateScopedGlobalPreferences(partition->globals)
		&& globals["ghostModeSettings"].size() == 1
		&& globals["ghostModeSettings"]["0"]["sendReadMessages"] == true
		&& globals["showMessageSeconds"] == true
		&& !globals.contains("ghostReadState")
		&& !globals.contains("deletedMessagePolicies")
		&& !globals.contains("countFilteredUnreadInBadge")
		&& !partition->globals.contains("101") && !partition->globals.contains("202"),
		"global preferences retain settings but contain no positive account IDs");
	const auto firstBytes = partition->accounts.at(101);
	const auto secondBytes = partition->accounts.at(202);
	const auto first = DecodeAccountData(firstBytes, 101);
	const auto second = DecodeAccountData(secondBytes, 202);
	Check(first && first->ghostMode && (*first->ghostMode)["sendWithoutSound"] == 2
		&& first->filteredUnread && first->watermarks.size() == 1
		&& first->watermarks.front().peerId == kPeer
		&& first->watermarks.front().readTill == 420
		&& first->deletedPolicies.at(kPeer) == 0,
		"typed account preferences preserve exact unsigned peer IDs");
	Check(second && second->ghostMode && (*second->ghostMode)["sendReadStories"] == false
		&& !second->filteredUnread && second->watermarks.size() == 1
		&& second->watermarks.front().topicRootId == 650
		&& second->watermarks.front().manuallyUnread
		&& second->deletedPolicies.at(500) == 1,
		"second account receives only its own settings and manual unread state");
	Check(!DecodeAccountData(firstBytes, 202) && !DecodeAccountData(secondBytes, 101),
		"account files are owner-bound");
	Check(!ValidateScopedGlobalPreferences(kSource), "scoped global loader refuses legacy mixed data");
	const auto older = PartitionLegacyPreferences(
		R"({"sendReadMessages":false,"sendWithoutSound":true})", kUsers);
	Check(older && older->globals.contains("\"useGlobalGhostMode\":true")
		&& older->globals.contains("\"sendReadMessages\":false"),
		"historic root ghost preferences keep common-mode behavior");
}

void CheckRefusals() {
	const auto rejects = [](QByteArrayView bytes) {
		return !PartitionLegacyPreferences(bytes, kUsers);
	};
	Check(rejects(R"({"ghostModeSettings":{"303":{"sendReadMessages":false}}})"),
		"orphan owner is never silently dropped");
	Check(rejects(R"({"ghostModeSettings":{"101":{},"0101":{}}})"),
		"noncanonical account IDs cannot alias trusted owner");
	Check(rejects(R"({"ghostModeSettings":{"101":{"sendReadMessages":false,"sendReadMessages":true}}})"),
		"duplicate nested JSON keys fail closed");
	Check(rejects(R"({"showMessageSeconds":true,"showMessageSeconds":false})"),
		"duplicate top-level JSON keys fail closed");
	Check(rejects(R"({"ghostReadState":{"101":[{"peerId":7,"topicRootId":0,"readTill":5,"manuallyUnread":false},{"peerId":7,"topicRootId":0,"readTill":6,"manuallyUnread":false}]}})"),
		"duplicate watermark rows fail closed");
	Check(rejects(R"({"deletedMessagePolicies":[{"accountId":101,"peerId":5.0,"policy":0}]})"),
		"floating-point IDs fail closed");
	Check(rejects(R"({"shadowBanIds":[123]})")
		&& rejects(R"({"messageShotSettings":{"cloudThemeAccessHash":7}})"),
		"unowned shadow bans and cloud theme credentials remain unsupported");
	Check(rejects(R"({"unknown":"keep me"})"), "unknown nonempty data blocks migration");
}

void CheckSourceFile() {
	auto temp = QTemporaryDir();
	const auto root = QDir(temp.path()).canonicalPath();
	if (!temp.isValid() || root.isEmpty()) {
		Check(false, "temporary directory");
		return;
	}
	const auto absent = ReadLegacyPartition(root, kUsers);
	Check(absent && absent->sourceSha256.isEmpty(), "missing source has no deletion proof");
	const auto path = QDir(root).filePath(QString::fromLatin1("ayu_settings.json"));
	auto file = QFile(path);
	const auto raw = QByteArray(kSource);
	if (!file.open(QIODevice::WriteOnly) || file.write(raw) != raw.size()) {
		Check(false, "synthetic settings file");
		return;
	}
	file.close();
	const auto prepared = ReadLegacyPartition(root, kUsers);
	Check(prepared && prepared->sourceSha256
		== QCryptographicHash::hash(raw, QCryptographicHash::Sha256),
		"retirement digest binds the actual complete source bytes");
	Check(file.open(QIODevice::ReadOnly) && file.readAll() == raw,
		"preflight preserves source bytes");
}

} // namespace

int main(int argc, char *argv[]) {
	const auto app = QCoreApplication(argc, argv);
	CheckSplit();
	CheckRefusals();
	CheckSourceFile();
	return Failures ? 1 : 0;
}
