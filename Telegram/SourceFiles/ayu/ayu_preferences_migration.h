// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/libs/json.hpp"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace MTP {
class AuthKey;
using AuthKeyPtr = std::shared_ptr<AuthKey>;
} // namespace MTP

namespace Ayu::Preferences {

struct Watermark final {
	quint64 peerId = 0;
	quint64 topicRootId = 0;
	qint64 readTill = 0;
	bool manuallyUnread = false;
};

struct AccountData final {
	std::optional<nlohmann::json> ghostMode;
	std::vector<Watermark> watermarks;
	bool filteredUnread = false;
	std::map<quint64, int> deletedPolicies;
};

struct LegacyPartition final {
	QByteArray sourceSha256;
	QByteArray globals;
	std::map<quint64, QByteArray> accounts;
};

[[nodiscard]] std::optional<LegacyPartition> ReadLegacyPartition(
	const QString &dataDirectory,
	std::span<const quint64> verifiedUsers);
[[nodiscard]] std::optional<LegacyPartition> PartitionLegacyPreferences(
	QByteArrayView source,
	std::span<const quint64> verifiedUsers);

[[nodiscard]] bool ValidateScopedGlobalPreferences(QByteArrayView payload);
[[nodiscard]] QByteArray EncodeAccountData(quint64 user, const AccountData &data);
[[nodiscard]] std::optional<AccountData> DecodeAccountData(
	QByteArrayView payload,
	quint64 expectedUser);

[[nodiscard]] bool StageScopedAccountPreferences(
	const QString &accountRoot,
	quint64 expectedUser,
	const MTP::AuthKeyPtr &key,
	const QByteArray &payload);
[[nodiscard]] bool StageScopedGlobalPreferences(
	const QString &settingsDirectory,
	const MTP::AuthKeyPtr &key,
	const QByteArray &sanitizedGlobals);
[[nodiscard]] std::optional<QByteArray> ReadScopedAccountPreferences(
	const QString &accountRoot,
	quint64 expectedUser,
	const MTP::AuthKeyPtr &key);
[[nodiscard]] bool WriteScopedAccountPreferences(
	const QString &accountRoot,
	quint64 expectedUser,
	const MTP::AuthKeyPtr &key,
	const QByteArray &payload);

} // namespace Ayu::Preferences
