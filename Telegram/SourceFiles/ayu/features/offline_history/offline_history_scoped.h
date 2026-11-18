// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/offline_history/offline_history_storage.h"
#include "ayu/features/offline_history/offline_history_paths.h"

#include <memory>
#include <optional>
#include <span>

namespace MTP {
class AuthKey;
using AuthKeyPtr = std::shared_ptr<AuthKey>;
} // namespace MTP

namespace Ayu::OfflineHistory {

struct ScopedOfflineAccount final {
	quint64 userId = 0;
	QString accountRoot;
	MTP::AuthKeyPtr key;
};

[[nodiscard]] std::optional<OfflineRetirementInventory> StageLegacyOfflineHistory(
	const QString &dataDirectory,
	std::span<const ScopedOfflineAccount> accounts);

namespace Storage {

[[nodiscard]] Paths ScopedPathsFor(const ScopedOfflineAccount &account, PeerId peer);
[[nodiscard]] QString ScopedAttachmentPath(
	const ScopedOfflineAccount &account,
	const Paths &paths,
	const Attachment &attachment);
[[nodiscard]] std::optional<QByteArray> ReadScopedFile(
	const ScopedOfflineAccount &account,
	const QString &path);
[[nodiscard]] bool WriteScopedFile(
	const ScopedOfflineAccount &account,
	const QString &path,
	const QByteArray &bytes,
	qint64 quota,
	const QStringList &excluded = {});
[[nodiscard]] bool ScopedFilePresent(
	const ScopedOfflineAccount &account,
	const QString &path,
	qint64 payloadSize);
[[nodiscard]] bool RemoveScopedPeer(
	const ScopedOfflineAccount &account,
	const Paths &paths);

} // namespace Storage
} // namespace Ayu::OfflineHistory
