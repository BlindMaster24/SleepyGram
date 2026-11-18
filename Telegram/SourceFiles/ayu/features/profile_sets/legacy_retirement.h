// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/offline_history/offline_history_paths.h"
#include "storage/storage_account_paths.h"

#include <QtCore/QByteArray>
#include <QtCore/QStringList>

#include <span>
#include <vector>

namespace Ayu::ProfileSets {

struct VerifiedLegacyRetirementAccount final {
	int index = 0;
	Storage::AccountPaths paths;
	QStringList dataFiles;
	QStringList tgwFiles;
	QStringList cacheDirectories;
	QStringList cacheFiles;
};

struct LegacyRetirementEntry final {
	QString relativePath;
	QByteArray sha256;
};

struct LegacyRetirementPlan final {
	QString dataDirectory;
	QString dataName;
	QByteArray transactionId;
	std::vector<int> accountIndices;
	std::vector<LegacyRetirementEntry> entries;
	Storage::LegacyWebviewTransfer webview = Storage::LegacyWebviewTransfer::RequireIsolated;
	bool walletInventoryVerified = false;
};

enum class LegacyRetirementResult : uchar {
	Complete,
	InvalidPlan,
	UnexpectedSource,
	FilesystemFailure,
};

enum class LegacyArchiveRetirement : uchar {
	ExpectedAbsent,
	VerifiedPartitioned,
};

// Capture under the same quiesced lease as staged-account verification.
[[nodiscard]] std::optional<LegacyRetirementPlan> CaptureLegacyRetirementPlan(
	const QString &dataDirectory,
	const QString &dataName,
	const QByteArray &transactionId,
	std::span<const int> legacyAccountIndices,
	std::span<const VerifiedLegacyRetirementAccount> verifiedAccounts,
	LegacyArchiveRetirement archive,
	const QByteArray &verifiedAyuSettingsSha256 = {},
	std::span<const OfflineHistory::LegacyOfflineEntry> verifiedOffline = {},
	Storage::LegacyWebviewTransfer webview = Storage::LegacyWebviewTransfer::RequireIsolated,
	const std::vector<LegacyRetirementEntry> *verifiedWalletFiles = nullptr);

[[nodiscard]] QByteArray SerializeLegacyRetirementPlan(
	const LegacyRetirementPlan &plan);
[[nodiscard]] std::optional<LegacyRetirementPlan> ParseLegacyRetirementPlan(
	const QByteArray &serialized);

// The caller holds the lease and has durably committed the authenticated plan.
[[nodiscard]] LegacyRetirementResult RetireLegacyProfileFiles(
	const QString &dataDirectory,
	const QByteArray &committedTransactionId,
	const LegacyRetirementPlan &plan);

} // namespace Ayu::ProfileSets
