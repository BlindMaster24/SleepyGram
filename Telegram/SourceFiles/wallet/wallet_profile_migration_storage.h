/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "storage/storage_account_paths.h"
#include "wallet/wallet_vault.h"

namespace Wallet {

struct LegacyWalletSourceFileProof {
	QString relativePath;
	QByteArray sha256;
};

struct UnlockedLegacyWalletProfileRing {
	DeviceKeyring keyring;
	SecureBytes deviceKey;
	std::vector<LegacyWalletSourceFileProof> files;
};

struct VerifiedLegacyWalletProfileRecord {
	QByteArray value;
	std::vector<LegacyWalletSourceFileProof> files;
};

struct LegacyWalletProfileRingReading {
	enum class State {
		Absent,
		Ready,
		WalletPasscodeRequired,
		WalletPasscodeRejected,
		Unsupported,
		InvalidSource,
	};
	State state = State::InvalidSource;
	std::optional<UnlockedLegacyWalletProfileRing> unlocked;
};

// The caller holds the exclusive, quiesced legacy-profile lease throughout.
[[nodiscard]] LegacyWalletProfileRingReading ReadLegacyWalletProfileRing(
	const QString &canonicalDataDirectory,
	const QString &dataName,
	const MTP::AuthKeyPtr &authenticatedLegacyKey,
	const SecureBytes *dedicatedWalletPasscode = nullptr);

[[nodiscard]] std::optional<VerifiedLegacyWalletProfileRecord> ReadLegacyWalletProfileRecord(
	const Storage::AccountPaths &authenticatedAccount,
	Storage::FileKey fileKey,
	const QString &storageKey,
	const MTP::AuthKeyPtr &authenticatedLegacyKey);

} // namespace Wallet
