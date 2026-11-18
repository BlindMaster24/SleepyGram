/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <optional>
#include <span>
#include <vector>

namespace Wallet {

class SecureBytes;
struct DeviceKeyring;

struct ProfileMigrationVaultRecord {
	QString storageKey;
	QByteArray encryptedValue;
};

struct ProfileMigrationWalletAccount {
	quint64 owner = 0;
	std::span<const QString> custodySecretRefs;
	std::span<const ProfileMigrationVaultRecord> secretRecords;
	const SecureBytes *destinationPasscode = nullptr;
};

struct ScopedProfileMigrationWallet {
	quint64 owner = 0;
	QByteArray scopedKeyring;
	std::vector<ProfileMigrationVaultRecord> secretRecords;
};

struct ScopedProfileMigrationWalletProof {
	QByteArray deviceKeySha256;
};

[[nodiscard]] std::optional<std::vector<QString>> ReadProfileMigrationCustodyRefs(
	const QString &storageKey,
	const QByteArray &decryptedValue);

[[nodiscard]] std::optional<ScopedProfileMigrationWalletProof>
VerifyScopedProfileMigrationWallet(
	const ProfileMigrationWalletAccount &account,
	const SecureBytes &oldDeviceKey,
	const QByteArray &scopedKeyring);

// Owners and complete custody inventories must come from authenticated source accounts.
[[nodiscard]] std::optional<std::vector<ScopedProfileMigrationWallet>>
PlanProfileWalletMigration(
	const DeviceKeyring &authorizedOldRing,
	const SecureBytes &oldDeviceKey,
	std::span<const ProfileMigrationWalletAccount> accounts);

} // namespace Wallet
