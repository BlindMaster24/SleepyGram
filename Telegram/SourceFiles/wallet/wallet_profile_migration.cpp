/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "wallet/wallet_profile_migration.h"

#include "storage/serialize_common.h"
#include "wallet/wallet_custody.h"
#include "wallet/wallet_vault.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QIODevice>

#include <openssl/crypto.h>

#include <algorithm>
#include <map>
#include <set>

namespace Wallet {
namespace {

using EntriesById = std::map<QByteArray, const DeviceKeyringEntry*>;

bool AsciiToken(const QString &text) {
	return !text.isEmpty() && std::ranges::all_of(text, [](QChar ch) {
		return ch.unicode() > 0x20 && ch.unicode() < 0x7F;
	});
}

bool ValidCustodyIdentifier(const QString &identifier) {
	return AsciiToken(identifier)
		&& !identifier.contains(QLatin1Char('/'))
		&& !identifier.contains(QLatin1Char('\\'));
}

bool ValidOptionalPublicKey(const QByteArray &key) {
	return key.isEmpty() || key.size() == kCustodyPublicKeySize;
}

std::optional<CustodyRecord> ReadStableCustodyRecord(
		Serialize::ByteArrayReader &stream,
		quint32 version) {
	auto record = CustodyRecord();
	auto network = qint32();
	auto flags = quint32();
	stream
		>> record.recordId
		>> record.address
		>> record.publicKey
		>> network
		>> record.secretRef
		>> flags;
	if (version >= 4) {
		stream >> record.signingKey;
	}
	constexpr auto kActiveFlag = quint32(1U << 0);
	constexpr auto kRotatedSinceBackupFlag = quint32(1U << 1);
	const auto allowedFlags = (version >= 3)
		? (kActiveFlag | kRotatedSinceBackupFlag)
		: kActiveFlag;
	if (!stream.ok()
		|| !ValidCustodyIdentifier(record.recordId)
		|| !AsciiToken(record.address)
		|| record.publicKey.size() != kCustodyPublicKeySize
		|| (network != 1 && network != 2)
		|| !ValidCustodyIdentifier(record.secretRef)
		|| (flags & ~allowedFlags)
		|| !ValidOptionalPublicKey(record.signingKey)) {
		return std::nullopt;
	}
	return record;
}

bool OpensRecord(
		const SecureBytes &deviceKey,
		const DeviceKeyringEntry &entry,
		const ProfileMigrationVaultRecord &record) {
	const auto key = OpenDeviceKeyringEntry(deviceKey, entry);
	return key && OpenVaultRecord(
		*key,
		record.storageKey,
		entry.keyId,
		record.encryptedValue).has_value();
}

std::optional<DeviceKeyring> VerifyAccountRecords(
		const ProfileMigrationWalletAccount &account,
		const VaultWrap &sourceWrap,
		const SecureBytes &oldDeviceKey,
		EntriesById &remaining) {
	if (account.secretRecords.empty()
		|| account.secretRecords.size() > remaining.size()
		|| account.secretRecords.size() != account.custodySecretRefs.size()) {
		return std::nullopt;
	}
	auto storageKeys = std::set<QString>();
	for (const auto &reference : account.custodySecretRefs) {
		if (!ValidCustodyIdentifier(reference)
			|| !storageKeys.emplace(VaultSecretStorageKey(reference)).second) {
			return std::nullopt;
		}
	}
	auto result = DeviceKeyring{ .wrap = sourceWrap };
	result.entries.reserve(account.secretRecords.size());
	for (const auto &record : account.secretRecords) {
		if (!storageKeys.erase(record.storageKey)) {
			return std::nullopt;
		}
		const auto id = ReadVaultRecordKeyId(record.encryptedValue);
		const auto entry = id ? remaining.find(*id) : remaining.end();
		if (entry == remaining.end()
			|| entry->second->accountId != account.owner
			|| !OpensRecord(oldDeviceKey, *entry->second, record)) {
			return std::nullopt;
		}
		result.entries.push_back(*entry->second);
		remaining.erase(entry);
	}
	return result;
}

QByteArray ExactPasscode(const SecureBytes *credential) {
	if (!credential) {
		return {};
	}
	const auto bytes = credential->span();
	return QByteArray::fromRawData(
		reinterpret_cast<const char*>(bytes.data()),
		bytes.size());
}

EntriesById IndexEntries(const DeviceKeyring &ring) {
	auto result = EntriesById();
	for (const auto &entry : ring.entries) {
		result.emplace(entry.keyId, &entry);
	}
	return result;
}

std::optional<ScopedProfileMigrationWallet> RotateAccountRecords(
		const ProfileMigrationWalletAccount &account,
		const DeviceKeyring &verified,
		const SecureBytes &oldDeviceKey) {
	const auto next = account.destinationPasscode
		? PrepareVaultPasscodeWrap(ExactPasscode(account.destinationPasscode))
		: PrepareVaultOpenWrap();
	const auto rotated = next
		? RotateDeviceKeyring(verified, oldDeviceKey, *next)
		: std::nullopt;
	if (!rotated) {
		return std::nullopt;
	}
	auto serialized = SerializeDeviceKeyring(rotated->keyring);
	if (!VerifyScopedProfileMigrationWallet(account, oldDeviceKey, serialized)) {
		return std::nullopt;
	}
	auto result = ScopedProfileMigrationWallet{
		.owner = account.owner,
		.scopedKeyring = std::move(serialized),
	};
	result.secretRecords.reserve(account.secretRecords.size());
	for (const auto &record : account.secretRecords) {
		auto &copy = result.secretRecords.emplace_back(record);
		copy.storageKey.detach();
		copy.encryptedValue.detach();
	}
	return result;
}

} // namespace

std::optional<std::vector<QString>> ReadProfileMigrationCustodyRefs(
		const QString &storageKey,
		const QByteArray &decryptedValue) {
	if (storageKey != u"custody/records"_q) {
		return std::nullopt;
	}
	constexpr auto kLastKnownVersion = quint32(4);
	auto stream = Serialize::ByteArrayReader(decryptedValue);
	auto version = quint32();
	auto count = quint32();
	stream >> version >> count;
	const auto minRecordSize = qint64(sizeof(quint32)) * (version >= 4 ? 7 : 6)
		+ kCustodyPublicKeySize;
	if (!stream.ok() || !version || version > kLastKnownVersion
		|| count > stream.underlying().device()->bytesAvailable() / minRecordSize) {
		return std::nullopt;
	}
	auto recordIds = std::set<QString>();
	auto refs = std::set<QString>();
	auto result = std::vector<QString>();
	for (auto i = quint32(0); i != count; ++i) {
		auto record = ReadStableCustodyRecord(stream, version);
		if (!record
			|| !recordIds.emplace(std::move(record->recordId)).second
			|| !refs.emplace(record->secretRef).second) {
			return std::nullopt;
		}
		result.push_back(std::move(record->secretRef));
	}
	if (version >= 2) {
		auto lastSeenServerKey = QByteArray();
		stream >> lastSeenServerKey;
		if (!ValidOptionalPublicKey(lastSeenServerKey)) {
			return std::nullopt;
		}
	}
	auto flags = quint32();
	if (version >= 3) {
		stream >> flags;
	}
	if (!stream.ok() || flags || !stream.atEnd()) {
		return std::nullopt;
	}
	return result;
}

std::optional<ScopedProfileMigrationWalletProof> VerifyScopedProfileMigrationWallet(
		const ProfileMigrationWalletAccount &account,
		const SecureBytes &oldDeviceKey,
		const QByteArray &scopedKeyring) {
	if (oldDeviceKey.span().size() != kVaultKeySize
		|| (account.destinationPasscode && account.destinationPasscode->empty())) {
		return std::nullopt;
	}
	const auto reading = ParseScopedDeviceKeyring(scopedKeyring, account.owner);
	const auto expectedKind = account.destinationPasscode ? VaultKind::Passcode : VaultKind::Open;
	if (reading.state != KeyringReading::State::Read
		|| reading.keyring.wrap.kind != expectedKind
		|| reading.keyring.entries.size() != account.secretRecords.size()) {
		return std::nullopt;
	}
	const auto &wrap = reading.keyring.wrap;
	const auto wrapKey = DeriveVaultWrapKey(wrap, ExactPasscode(account.destinationPasscode));
	const auto deviceKey = wrapKey ? UnwrapVaultKey(wrap, *wrapKey) : std::nullopt;
	if (!deviceKey || !CRYPTO_memcmp(
			deviceKey->span().data(),
			oldDeviceKey.span().data(),
			kVaultKeySize)) {
		return std::nullopt;
	}
	auto entries = IndexEntries(reading.keyring);
	if (!VerifyAccountRecords(account, wrap, *deviceKey, entries) || !entries.empty()) {
		return std::nullopt;
	}
	return ScopedProfileMigrationWalletProof{
		.deviceKeySha256 = QCryptographicHash::hash(
			QByteArrayView(
				reinterpret_cast<const char*>(deviceKey->span().data()), kVaultKeySize),
			QCryptographicHash::Sha256),
	};
}

std::optional<std::vector<ScopedProfileMigrationWallet>>
PlanProfileWalletMigration(
		const DeviceKeyring &authorizedOldRing,
		const SecureBytes &oldDeviceKey,
		std::span<const ProfileMigrationWalletAccount> accounts) {
	const auto sourceKind = authorizedOldRing.wrap.kind;
	if (accounts.empty()
		|| (sourceKind != VaultKind::Passcode && sourceKind != VaultKind::Open)
		|| oldDeviceKey.span().size() != kVaultKeySize
		|| accounts.size() > authorizedOldRing.entries.size()
		|| SerializeDeviceKeyring(authorizedOldRing).isEmpty()) {
		return std::nullopt;
	}
	auto remaining = IndexEntries(authorizedOldRing);
	auto owners = std::set<quint64>();
	auto verified = std::vector<DeviceKeyring>();
	verified.reserve(accounts.size());
	for (const auto &account : accounts) {
		if (!account.owner
			|| !owners.emplace(account.owner).second
			|| (sourceKind == VaultKind::Passcode && !account.destinationPasscode)
			|| (account.destinationPasscode && account.destinationPasscode->empty())) {
			return std::nullopt;
		}
		auto ring = VerifyAccountRecords(
			account,
			authorizedOldRing.wrap,
			oldDeviceKey,
			remaining);
		if (!ring) {
			return std::nullopt;
		}
		verified.push_back(std::move(*ring));
	}
	if (!remaining.empty()) {
		return std::nullopt;
	}
	auto result = std::vector<ScopedProfileMigrationWallet>();
	result.reserve(accounts.size());
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		auto migrated = RotateAccountRecords(accounts[i], verified[i], oldDeviceKey);
		if (!migrated) {
			return std::nullopt;
		}
		result.push_back(std::move(*migrated));
	}
	return result;
}

} // namespace Wallet
