/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "wallet/wallet_profile_migration.h"

#include "storage/serialize_common.h"
#include "wallet/wallet_vault.h"

#include <algorithm>
#include <array>
#include <cstdio>

namespace {

using namespace Wallet;

constexpr auto kFirstOwner = quint64(101);
constexpr auto kSecondOwner = quint64(0x0100'0000'0000'0065ULL);
const auto kCustodyStorageKey = u"custody/records"_q;

struct CustodyWireRecord {
	QString recordId;
	QString secretRef;
	QString address = u"0:"_q + QString(64, QLatin1Char('a'));
	QByteArray publicKey = QByteArray(32, 'p');
	qint32 network = 1;
	quint32 flags = 0;
	QByteArray signingKey;
};

QByteArray CustodyValue(
		quint32 version,
		std::span<const CustodyWireRecord> records,
		const QByteArray &lastSeenServerKey = QByteArray(32, 's'),
		quint32 storeFlags = 0) {
	auto stream = Serialize::ByteArrayWriter();
	stream << version << quint32(records.size());
	for (const auto &record : records) {
		stream
			<< record.recordId
			<< record.address
			<< record.publicKey
			<< record.network
			<< record.secretRef
			<< record.flags;
		if (version >= 4) {
			stream << record.signingKey;
		}
	}
	if (version >= 2) {
		stream << lastSeenServerKey;
	}
	if (version >= 3) {
		stream << storeFlags;
		if (storeFlags & 1) {
			stream << u"pending-id"_q << u"pending-ref"_q << u"pending-op"_q;
			if (version >= 4) {
				stream << QByteArray(32, 'k');
			}
		}
	}
	return std::move(stream).result();
}

template <typename Check>
void CheckCustodyReader(Check check) {
	const auto records = std::array{
		CustodyWireRecord{
			.recordId = u"active-id"_q,
			.secretRef = u"wallet:active-id:mnemonic"_q,
			.flags = 1,
		},
		CustodyWireRecord{
			.recordId = u"parked-id"_q,
			.secretRef = u"wallet:parked-id:mnemonic"_q,
			.network = 2,
		},
	};
	const auto refs = std::vector{ records[0].secretRef, records[1].secretRef };
	const auto read = [](const QByteArray &value) {
		return ReadProfileMigrationCustodyRefs(kCustodyStorageKey, value);
	};
	for (auto version = quint32(1); version <= 4; ++version) {
		const auto parsed = read(CustodyValue(version, records));
		check(parsed && *parsed == refs, "historical active and parked references");
		const auto publicOnly = read(CustodyValue(version, {}));
		check(publicOnly && publicOnly->empty(), "historical public-only custody");
	}
	auto changed = records;
	changed[1].flags = 2;
	changed[1].signingKey = QByteArray(32, 'k');
	check(read(CustodyValue(4, changed)) == refs, "completed rotation retained");
	check(!read(CustodyValue(2, changed)), "flag outside historical format");
	changed[1].flags = 4;
	check(!read(CustodyValue(4, changed)), "rotation still waiting for server key");
	changed[1].flags = 8;
	check(!read(CustodyValue(4, changed)), "unknown record flag");
	changed = records;
	changed[1].recordId = changed[0].recordId;
	check(!read(CustodyValue(4, changed)), "duplicate record ID");
	changed[1].recordId = u"broken"_q + QChar(0);
	check(!read(CustodyValue(4, changed)), "record ID with embedded NUL");
	changed = records;
	changed[1].secretRef = changed[0].secretRef;
	check(!read(CustodyValue(4, changed)), "duplicate secret reference");
	for (const auto &bad : { QString(), u"secret/ref"_q, u"a\\b"_q, u"a b"_q, u"λ"_q }) {
		changed[1].secretRef = bad;
		check(!read(CustodyValue(4, changed)), "malformed secret reference");
	}
	changed = records;
	changed[1].address.clear();
	check(!read(CustodyValue(4, changed)), "missing address");
	changed = records;
	changed[1].network = 3;
	check(!read(CustodyValue(4, changed)), "unknown custody network");
	changed = records;
	changed[1].publicKey.chop(1);
	check(!read(CustodyValue(4, changed)), "invalid anchor key length");
	changed = records;
	changed[1].signingKey = QByteArray(31, 'k');
	check(!read(CustodyValue(4, changed)), "invalid signing key length");
	check(!read(CustodyValue(4, records, QByteArray(33, 'k'))), "invalid server key length");
	check(!read(CustodyValue(3, {}, {}, 1)), "pending-only legacy rotation rejected");
	check(!read(CustodyValue(4, records, {}, 1)), "pending key rejected");
	check(!read(CustodyValue(4, {}, {}, 2)), "unknown store flag");
	check(!read(CustodyValue(0, {})) && !read(CustodyValue(5, {})), "unsupported versions");
	check(!read(QByteArray::fromHex("00000004ffffffff")), "unbacked record count");
	const auto current = CustodyValue(4, records);
	check(!ReadProfileMigrationCustodyRefs(u"journal/id/slot"_q, current), "no journal reader");
	check(!read(current + 'x'), "trailing custody payload");
	for (auto size = qsizetype(0); size != current.size(); ++size) {
		check(!read(current.first(size)), "truncated custody data");
	}
}

bool AddSecret(
		DeviceKeyringRotation &old,
		quint64 owner,
		const QString &reference,
		char seed,
		std::vector<ProfileMigrationVaultRecord> &records) {
	const auto keyId = QByteArray(kVaultKeyIdSize, seed);
	const auto key = SecureBytes(QByteArray(kVaultKeySize, seed));
	auto entry = SealDeviceKeyringEntry(old.key, keyId, owner, key);
	const auto storageKey = VaultSecretStorageKey(reference);
	const auto secret = QByteArray(11, seed);
	auto ciphertext = SealVaultRecord(
		key,
		storageKey,
		keyId,
		seed == 'a',
		bytes::make_span(secret));
	if (!entry || ciphertext.isEmpty()) {
		return false;
	}
	old.keyring.entries.push_back(std::move(*entry));
	records.push_back({
		.storageKey = storageKey,
		.encryptedValue = std::move(ciphertext),
	});
	return true;
}

std::optional<SecureBytes> Unlock(
		const DeviceKeyring &ring,
		const QByteArray &passcode) {
	const auto key = DeriveVaultWrapKey(ring.wrap, passcode);
	return key ? UnwrapVaultKey(ring.wrap, *key) : std::nullopt;
}

} // namespace

int main() {
	using State = KeyringReading::State;
	const auto open = PrepareVaultOpenWrap();
	auto old = open ? RotateDeviceKeyring({}, {}, *open) : std::nullopt;
	const auto firstRefs = std::array{ u"same-ref"_q, u"second-ref"_q };
	const auto secondRefs = std::array{ u"same-ref"_q };
	auto firstRecords = std::vector<ProfileMigrationVaultRecord>();
	auto secondRecords = std::vector<ProfileMigrationVaultRecord>();
	if (!old
		|| !AddSecret(*old, kFirstOwner, firstRefs[0], 'a', firstRecords)
		|| !AddSecret(*old, kFirstOwner, firstRefs[1], 'b', firstRecords)
		|| !AddSecret(*old, kSecondOwner, secondRefs[0], 'c', secondRecords)) {
		return 2;
	}
	const auto firstText = u" wallet α "_q.toUtf8();
	const auto secondText = u"wallet β"_q.toUtf8();
	const auto firstPasscode = SecureBytes(firstText);
	const auto secondPasscode = SecureBytes(secondText);
	const auto accounts = std::array{
		ProfileMigrationWalletAccount{
			.owner = kFirstOwner,
			.custodySecretRefs = firstRefs,
			.secretRecords = firstRecords,
			.destinationPasscode = &firstPasscode,
		},
		ProfileMigrationWalletAccount{
			.owner = kSecondOwner,
			.custodySecretRefs = secondRefs,
			.secretRecords = secondRecords,
			.destinationPasscode = &secondPasscode,
		},
	};
	auto checks = 0;
	auto failures = 0;
	const auto check = [&](bool passed, const char *name) {
		++checks;
		if (!passed) {
			++failures;
			std::fprintf(stderr, "Failed: %s\n", name);
		}
	};
	CheckCustodyReader(check);
	const auto sourceRing = SerializeDeviceKeyring(old->keyring);
	const auto migrated = PlanProfileWalletMigration(old->keyring, old->key, accounts);
	check(migrated && migrated->size() == accounts.size(), "migrates both owner scopes");
	if (!migrated || migrated->size() != accounts.size()) {
		return 1;
	}
	const auto &first = (*migrated)[0];
	const auto &second = (*migrated)[1];
	const auto reopenedFirst = VerifyScopedProfileMigrationWallet(accounts[0], old->key, first.scopedKeyring);
	const auto reopenedSecond = VerifyScopedProfileMigrationWallet(accounts[1], old->key, second.scopedKeyring);
	check(reopenedFirst && reopenedSecond
		&& reopenedFirst->deviceKeySha256 != reopenedSecond->deviceKeySha256,
		"retry proves owner-specific wrapped device keys with no rotation");
	const auto firstRead = ParseScopedDeviceKeyring(first.scopedKeyring, kFirstOwner);
	const auto secondRead = ParseScopedDeviceKeyring(second.scopedKeyring, kSecondOwner);
	check(first.owner == kFirstOwner && second.owner == kSecondOwner, "exact owners");
	check(firstRead.state == State::Read && secondRead.state == State::Read, "scoped codecs");
	check(ParseScopedDeviceKeyring(first.scopedKeyring, kSecondOwner).state == State::Broken,
		"one scoped keyring cannot be parsed for another owner");
	const auto firstD = Unlock(firstRead.keyring, firstText);
	const auto secondD = Unlock(secondRead.keyring, secondText);
	check(firstD && secondD, "destination passcodes open their own wraps");
	check(!Unlock(firstRead.keyring, firstText.trimmed()), "exact first passcode bytes");
	check(!Unlock(firstRead.keyring, secondText), "other destination passcode rejected");
	check(firstRead.keyring.wrap.salt != secondRead.keyring.wrap.salt, "new per-owner salts");
	if (!firstD || !secondD || firstRead.keyring.entries.size() != 2
		|| secondRead.keyring.entries.size() != 1) {
		return 1;
	}
	check(!std::ranges::equal(firstD->span(), secondD->span()), "independent device keys");
	check(!OpenDeviceKeyringEntry(old->key, firstRead.keyring.entries.front()),
		"old device key rejected");
	check(!OpenDeviceKeyringEntry(*firstD, secondRead.keyring.entries.front()),
		"neighbor device key rejected");
	const auto recordCheck = [&](
			const auto &out,
			const auto &input,
			const auto &ring,
			const SecureBytes &deviceKey,
			char seed) {
		check(out.size() == input.size(), "exact record count");
		for (auto i = size_t(0); i != out.size() && i != input.size(); ++i, ++seed) {
			const auto &entry = ring.entries[i];
			const auto key = OpenDeviceKeyringEntry(deviceKey, entry);
			const auto secret = key ? OpenVaultRecord(
				*key, out[i].storageKey, entry.keyId, out[i].encryptedValue) : std::nullopt;
			check(out[i].storageKey == input[i].storageKey
				&& out[i].encryptedValue == input[i].encryptedValue,
				"original nested ciphertext preserved");
			check(secret && secret->requireUserPresence == (seed == 'a')
				&& std::ranges::equal(secret->bytes.span(), bytes::make_span(QByteArray(11, seed))),
				"original payload and user-presence policy preserved");
		}
	};
	recordCheck(first.secretRecords, firstRecords, firstRead.keyring, *firstD, 'a');
	recordCheck(second.secretRecords, secondRecords, secondRead.keyring, *secondD, 'c');
	const auto rejects = [&](const auto &changed) {
		return !PlanProfileWalletMigration(old->keyring, old->key, changed);
	};
	check(rejects(std::span(accounts).first(1)), "rejects entire omitted owner");
	check(rejects(std::span(accounts).first(0)), "rejects empty reservation");
	auto changed = accounts;
	changed[0].owner = 0;
	check(rejects(changed), "rejects zero owner");
	changed[0].owner = kSecondOwner;
	check(rejects(changed), "rejects wrong authenticated owner");
	changed = accounts;
	changed[1] = changed[0];
	check(rejects(changed), "rejects duplicate fully valid owner");
	changed = accounts;
	changed[0].destinationPasscode = nullptr;
	changed[1].destinationPasscode = nullptr;
	const auto openAccounts = changed;
	const auto openMigration = PlanProfileWalletMigration(old->keyring, old->key, openAccounts);
	check(openMigration && openMigration->size() == 2
		&& ParseScopedDeviceKeyring((*openMigration)[0].scopedKeyring, kFirstOwner)
			.keyring.wrap.kind == VaultKind::Open
		&& VerifyScopedProfileMigrationWallet(
			openAccounts[1], old->key, (*openMigration)[1].scopedKeyring),
		"legacy Open preserves the mode inside each scoped account");
	auto originalOwnerRing = old->keyring;
	originalOwnerRing.entries.resize(2);
	check(!VerifyScopedProfileMigrationWallet(
		openAccounts[0], old->key, SerializeDeviceKeyring(originalOwnerRing)),
		"retry refuses a scoped ring retaining the shared legacy device key");
	check(!VerifyScopedProfileMigrationWallet(openAccounts[0], old->key, first.scopedKeyring),
		"retry does not mix Open and Passcode policies");
	auto protectedSource = old->keyring;
	protectedSource.wrap = firstRead.keyring.wrap;
	check(!PlanProfileWalletMigration(protectedSource, old->key, openAccounts),
		"protected source cannot silently downgrade to Open");
	const auto emptyPasscode = SecureBytes();
	changed[0].destinationPasscode = &emptyPasscode;
	check(rejects(changed), "rejects empty destination passcode");
	changed = accounts;
	changed[0].secretRecords = std::span(firstRecords).first(1);
	check(rejects(changed), "rejects missing referenced storage record");
	changed[0].custodySecretRefs = std::span(firstRefs).first(1);
	check(rejects(changed), "rejects unmatched keyring entry");
	const auto duplicateRefs = std::array{ firstRefs[0], firstRefs[0] };
	changed = accounts;
	changed[0].custodySecretRefs = duplicateRefs;
	check(rejects(changed), "rejects duplicate source reference");
	const auto badRefs = std::array{ firstRefs[0], u"a/b"_q };
	changed[0].custodySecretRefs = badRefs;
	check(rejects(changed), "rejects noncanonical logical reference");
	auto modified = firstRecords;
	changed = accounts;
	changed[0].secretRecords = modified;
	modified[1].storageKey = modified[0].storageKey;
	check(rejects(changed), "rejects duplicate source record");
	modified[1] = firstRecords[1];
	modified[1].storageKey = u"journal/transfer/state"_q;
	check(rejects(changed), "rejects journal records");
	modified[1] = firstRecords[1];
	modified[1].encryptedValue = QByteArray("pre-vault fixture");
	check(rejects(changed), "rejects old record formats");
	modified[1].encryptedValue = firstRecords[0].encryptedValue;
	check(rejects(changed), "rejects one key ID assigned to two records");
	modified[1].encryptedValue = firstRecords[1].encryptedValue;
	modified[1].encryptedValue[modified[1].encryptedValue.size() - 1] ^= 1;
	check(rejects(changed), "rejects authenticated record tampering");
	modified[0] = secondRecords[0];
	check(rejects(changed), "rejects same reference borrowed from neighbor owner");
	modified[0] = firstRecords[0];
	modified[1] = firstRecords[1];
	const auto renamedRefs = std::array{ firstRefs[0], u"renamed"_q };
	changed[0].custodySecretRefs = renamedRefs;
	modified[1].storageKey = VaultSecretStorageKey(renamedRefs[1]);
	check(rejects(changed), "rejects ciphertext bound to a different storage key");
	auto invalidRing = old->keyring;
	invalidRing.entries[1].keyId = invalidRing.entries[0].keyId;
	check(!PlanProfileWalletMigration(invalidRing, old->key, accounts),
		"rejects duplicate keyring ID");
	invalidRing = old->keyring;
	invalidRing.entries[0].sealed[0] ^= 1;
	check(!PlanProfileWalletMigration(invalidRing, old->key, accounts),
		"rejects keyring entry tampering");
	const auto wrong = SecureBytes(QByteArray(kVaultKeySize, 'w'));
	check(!PlanProfileWalletMigration(old->keyring, wrong, accounts),
		"rejects wrong old device key");
	check(SerializeDeviceKeyring(old->keyring) == sourceRing, "old keyring remains unchanged");
	std::printf("Passed %d of %d wallet migration checks\n", checks - failures, checks);
	return failures ? 1 : 0;
}
