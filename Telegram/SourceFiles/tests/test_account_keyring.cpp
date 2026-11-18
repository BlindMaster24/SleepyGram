/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/account_keyring.h"

#include <openssl/rand.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>

#include <array>
#include <cstdio>

namespace {

using namespace Ayu::ProfileSets;

int RunChecks() {
	auto passed = 0;
	auto total = 0;
	const auto check = [&](const char *name, bool condition) {
		++total;
		if (condition) {
			++passed;
			std::printf("PASS %s\n", name);
		} else {
			std::printf("FAIL %s\n", name);
		}
	};

	auto wrappingKey = QByteArray(kAccountKeyringWrappingKeySize, Qt::Uninitialized);
	if (RAND_bytes(
		reinterpret_cast<unsigned char*>(wrappingKey.data()),
		wrappingKey.size()) != 1) {
		return 1;
	}
	const auto first = NewAccountKey({ 1, 7 });
	const auto second = NewAccountKey({ 1, 8 });
	if (!first || !second) {
		return 1;
	}
	const auto accounts = std::vector<AccountKey>{ *first, *second };
	const auto fixtureKey = AccountKey{ { 1, 7 }, QByteArray(kAccountKeySize, 'k') };
	auto local = std::array<char, kAccountLocalStorageKeySize>();
	auto otherLocal = std::array<char, kAccountLocalStorageKeySize>();
	check("local-storage-key-format", DeriveAccountLocalStorageKey(
		fixtureKey, bytes::make_span(local))
		&& QCryptographicHash::hash(
			QByteArrayView(local.data(), local.size()),
			QCryptographicHash::Sha256).toHex()
			== "6484322b3a2b302f559936a3b392bf9b90ce1b8596dac762c7321cfa59650b27");
	check("local-storage-key-is-bound-to-account-id",
		DeriveAccountLocalStorageKey(
			{ { 1, 8 }, fixtureKey.key }, bytes::make_span(otherLocal))
		&& local != otherLocal);
	check("invalid-local-storage-keys-rejected",
		!DeriveAccountLocalStorageKey(
			{ {}, fixtureKey.key }, bytes::make_span(otherLocal))
		&& !DeriveAccountLocalStorageKey(
			{ fixtureKey.id, QByteArray(kAccountKeySize, '\0') },
			bytes::make_span(otherLocal))
		&& !DeriveAccountLocalStorageKey(
			fixtureKey, bytes::make_span(otherLocal).subspan(1)));
	KeyringError error = KeyringError::Malformed;
	const auto sealed = SealAccountKeyring(accounts, wrappingKey, &error);
	const auto restored = OpenAccountKeyring(sealed, wrappingKey, &error);
	check("authenticated-round-trip", restored && *restored == accounts
		&& error == KeyringError::None);

	auto wrongKey = QByteArray(kAccountKeyringWrappingKeySize, 'x');
	const auto wrongKeyResult = OpenAccountKeyring(sealed, wrongKey, &error);
	check("wrong-wrapping-key-rejected", !wrongKeyResult
		&& error == KeyringError::AuthenticationFailed);

	auto tampered = sealed;
	tampered[tampered.size() - 1] = char(tampered.back() ^ 1);
	const auto tamperedResult = OpenAccountKeyring(tampered, wrappingKey, &error);
	check("tampered-tag-rejected", !tamperedResult
		&& error == KeyringError::AuthenticationFailed);

	const auto truncatedResult = OpenAccountKeyring(
		sealed.left(sealed.size() - 1), wrappingKey, &error);
	check("truncated-record-rejected", !truncatedResult
		&& error == KeyringError::Malformed);
	auto unknownVersion = sealed;
	unknownVersion[7] = char(2);
	const auto unknownVersionResult = OpenAccountKeyring(
		unknownVersion, wrappingKey, &error);
	check("unknown-version-rejected", !unknownVersionResult
		&& error == KeyringError::UnsupportedVersion);

	auto duplicateId = accounts;
	duplicateId[1].id = duplicateId[0].id;
	check("duplicate-account-id-rejected", ValidateAccountKeys(duplicateId)
		== KeyringError::DuplicateAccountId
		&& SealAccountKeyring(duplicateId, wrappingKey, &error).isEmpty()
		&& error == KeyringError::DuplicateAccountId);

	auto duplicateKey = accounts;
	duplicateKey[1].key = duplicateKey[0].key;
	check("duplicate-account-key-rejected", ValidateAccountKeys(duplicateKey)
		== KeyringError::DuplicateAccountKey);

	auto badKey = accounts;
	badKey[0].key.chop(1);
	check("wrong-account-key-size-rejected", ValidateAccountKeys(badKey)
		== KeyringError::InvalidAccountKey);
	auto tooMany = std::vector<AccountKey>(
		65'537,
		AccountKey{ .id = { 0, 1 }, .key = QByteArray(kAccountKeySize, 'k') });
	check("account-count-bound-enforced", ValidateAccountKeys(tooMany)
		== KeyringError::TooManyAccounts);

	const auto legacy = QByteArray(256, 'L');
	const auto legacyResult = OpenAccountKeyring(legacy, wrappingKey, &error);
	check("legacy-root-key-is-not-interpreted-as-keyring", !legacyResult
		&& error == KeyringError::Malformed);

	auto invalidKey = wrappingKey.left(wrappingKey.size() - 1);
	check("wrong-wrapping-key-size-rejected",
		SealAccountKeyring(accounts, invalidKey, &error).isEmpty()
		&& error == KeyringError::InvalidWrappingKey);
	const auto zeroWrappingKey = QByteArray(
		kAccountKeyringWrappingKeySize, '\0');
	check("default-zero-wrapping-key-rejected",
		SealAccountKeyring(accounts, zeroWrappingKey, &error).isEmpty()
		&& error == KeyringError::InvalidWrappingKey);

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	return RunChecks();
}
