/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_vault.h"
#include "base/qt/qt_string.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QEventLoop>

#include <cstdio>
#include <utility>

namespace {

using namespace Ayu::ProfileSets;

QByteArray Verifier(quint32 value) {
	auto result = QByteArray(kVerifierSize, '\0');
	for (auto i = 0; i != 4; ++i) {
		result[i] = char(value >> (8 * i));
	}
	return result;
}

DerivedCredential Credential(quint32 value) {
	return {
		.verifier = Verifier(value),
		.key = QByteArray(kProfileVaultKeySize, char((value % 255) + 1)),
	};
}

Metadata MetadataFixture() {
	return {
		.verifierSalt = QByteArray(kVerifierSaltSize, 's'),
		.verifierKdf = {
			.kind = 2,
			.memory = 16'384,
			.time = 1,
			.parallel = 1,
		},
		.masterVerifier = Verifier(0xFFFFFFFF),
		.sets = {
			{
				.id = { 1, 1 },
				.name = u"Work"_q,
				.verifier = Verifier(1),
				.accounts = { { 4, 1 } },
			},
			{
				.id = { 1, 2 },
				.name = u"Shared"_q,
				.verifier = Verifier(2),
				.accounts = { { 4, 1 }, { 4, 2 } },
			},
			{
				.id = { 1, 3 },
				.name = u"Empty"_q,
				.verifier = Verifier(3),
			},
		},
	};
}

DerivedCredential Derive(
		const QString &password,
		const QByteArray &salt,
		KdfParameters kdf) {
	auto result = DerivedCredential();
	auto loop = QEventLoop();
	DeriveProfileVaultCredential(
		salt,
		kdf,
		password,
		[&](DerivedCredential credential) {
			result = std::move(credential);
			loop.quit();
		});
	loop.exec();
	return result;
}

std::optional<ProfileVault> CreateFixture(
		Metadata metadata,
		ProfileVaultError *error) {
	const auto accounts = std::vector<AccountKey>{
		{ .id = { 4, 1 }, .key = QByteArray(kAccountKeySize, 'A') },
		{ .id = { 4, 2 }, .key = QByteArray(kAccountKeySize, 'B') },
	};
	const auto grants = std::vector<SetGrantCredential>{
		{ .id = { 1, 1 }, .credential = Credential(1) },
		{ .id = { 1, 2 }, .credential = Credential(2) },
		{ .id = { 1, 3 }, .credential = Credential(3) },
	};
	return SealProfileVault(
		metadata,
		accounts,
		Credential(0xFFFFFFFF),
		grants,
		error);
}

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

	check("safe-kdf-parameters-accepted", ValidProfileVaultKdf({
		.kind = 2,
		.memory = 16'384,
		.time = 1,
		.parallel = 1,
	}));
	check("weak-scrypt-parameters-rejected", !ValidProfileVaultKdf({
		.kind = 2,
		.memory = 2,
		.time = 1,
		.parallel = 1,
	}));
	check("oversized-scrypt-parameters-rejected", !ValidProfileVaultKdf({
		.kind = 2,
		.memory = 262'144,
		.time = 1,
		.parallel = 1,
	}));
	check("unbounded-scrypt-parallelism-rejected", !ValidProfileVaultKdf({
		.kind = 2,
		.memory = 16'384,
		.time = 1,
		.parallel = 2,
	}));
	check("argon-kdf-parameters-bounded", ValidProfileVaultKdf({
		.kind = 1,
		.memory = 8'192,
		.time = 1,
		.parallel = 1,
	}) && !ValidProfileVaultKdf({
		.kind = 1,
		.memory = 131'072,
		.time = 1,
		.parallel = 1,
	}));

	const auto metadata = MetadataFixture();
	ProfileVaultError error = ProfileVaultError::Malformed;
	const auto vault = CreateFixture(metadata, &error);
	check("independent-vault-grants-created",
		vault && error == ProfileVaultError::None);
	if (!vault) {
		return 1;
	}
	const auto serialized = SerializeProfileVault(*vault, &error);
	const auto parsed = ParseProfileVault(serialized, &error);
	check("versioned-vault-round-trip", parsed.has_value()
		&& error == ProfileVaultError::None);
	if (!parsed) {
		return 1;
	}

	const auto admin = OpenProfileVault(
		*parsed,
		Credential(0xFFFFFFFF),
		&error);
	check("admin-password-opens-metadata-and-all-keys",
		std::holds_alternative<AdminVaultAccess>(admin)
		&& std::get<AdminVaultAccess>(admin).accounts.size() == 2
		&& std::get<AdminVaultAccess>(admin).metadata == metadata);

	const auto work = OpenProfileVault(*parsed, Credential(1), &error);
	check("set-password-opens-only-member-keys",
		std::holds_alternative<SetVaultAccess>(work)
		&& std::get<SetVaultAccess>(work).id == SetId{ 1, 1 }
		&& std::get<SetVaultAccess>(work).accounts.size() == 1
		&& std::get<SetVaultAccess>(work).accounts.front().id == AccountId{ 4, 1 });

	const auto empty = OpenProfileVault(*parsed, Credential(3), &error);
	check("empty-set-opens-with-no-account-keys",
		std::holds_alternative<SetVaultAccess>(empty)
		&& std::get<SetVaultAccess>(empty).id == SetId{ 1, 3 }
		&& std::get<SetVaultAccess>(empty).accounts.empty());

	const auto wrong = OpenProfileVault(*parsed, Credential(777), &error);
	check("wrong-password-yields-no-keys",
		std::holds_alternative<WrongPassword>(wrong)
		&& error == ProfileVaultError::WrongPassword);

	auto passwordMetadata = MetadataFixture();
	const auto adminCredential = Derive(
		u"admin passphrase"_q,
		passwordMetadata.verifierSalt,
		passwordMetadata.verifierKdf);
	const auto workCredential = Derive(
		u"work passphrase"_q,
		passwordMetadata.verifierSalt,
		passwordMetadata.verifierKdf);
	const auto sharedCredential = Derive(
		u"shared passphrase"_q,
		passwordMetadata.verifierSalt,
		passwordMetadata.verifierKdf);
	const auto emptyCredential = Derive(
		u"empty passphrase"_q,
		passwordMetadata.verifierSalt,
		passwordMetadata.verifierKdf);
	passwordMetadata.masterVerifier = adminCredential.verifier;
	passwordMetadata.sets[0].verifier = workCredential.verifier;
	passwordMetadata.sets[1].verifier = sharedCredential.verifier;
	passwordMetadata.sets[2].verifier = emptyCredential.verifier;
	const auto passwordAccounts = std::vector<AccountKey>{
		{ .id = { 4, 1 }, .key = QByteArray(kAccountKeySize, 'A') },
		{ .id = { 4, 2 }, .key = QByteArray(kAccountKeySize, 'B') },
	};
	const auto passwordGrants = std::vector<SetGrantCredential>{
		{ .id = { 1, 1 }, .credential = workCredential },
		{ .id = { 1, 2 }, .credential = sharedCredential },
		{ .id = { 1, 3 }, .credential = emptyCredential },
	};
	const auto passwordVault = SealProfileVault(
		passwordMetadata,
		passwordAccounts,
		adminCredential,
		passwordGrants,
		&error);
	const auto actualPasswordAccess = passwordVault
		? OpenProfileVault(
			*passwordVault,
			Derive(
				u"work passphrase"_q,
				passwordMetadata.verifierSalt,
				passwordMetadata.verifierKdf),
			&error)
		: ProfileVaultAccess(WrongPassword());
	const auto actualWrongPasswordAccess = passwordVault
		? OpenProfileVault(
			*passwordVault,
			Derive(
				u"not the password"_q,
				passwordMetadata.verifierSalt,
				passwordMetadata.verifierKdf),
			&error)
		: ProfileVaultAccess(WrongPassword());
	check("password-kdf-routes-to-authorized-grant-only",
		passwordVault
		&& std::holds_alternative<SetVaultAccess>(actualPasswordAccess)
		&& std::get<SetVaultAccess>(actualPasswordAccess).id == SetId{ 1, 1 }
		&& std::get<SetVaultAccess>(actualPasswordAccess).accounts.size() == 1
		&& std::holds_alternative<WrongPassword>(actualWrongPasswordAccess));

	auto tampered = *parsed;
	tampered.grants[0].ciphertext[0] ^= 1;
	const auto tamperedAccess = OpenProfileVault(
		tampered,
		Credential(1),
		&error);
	check("tampered-set-envelope-rejected",
		std::holds_alternative<WrongPassword>(tamperedAccess)
		&& error == ProfileVaultError::AuthenticationFailed);

	auto grafted = *parsed;
	std::swap(grafted.grants[0].nonce, grafted.grants[1].nonce);
	std::swap(grafted.grants[0].ciphertext, grafted.grants[1].ciphertext);
	const auto graftedSet = OpenProfileVault(grafted, Credential(1), &error);
	const auto graftedAdmin = OpenProfileVault(
		grafted,
		Credential(0xFFFFFFFF),
		&error);
	check("cross-set-graft-rejected-for-both-roles",
		std::holds_alternative<WrongPassword>(graftedSet)
		&& std::get<WrongPassword>(graftedSet) == WrongPassword()
		&& std::holds_alternative<WrongPassword>(graftedAdmin)
		&& error == ProfileVaultError::MetadataMismatch);

	auto large = Metadata();
	large.verifierSalt = metadata.verifierSalt;
	large.verifierKdf = metadata.verifierKdf;
	large.masterVerifier = metadata.masterVerifier;
	auto largeGrants = std::vector<SetGrantCredential>();
	largeGrants.reserve(1000);
	for (auto i = quint32(0); i != 1000; ++i) {
		const auto id = SetId{ 9, quint64(i) + 1 };
		large.sets.push_back({
			.id = id,
			.name = u"Set %1"_q.arg(i),
			.verifier = Verifier(i + 1),
			.accounts = {},
		});
		largeGrants.push_back({ id, Credential(i + 1) });
	}
	const auto largeVault = SealProfileVault(
		large,
		{},
		Credential(0xFFFFFFFF),
		largeGrants,
		&error);
	const auto largeSerialized = largeVault
		? SerializeProfileVault(*largeVault, &error)
		: QByteArray();
	check("one-thousand-set-vault-round-trip",
		largeVault
		&& ParseProfileVault(largeSerialized, &error).has_value()
		&& largeVault->grants.size() == 1000);

	auto altered = serialized;
	altered[7] = char(2);
	check("unknown-vault-version-rejected",
		!ParseProfileVault(altered, &error)
		&& error == ProfileVaultError::UnsupportedVersion);

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	return RunChecks();
}
