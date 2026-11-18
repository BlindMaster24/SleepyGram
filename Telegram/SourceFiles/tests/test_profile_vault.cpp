/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_vault.h"
#include "base/basic_types.h"

#include <QtCore/QCoreApplication>

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

std::vector<AccountVaultLocator> LocatorsFixture() {
	return {
		{ .id = { 4, 1 }, .value = QByteArray(kAccountVaultLocatorSize, 'X') },
		{ .id = { 4, 2 }, .value = QByteArray(kAccountVaultLocatorSize, 'Y') },
	};
}

DerivedCredential DeriveFixtureCredential(char marker) {
	return details::ProfileVaultCredentialFromKdfOutput(QByteArray(256, marker));
}

std::optional<ProfileVault> CreateFixture(
		Metadata metadata,
		ProfileVaultError *error,
		std::vector<AccountVaultLocator> locators = LocatorsFixture()) {
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
		locators,
		Credential(0xFFFFFFFF),
		grants,
		error);
}

QByteArray LegacyVaultFixture() {
	// v1, with deterministic synthetic data and independent verifier and key.
	return QByteArray::fromBase64(
		"U1BHVgAAAAF2dnZ2dnZ2dnZ2dnZ2dnZ2AAAAEHNzc3Nzc3Nzc3Nzc3Nzc3MAAAACAABAAAAA"
		"AAEAAAAB/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQEBAQAAAIw"
		"pqW28L2BpgisHrXnbDZ3ZTeTLzCNucRw+/QfWlzRurV9TIkb+aBfA2nGFyNKdb4sauM3hWof"
		"CHzNqaPI/nX6UG8fTre3Mhitoa76+gcNQ7UPmHFemjp1uCw3epOHEoFamFrrHETZJUAx3IMS"
		"S+C+8/tjrBppy7ooqckqPn9B/zNTdhnHI/o3q9Fxio3nTwKzoHTHcJhMLOjhwfAwkAS96VqG"
		"rHh3p90Un686rq4QRXLqLa0b9o6oLgxEh5Nj+ME5FWO5q10UKbiMnVW0S0FqoPqvdWMK3Tv8"
		"MO7huVivPVVgRhkVHdp9hRAlcR6S09CwQWpJOORQLAtT23Wi7i9wH+ohCvHZEcSpyrQMZ8hB"
		"/wMkCYdJMZfhyomZVI47BGHBv1GxL9OYNIg44+GOoH6h/B8/TkccjY2SHzTpbclwv71GN/KG"
		"a9u1G+GERG7pmUqn1ExxvEPw4f9GHE25ZQ+MODr6hOXHFRIYr6zJAO27FhBcC3oEJm6j5ZNo"
		"sf5SCt0XdkRTcViw12INzfIL0f5iNSdpas57y3B3a9gfNlQdLrKeNJ7Li4YD4nKnHH0YCjMq"
		"o5FxociDbMQd6jI/TPNbTZPEV32aF4bbetUeChsYLjcFyIaylmWFb1ta1LI43tOzmgCnl7RB"
		"EHSj9IrdQS5gUwjOCKRJQMbSrJmcp6Q/R5zpa8Ud+hZT7DqHBp82Ucia/FOW3GSWlyNwy/GU"
		"lJksEcQVamBj/hdkye4O8GOQjZEAAAABAAAAAAAAAAEAAAAAAAAAAQEAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAgICAgICAgICAgICAAAAhL21d7LwKOCy9PjmX9dv5H7O7uqH"
		"OsoZaPW+MN5BAAebUpDmw7p3Fdx3qY6vEHPKLvVOGBigCLanY6zPybeSxmTo+3Qhk45MHrcy"
		"4aVqtd7bnPqZJimeLkVozbLCrLqCfvNHa5QBS9dH11HBOYlSosb81Pwdh3VilHUEqZ0x/fp8"
		"3WDvQQ==");
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
		&& parsed->version == kProfileVaultVersion
		&& error == ProfileVaultError::None);
	if (!parsed) {
		return 1;
	}

	const auto admin = OpenProfileVault(
		*parsed,
		Credential(0xFFFFFFFF),
		&error);
	const auto locators = LocatorsFixture();
	check("admin-password-opens-metadata-all-keys-and-locators",
		std::holds_alternative<AdminVaultAccess>(admin)
		&& std::get<AdminVaultAccess>(admin).accounts.size() == 2
		&& std::get<AdminVaultAccess>(admin).locators == locators
		&& std::get<AdminVaultAccess>(admin).metadata == metadata);

	const auto work = OpenProfileVault(*parsed, Credential(1), &error);
	check("set-password-opens-only-member-keys-and-locators",
		std::holds_alternative<SetVaultAccess>(work)
		&& std::get<SetVaultAccess>(work).id == SetId{ 1, 1 }
		&& std::get<SetVaultAccess>(work).accounts.size() == 1
		&& std::get<SetVaultAccess>(work).locators
			== std::vector<AccountVaultLocator>{ locators.front() }
		&& std::get<SetVaultAccess>(work).accounts.front().id == AccountId{ 4, 1 });

	const auto empty = OpenProfileVault(*parsed, Credential(3), &error);
	check("empty-set-opens-with-no-account-keys",
		std::holds_alternative<SetVaultAccess>(empty)
		&& std::get<SetVaultAccess>(empty).id == SetId{ 1, 3 }
		&& std::get<SetVaultAccess>(empty).accounts.empty()
		&& std::get<SetVaultAccess>(empty).locators.empty());
	const auto other = OpenProfileVault(*parsed, Credential(2), &error);
	const auto workAccess = std::get_if<SetVaultAccess>(&work);
	const auto otherAccess = std::get_if<SetVaultAccess>(&other);
	const auto emptyAccess = std::get_if<SetVaultAccess>(&empty);
	check("settings-keys-are-scoped-even-with-overlapping-accounts",
		workAccess && otherAccess && emptyAccess
		&& workAccess->settingsKey.size() == kProfileVaultKeySize
		&& otherAccess->settingsKey.size() == kProfileVaultKeySize
		&& emptyAccess->settingsKey.size() == kProfileVaultKeySize
		&& workAccess->settingsKey != otherAccess->settingsKey
		&& workAccess->settingsKey != emptyAccess->settingsKey);

	const auto wrong = OpenProfileVault(*parsed, Credential(777), &error);
	check("wrong-password-yields-no-keys",
		std::holds_alternative<WrongPassword>(wrong)
		&& error == ProfileVaultError::WrongPassword);

	auto duplicateLocators = LocatorsFixture();
	duplicateLocators[0].value = duplicateLocators[1].value;
	check("seal-rejects-duplicate-or-mismatched-locators",
		!CreateFixture(metadata, &error, duplicateLocators)
		&& !CreateFixture(metadata, &error, { locators.front() })
		&& error == ProfileVaultError::MetadataMismatch);

	auto updatedMetadata = metadata;
	updatedMetadata.sets[0].name = u"Updated"_q;
	updatedMetadata.sets[0].accounts = { { 4, 2 } };
	const auto membership = UpdateProfileVault(
		*parsed,
		Credential(0xFFFFFFFF),
		updatedMetadata,
		{},
		&error);
	const auto movedGrant = membership
		? OpenProfileVault(*membership, Credential(1), &error)
		: ProfileVaultAccess(WrongPassword());
	const auto moved = std::get_if<SetVaultAccess>(&movedGrant);
	check("master-updates-membership-without-set-passwords",
		membership
		&& membership->id == parsed->id
		&& membership->grants[0] != parsed->grants[0]
		&& membership->grants[1] == parsed->grants[1]
		&& membership->grants[2] == parsed->grants[2]
		&& moved && moved->accounts.size() == 1
		&& moved->accounts.front().id == locators.back().id
		&& moved->locators == std::vector<AccountVaultLocator>{ locators.back() });
	if (!membership) {
		return 1;
	}

	updatedMetadata.sets[0].verifier = Verifier(5);
	updatedMetadata.sets.pop_back();
	updatedMetadata.sets.push_back({
		.id = { 1, 4 },
		.name = u"New"_q,
		.verifier = Verifier(6),
		.accounts = { { 4, 1 } },
	});
	const auto updated = UpdateProfileVault(
		*membership,
		Credential(0xFFFFFFFF),
		updatedMetadata,
		{
			{ .id = { 1, 1 }, .credential = Credential(5) },
			{ .id = { 1, 4 }, .credential = Credential(6) },
		},
		&error);
	const auto updatedBytes = updated
		? SerializeProfileVault(*updated, &error)
		: QByteArray();
	const auto updatedReadback = ParseProfileVault(updatedBytes, &error);
	if (!updatedReadback) {
		check("updated-vault-round-trip", false);
		return 1;
	}
	const auto rotatedGrant = OpenProfileVault(*updatedReadback, Credential(5));
	const auto newGrant = OpenProfileVault(*updatedReadback, Credential(6));
	const auto rotated = std::get_if<SetVaultAccess>(&rotatedGrant);
	const auto added = std::get_if<SetVaultAccess>(&newGrant);
	check("master-resets-adds-and-removes-grants-with-stable-identity",
		updatedReadback->id == parsed->id
		&& updatedReadback->grants[1] == parsed->grants[1]
		&& rotated && moved && rotated->accounts == moved->accounts
		&& rotated->locators == moved->locators
		&& added && added->locators
			== std::vector<AccountVaultLocator>{ locators.front() }
		&& std::holds_alternative<WrongPassword>(
			OpenProfileVault(*updatedReadback, Credential(1)))
		&& std::holds_alternative<WrongPassword>(
			OpenProfileVault(*updatedReadback, Credential(3))));
	check("settings-key-survives-password-and-membership-changes",
		rotated && moved && workAccess
		&& rotated->settingsKey == workAccess->settingsKey
		&& moved->settingsKey == workAccess->settingsKey);
	check("set-password-cannot-authorize-a-vault-update",
		!UpdateProfileVault(*parsed, Credential(1), metadata, {}, &error)
		&& error == ProfileVaultError::WrongPassword);
	const auto pruned = PruneProfileVaultAccounts(
		*parsed, Credential(0xFFFFFFFF), { { 4, 1 } }, &error);
	if (!pruned) {
		check("account-pruning-created-successor", false);
		return 1;
	}
	const auto prunedAdmin = OpenProfileVault(*pruned, Credential(0xFFFFFFFF));
	const auto prunedFirst = OpenProfileVault(*pruned, Credential(1));
	const auto prunedShared = OpenProfileVault(*pruned, Credential(2));
	const auto prunedAdminAccess = std::get_if<AdminVaultAccess>(&prunedAdmin);
	const auto prunedFirstAccess = std::get_if<SetVaultAccess>(&prunedFirst);
	const auto prunedSharedAccess = std::get_if<SetVaultAccess>(&prunedShared);
	check("account-pruning-removes-keys-from-master-and-overlapping-grants",
		prunedAdminAccess && prunedAdminAccess->accounts.size() == 1
		&& prunedAdminAccess->locators
			== std::vector<AccountVaultLocator>{ locators.back() }
		&& prunedAdminAccess->metadata.sets[0].accounts.empty()
		&& prunedFirstAccess && prunedFirstAccess->accounts.empty()
		&& prunedSharedAccess && prunedSharedAccess->accounts.size() == 1
		&& prunedSharedAccess->locators
			== std::vector<AccountVaultLocator>{ locators.back() }
		&& pruned->grants[2] == parsed->grants[2]);
	check("account-pruning-rejects-unauthorized-or-unknown-targets",
		!PruneProfileVaultAccounts(*parsed, Credential(1), { { 4, 1 } }, &error)
		&& error == ProfileVaultError::WrongPassword
		&& !PruneProfileVaultAccounts(
			*parsed, Credential(0xFFFFFFFF), { { 4, 7 } }, &error)
		&& error == ProfileVaultError::InvalidAccountRemoval);
	check("changed-passcode-requires-matching-replacement-credential",
		!UpdateProfileVault(
			*membership,
			Credential(0xFFFFFFFF),
			updatedMetadata,
			{},
			&error)
		&& error == ProfileVaultError::MetadataMismatch);

	auto passwordMetadata = MetadataFixture();
	const auto adminCredential = DeriveFixtureCredential('A');
	const auto workCredential = DeriveFixtureCredential('W');
	const auto sharedCredential = DeriveFixtureCredential('S');
	const auto emptyCredential = DeriveFixtureCredential('E');
	check("public-verifier-is-distinct-from-private-credential-key",
		adminCredential.valid() && adminCredential.verifier != adminCredential.key
		&& workCredential.valid() && workCredential.verifier != workCredential.key);
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
			DeriveFixtureCredential('W'),
			&error)
		: ProfileVaultAccess(WrongPassword());
	const auto actualWrongPasswordAccess = passwordVault
		? OpenProfileVault(
			*passwordVault,
			DeriveFixtureCredential('N'),
			&error)
		: ProfileVaultAccess(WrongPassword());
	check("credential-derived-from-kdf-output-routes-only-to-its-grant",
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

	auto foreign = CreateFixture(metadata, &error);
	if (foreign) {
		foreign->grants[0] = parsed->grants[0];
	}
	check("same-credentials-do-not-transfer-grants-between-vaults",
		foreign && foreign->id != parsed->id
		&& std::holds_alternative<WrongPassword>(
			OpenProfileVault(*foreign, Credential(1), &error))
		&& error == ProfileVaultError::AuthenticationFailed);

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

	const auto legacyBytes = LegacyVaultFixture();
	const auto legacy = ParseProfileVault(legacyBytes, &error);
	const auto legacyAdmin = legacy
		? OpenProfileVault(*legacy, Credential(0xFFFFFFFF), &error)
		: ProfileVaultAccess(WrongPassword());
	const auto legacyGrant = legacy
		? OpenProfileVault(*legacy, Credential(1), &error)
		: ProfileVaultAccess(WrongPassword());
	const auto legacySet = std::get_if<SetVaultAccess>(&legacyGrant);
	check("legacy-vault-fixture-remains-readable-with-no-locators",
		legacy && legacy->version == kLegacyProfileVaultVersion
		&& std::holds_alternative<AdminVaultAccess>(legacyAdmin)
		&& legacySet && legacySet->accounts.size() == 1
		&& legacySet->accounts.front().id == AccountId{ 4, 1 }
		&& legacySet->locators.empty());
	check("legacy-vault-fixture-rejects-in-place-update",
		legacy && !UpdateProfileVault(
			*legacy,
			Credential(0xFFFFFFFF),
			metadata,
			{},
			&error)
		&& error == ProfileVaultError::UnsupportedVersion);

	auto altered = serialized;
	altered[7] = char(3);
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
