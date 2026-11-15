/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_generation.h"

#include "base/basic_types.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <cstdio>
#include <vector>

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

VerifiedRegistryIdentity Identity(quint64 value) {
	auto bytes = QByteArray(8, Qt::Uninitialized);
	for (auto i = 0; i != 8; ++i) {
		bytes[i] = char(value >> ((7 - i) * 8));
	}
	return { .kind = RegistryIdentityKind::ServerUserId, .value = bytes };
}

struct Fixture final {
	QByteArray vault;
	QByteArray keyring;
	QByteArray keyringWrappingKey;
	QByteArray environmentId;
	AccountRegistry registry;
	std::vector<ProfileGenerationAccountBinding> mappings;
};

std::optional<Fixture> MakeFixture() {
	const auto environmentId = QByteArray(16, 'E');
	const auto accountOne = AccountKey{
		.id = { 4, 1 },
		.key = QByteArray(kAccountKeySize, 'A'),
	};
	const auto accountTwo = AccountKey{
		.id = { 4, 2 },
		.key = QByteArray(kAccountKeySize, 'B'),
	};
	const auto accounts = std::vector<AccountKey>{ accountOne, accountTwo };
	const auto master = Credential(0xFFFFFFFF);
	const auto set = Credential(1);
	const auto empty = Credential(2);
	const auto metadata = Metadata{
		.verifierSalt = QByteArray(kVerifierSaltSize, 'S'),
		.verifierKdf = {
			.kind = 2,
			.memory = 16'384,
			.time = 1,
			.parallel = 1,
		},
		.masterVerifier = master.verifier,
		.sets = {
			{
				.id = { 1, 1 },
				.name = u"Granted"_q,
				.verifier = set.verifier,
				.accounts = { accountOne.id },
			},
			{
				.id = { 1, 2 },
				.name = u"Empty"_q,
				.verifier = empty.verifier,
			},
		},
	};
	const auto vault = SealProfileVault(
		metadata,
		accounts,
		master,
		{
			{ .id = { 1, 1 }, .credential = set },
			{ .id = { 1, 2 }, .credential = empty },
		});
	if (!vault) {
		return std::nullopt;
	}
	ProfileVaultError vaultError = ProfileVaultError::None;
	const auto vaultBytes = SerializeProfileVault(*vault, &vaultError);
	const auto wrappingKey = QByteArray(kAccountKeyringWrappingKeySize, 'W');
	KeyringError keyringError = KeyringError::None;
	const auto keyringBytes = SealAccountKeyring(
		accounts,
		wrappingKey,
		&keyringError);
	if (vaultBytes.isEmpty() || keyringBytes.isEmpty()) {
		return std::nullopt;
	}
	const auto identityOne = Identity(101);
	const auto identityTwo = Identity(202);
	auto registry = NewAccountRegistry(environmentId);
	if (!registry) {
		return std::nullopt;
	}
	registry->entries = {
		{
			.id = accountOne.id,
			.legacyDataNameHash = AccountRegistryDataNameHash(u"profile_one"_q),
			.slot = 0,
			.identityFingerprints = { RegistryIdentityFingerprint(identityOne) },
			.retired = false,
		},
		{
			.id = accountTwo.id,
			.legacyDataNameHash = AccountRegistryDataNameHash(u"profile_two"_q),
			.slot = 1,
			.identityFingerprints = { RegistryIdentityFingerprint(identityTwo) },
			.retired = false,
		},
	};
	return Fixture{
		.vault = vaultBytes,
		.keyring = keyringBytes,
		.keyringWrappingKey = wrappingKey,
		.environmentId = environmentId,
		.registry = std::move(*registry),
		.mappings = {
			{
				.id = accountOne.id,
				.dataName = u"profile_one"_q,
				.slot = 0,
				.identities = { identityOne },
			},
			{
				.id = accountTwo.id,
				.dataName = u"profile_two"_q,
				.slot = 1,
				.identities = { identityTwo },
			},
		},
	};
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
	const auto fixture = MakeFixture();
	check("encrypted-fixture-created", fixture.has_value());
	if (!fixture) {
		return 1;
	}
	auto temporary = QTemporaryDir(
		QDir::tempPath() + u"/sleepygram-migration-fixture-XXXXXX"_q);
	if (!temporary.isValid() || !QDir().rmdir(temporary.path())) {
		check("isolated-fixture-workspace-created", false);
		return 1;
	}
	MigrationError migrationError = MigrationError::None;
	auto sidecar = MigrationController::CreateIsolatedFixtureWorkspace(
		temporary.path(),
		&migrationError);
	check("isolated-fixture-workspace-created", sidecar.has_value());
	if (!sidecar) {
		return 1;
	}
	check("stage-written-before-commit", sidecar->Stage({
		{
			.artifact = MigrationArtifact::ProfileVault,
			.encryptedBytes = fixture->vault,
		},
		{
			.artifact = MigrationArtifact::AccountKeyring,
			.encryptedBytes = fixture->keyring,
		},
	}, &migrationError));
	const auto globalTdataPath = temporary.path()
		+ u"-unused-profile-root/tdata"_q;
	auto adapterCalls = std::vector<AccountId>();
	auto closeCalls = std::vector<AccountId>();
	auto adminKeyRequests = 0;
	auto adapter = StartProfileAccount(
		[&](const AccountStorageTarget &target, const AccountKey &key)
		-> std::optional<Fn<void()>> {
			adapterCalls.push_back(target.id);
			if (target.id == AccountId{ 4, 1 }
				&& key.key != QByteArray(kAccountKeySize, 'A')) {
				return std::nullopt;
			}
			return Fn<void()>([&, id = target.id] {
				closeCalls.push_back(id);
			});
		});
	ProfileGenerationError generationError = ProfileGenerationError::None;
	auto beforeCommit = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return fixture->keyringWrappingKey;
		},
		Credential(1),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		adapter,
		&generationError);
	check("uncommitted-sidecar-does-not-start-adapters",
		!beforeCommit
		&& generationError == ProfileGenerationError::NotCommitted
		&& adapterCalls.empty()
		&& adminKeyRequests == 0
		&& !QFileInfo::exists(globalTdataPath));
	const auto committed = sidecar->Commit(&migrationError);
	check("sidecar-committed", committed.has_value());
	if (!committed) {
		return 1;
	}
	auto granted = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return fixture->keyringWrappingKey;
		},
		Credential(1),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		adapter,
		&generationError);
	check("set-unlock-starts-only-granted-account",
		granted
		&& generationError == ProfileGenerationError::None
		&& granted->access().role == ProfileGenerationRole::Set
		&& granted->access().setId == SetId{ 1, 1 }
		&& granted->plan().targets().size() == 1
		&& granted->plan().targets().front().id == AccountId{ 4, 1 }
		&& adapterCalls == std::vector<AccountId>{ { 4, 1 } }
		&& adminKeyRequests == 0
		&& !QFileInfo::exists(globalTdataPath));
	if (!granted) {
		return 1;
	}
	granted->Close();
	check("generation-close-calls-adapter-cleanup", closeCalls
		== std::vector<AccountId>{ { 4, 1 } });
	auto emptyCalls = 0;
	auto empty = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return fixture->keyringWrappingKey;
		},
		Credential(2),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		[&](const AccountStorageTarget&, const AccountKey&)
		-> std::optional<Fn<void()>> {
			++emptyCalls;
			return Fn<void()>([] {});
		},
		&generationError);
	check("empty-set-opens-without-adapter-or-admin-keyring",
		empty && empty->access().role == ProfileGenerationRole::Set
		&& empty->access().setId == SetId{ 1, 2 }
		&& empty->plan().targets().empty()
		&& emptyCalls == 0
		&& adminKeyRequests == 0);
	auto adminStarted = std::vector<AccountId>();
	auto adminClosed = std::vector<AccountId>();
	auto master = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return fixture->keyringWrappingKey;
		},
		Credential(0xFFFFFFFF),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		[&](const AccountStorageTarget &target, const AccountKey&)
		-> std::optional<Fn<void()>> {
			adminStarted.push_back(target.id);
			return Fn<void()>([&, id = target.id] {
				adminClosed.push_back(id);
			});
		},
		&generationError);
	check("master-unlock-verifies-sidecar-keyring-and-starts-all",
		master
		&& master->access().role == ProfileGenerationRole::Master
		&& master->plan().targets().size() == 2
		&& adminKeyRequests == 1
		&& adminStarted == std::vector<AccountId>{ { 4, 1 }, { 4, 2 } });
	if (!master) {
		return 1;
	}
	master->Close();
	check("master-close-rolls-back-in-reverse-order", adminClosed
		== std::vector<AccountId>{ { 4, 2 }, { 4, 1 } });
	auto wrongKeyringCalls = 0;
	auto wrongAdminKey = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return QByteArray(kAccountKeyringWrappingKeySize, 'X');
		},
		Credential(0xFFFFFFFF),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		[&](const AccountStorageTarget&, const AccountKey&)
		-> std::optional<Fn<void()>> {
			++wrongKeyringCalls;
			return Fn<void()>([] {});
		},
		&generationError);
	check("master-keyring-mismatch-fails-before-adapter",
		!wrongAdminKey
		&& generationError == ProfileGenerationError::InvalidKeyring
		&& wrongKeyringCalls == 0
		&& adminKeyRequests == 2);
	auto wrongPasswordCalls = 0;
	auto rejectedPassword = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return fixture->keyringWrappingKey;
		},
		Credential(999),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		[&](const AccountStorageTarget&, const AccountKey&)
		-> std::optional<Fn<void()>> {
			++wrongPasswordCalls;
			return Fn<void()>([] {});
		},
		&generationError);
	check("wrong-password-never-requests-admin-key-or-starts-account",
		!rejectedPassword
		&& generationError == ProfileGenerationError::WrongPassword
		&& wrongPasswordCalls == 0
		&& adminKeyRequests == 2);
	auto mappingCalls = 0;
	auto invalidMappings = fixture->mappings;
	invalidMappings[0].dataName = u"other_account"_q;
	auto badMapping = OpenCommittedProfileGeneration(
		*sidecar,
		{},
		Credential(1),
		fixture->registry,
		fixture->environmentId,
		invalidMappings,
		globalTdataPath,
		[&](const AccountStorageTarget&, const AccountKey&)
		-> std::optional<Fn<void()>> {
			++mappingCalls;
			return Fn<void()>([] {});
		},
		&generationError);
	check("legacy-mapping-mismatch-fails-before-adapter",
		!badMapping
		&& generationError == ProfileGenerationError::InvalidMappings
		&& mappingCalls == 0);
	auto startOrder = std::vector<AccountId>();
	auto partialCloseOrder = std::vector<AccountId>();
	auto partialFailure = OpenCommittedProfileGeneration(
		*sidecar,
		{},
		Credential(0xFFFFFFFF),
		fixture->registry,
		fixture->environmentId,
		fixture->mappings,
		globalTdataPath,
		[&](const AccountStorageTarget &target, const AccountKey &)
		-> std::optional<Fn<void()>> {
			startOrder.push_back(target.id);
			if (target.id == AccountId{ 4, 2 }) {
				return std::nullopt;
			}
			return Fn<void()>([&, id = target.id] {
				partialCloseOrder.push_back(id);
			});
		},
		&generationError);
	check("partial-adapter-failure-rolls-back-started-accounts",
		!partialFailure
		&& generationError == ProfileGenerationError::StartFailed
		&& startOrder == std::vector<AccountId>{ { 4, 1 }, { 4, 2 } }
		&& partialCloseOrder == std::vector<AccountId>{ { 4, 1 } });
	std::printf("%d/%d checks passed\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);
	return RunChecks();
}
