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

struct Fixture final {
	QByteArray vault;
	QByteArray keyring;
	QByteArray keyringWrappingKey;
	std::vector<AccountVaultLocator> locators;
	Metadata metadata;
};

std::optional<Fixture> MakeFixture() {
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
	const auto shared = Credential(3);
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
			{
				.id = { 1, 3 },
				.name = u"Shared"_q,
				.verifier = shared.verifier,
				.accounts = { accountOne.id, accountTwo.id },
			},
		},
	};
	const auto locators = std::vector<AccountVaultLocator>{
		{ .id = accountOne.id, .value = QByteArray(kAccountVaultLocatorSize, 'X') },
		{ .id = accountTwo.id, .value = QByteArray(kAccountVaultLocatorSize, 'Y') },
	};
	const auto vault = SealProfileVault(
		metadata,
		accounts,
		locators,
		master,
		{
			{ .id = { 1, 1 }, .credential = set },
			{ .id = { 1, 2 }, .credential = empty },
			{ .id = { 1, 3 }, .credential = shared },
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
	return Fixture{
		.vault = vaultBytes,
		.keyring = keyringBytes,
		.keyringWrappingKey = wrappingKey,
		.locators = locators,
		.metadata = metadata,
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
	auto temporary = QTemporaryDir();
	if (!temporary.isValid() || !QDir(temporary.path()).mkdir(u"tdata"_q)) {
		check("temporary-tdata-created", false);
		return 1;
	}
	const auto tdata = QDir(temporary.path()).filePath(u"tdata"_q);
	const auto sidecar = MigrationController::CreateProfileWorkspace(tdata);
	check("temporary-profile-workspace-created", sidecar.has_value());
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
	}));
	auto adapterCalls = std::vector<AccountId>();
	auto closeCalls = std::vector<AccountId>();
	const auto grantedPath = Storage::ScopedAccountPaths(
		sidecar->accountStorageRoot(),
		AccountVaultDataName(fixture->locators[0]));
	const auto adapter = StartProfileAccount(
		[&](const AccountStorageTarget &target, const AccountKey &key)
		-> std::optional<Fn<void()>> {
			adapterCalls.push_back(target.id);
			if (!grantedPath || target.paths.authPath != grantedPath->authPath
				|| target.id != AccountId{ 4, 1 } || key.id != target.id
				|| key.key != QByteArray(kAccountKeySize, 'A')) {
				return std::nullopt;
			}
			return Fn<void()>([&, id = target.id] {
				closeCalls.push_back(id);
			});
		});
	auto error = ProfileGenerationError::None;
	const auto beforeCommit = OpenCommittedProfileGeneration(
		*sidecar,
		Credential(1),
		adapter,
		&error);
	check("uncommitted-sidecar-does-not-start-adapters",
		!beforeCommit && error == ProfileGenerationError::NotCommitted
		&& adapterCalls.empty());
	const auto committed = sidecar->CommitVerified([&](const auto &files) {
		return files.profileVault == fixture->vault
			&& files.accountKeyring == fixture->keyring;
	});
	check("sidecar-committed", committed.has_value());
	if (!committed) {
		return 1;
	}
	auto granted = OpenCommittedProfileGeneration(
		*sidecar,
		Credential(1),
		adapter,
		&error);
	check("set-unlock-starts-only-account-at-granted-locator",
		granted && error == ProfileGenerationError::None
		&& granted->access().role == ProfileGenerationRole::Set
		&& granted->access().setId == SetId{ 1, 1 }
		&& granted->settingsKey().size() == kProfileVaultKeySize
		&& !granted->adminMetadata()
		&& granted->plan().targets().size() == 1
		&& granted->plan().targets().front().id == AccountId{ 4, 1 }
		&& granted->plan().targets().front().dataName
			== AccountVaultDataName(fixture->locators[0])
		&& adapterCalls == std::vector<AccountId>{ { 4, 1 } });
	if (!granted) {
		return 1;
	}
	granted->Close();
	check("generation-close-calls-adapter-cleanup", closeCalls
		== std::vector<AccountId>{ { 4, 1 } } && granted->settingsKey().isEmpty());

	const auto empty = OpenCommittedProfileGeneration(
		*sidecar,
		Credential(2),
		{},
		&error);
	check("empty-set-opens-without-an-adapter-or-administrative-data",
		empty && error == ProfileGenerationError::None
		&& empty->access().role == ProfileGenerationRole::Set
		&& empty->access().setId == SetId{ 1, 2 }
		&& empty->plan().targets().empty()
		&& !empty->adminMetadata());

	auto master = OpenCommittedProfileGeneration(
		*sidecar,
		Credential(0xFFFFFFFF),
		adapter,
		&error);
	check("master-unlock-returns-metadata-without-account-startup",
		master && error == ProfileGenerationError::None
		&& master->access().role == ProfileGenerationRole::Master
		&& !master->access().setId
		&& master->plan().targets().empty()
		&& master->settingsKey().isEmpty()
		&& master->adminMetadata() && *master->adminMetadata() == fixture->metadata
		&& adapterCalls.size() == 1);
	if (!master) {
		return 1;
	}
	master->Close();
	check("master-close-clears-metadata-without-closing-accounts",
		!master->adminMetadata() && closeCalls.size() == 1);

	auto adminKeyRequests = 0;
	const auto wrongAdminKey = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return QByteArray(kAccountKeyringWrappingKeySize, 'Z');
		},
		Credential(0xFFFFFFFF),
		{},
		{},
		{},
		{},
		adapter,
		&error);
	check("master-keyring-mismatch-fails-before-adapter",
		!wrongAdminKey && error == ProfileGenerationError::InvalidKeyring
		&& adapterCalls.size() == 1 && adminKeyRequests == 1);

	const auto ignoredLegacyRoot = QDir(temporary.path()).filePath(u"other"_q);
	const auto scoped = OpenCommittedProfileGeneration(
		*sidecar,
		[&]() -> std::optional<QByteArray> {
			++adminKeyRequests;
			return fixture->keyringWrappingKey;
		},
		Credential(1),
		{},
		{},
		{ { .id = { 4, 1 }, .dataName = u"untrusted"_q } },
		ignoredLegacyRoot,
		adapter,
		&error);
	check("scoped-startup-does-not-consume-legacy-mappings-or-admin-key",
		scoped && error == ProfileGenerationError::None && adminKeyRequests == 1
		&& !QFileInfo::exists(ignoredLegacyRoot) && adapterCalls.size() == 2);
	const auto rejectedPassword = OpenCommittedProfileGeneration(
		*sidecar,
		Credential(999),
		adapter,
		&error);
	check("wrong-password-never-starts-account",
		!rejectedPassword && error == ProfileGenerationError::WrongPassword
		&& adapterCalls.size() == 2);

	auto startOrder = std::vector<AccountId>();
	auto partialCloseOrder = std::vector<AccountId>();
	const auto partialFailure = OpenCommittedProfileGeneration(
		*sidecar,
		Credential(3),
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
		&error);
	check("partial-adapter-failure-rolls-back-started-accounts",
		!partialFailure && error == ProfileGenerationError::StartFailed
		&& startOrder == std::vector<AccountId>{ { 4, 1 }, { 4, 2 } }
		&& partialCloseOrder == std::vector<AccountId>{ { 4, 1 } });

	auto corrupt = AuthenticateCommittedProfileGeneration(
		*sidecar, {}, Credential(3), {}, {}, {}, {}, committed->transactionId);
	auto validated = std::vector<AccountId>();
	check("offline-validation-checks-every-account-before-any-start",
		corrupt && !corrupt->Start(
			*sidecar,
			[&](const AccountStorageTarget &target, const AccountKey &) {
				validated.push_back(target.id);
				return target.id != AccountId{ 4, 2 };
			},
			adapter,
			&error)
		&& error == ProfileGenerationError::ValidationFailed
		&& adapterCalls.size() == 2
		&& validated == std::vector<AccountId>{ { 4, 1 }, { 4, 2 } });

	const auto authenticate = [&](const QByteArray &transactionId) {
		return AuthenticateCommittedProfileGeneration(
			*sidecar, {}, Credential(1), {}, {}, {}, {}, transactionId, &error);
	};
	auto firstRoute = authenticate(committed->transactionId);
	auto pendingRoute = authenticate(committed->transactionId);
	check("authentication-prepares-grants-without-starting-accounts",
		firstRoute && pendingRoute && adapterCalls.size() == 2);
	check("authenticated-route-starts-once",
		firstRoute && firstRoute->Start(*sidecar, adapter, &error)
		&& adapterCalls.size() == 3
		&& !firstRoute->Start(*sidecar, adapter, &error)
		&& error == ProfileGenerationError::InvalidPlan
		&& adapterCalls.size() == 3);
	if (firstRoute) {
		firstRoute->Close();
	}
	const auto replacement = sidecar->ReplaceCommitted(
		committed->transactionId,
		{
			{ MigrationArtifact::ProfileVault, fixture->vault },
			{ MigrationArtifact::AccountKeyring, fixture->keyring },
		},
		[&](const auto &files) {
			return files.profileVault == fixture->vault
				&& files.accountKeyring == fixture->keyring;
		});
	check("credential-derived-for-old-generation-is-rejected",
		replacement && !authenticate(committed->transactionId)
		&& error == ProfileGenerationError::StaleGeneration);
	check("prepared-grants-cannot-start-after-generation-replacement",
		replacement && pendingRoute
		&& !pendingRoute->Start(*sidecar, adapter, &error)
		&& error == ProfileGenerationError::StaleGeneration
		&& pendingRoute->plan().targets().empty()
		&& adapterCalls.size() == 3);
	if (!replacement) {
		return 1;
	}
	auto modified = fixture->metadata;
	modified.sets[0].name = u"Renamed"_q;
	modified.sets[0].verifier = Credential(4).verifier;
	const auto replacements = std::vector<SetGrantCredential>{
		{ modified.sets[0].id, Credential(4) },
	};
	check("settings-write-rejects-non-master-password",
		!CommitProfileSetChanges(
			*sidecar, replacement->transactionId, Credential(1),
			modified, replacements, &error)
		&& error == ProfileGenerationError::WrongPassword);
	const auto changed = CommitProfileSetChanges(
		*sidecar, replacement->transactionId, Credential(0xFFFFFFFF),
		modified, replacements, &error);
	check("master-settings-write-replaces-the-active-generation",
		changed && *changed != replacement->transactionId
		&& error == ProfileGenerationError::None
		&& !CommitProfileSetChanges(
			*sidecar, replacement->transactionId, Credential(0xFFFFFFFF),
			modified, replacements, &error)
		&& error == ProfileGenerationError::StaleGeneration);
	if (changed) {
		const auto fresh = sidecar->LoadCommitted();
		const auto master = OpenCommittedProfileGeneration(
			*sidecar, Credential(0xFFFFFFFF), {}, &error);
		const auto oldPassword = OpenCommittedProfileGeneration(
			*sidecar, Credential(1), adapter, &error);
		const auto newPassword = OpenCommittedProfileGeneration(
			*sidecar, Credential(4), adapter, &error);
		check("updated-settings-open-with-same-accounts-and-replaced-password",
			fresh && fresh->transactionId == *changed
			&& fresh->accountKeyring == fixture->keyring
			&& master && master->adminMetadata()
			&& *master->adminMetadata() == modified
			&& !oldPassword && newPassword && adapterCalls.size() == 4);
	}
	std::printf("%d/%d checks passed\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);
	return RunChecks();
}
