// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_emergency.h"

#include "ayu/features/emergency_actions/emergency_recovery_record.h"
#include "ayu/features/emergency_actions/mtproto_session_effect_transport.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_emergency_bundle.h"
#include "ayu/features/profile_sets/profile_installation_removal.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_admission.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_bundle.h"
#include "storage/details/storage_native_path.h"
#include "storage/storage_account.h"

#ifdef Q_OS_MAC
#include <QtCore/QOperatingSystemVersion>
#include <openssl/crypto.h>
#endif // Q_OS_MAC

#include <QtCore/QFileInfo>
#include <QtCore/QtEndian>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;
using Error = ProfileGenerationError;

auto BytesOf(const QByteArray &data) {
	return std::span<const uint8_t>{
		reinterpret_cast<const uint8_t*>(data.constData()), size_t(data.size()) };
}

auto ByteArrayOf(std::span<const uint8_t> bytes) {
	return QByteArray(reinterpret_cast<const char*>(bytes.data()), qsizetype(bytes.size()));
}

QByteArray TransactionId(std::string_view hex) {
	return QByteArray::fromHex(QByteArray(hex.data(), qsizetype(hex.size())));
}

template <typename Id>
Id StorageId(std::string_view value) {
	const auto bytes = TransactionId(value);
	return (bytes.size() == 16 && bytes.toHex().toStdString() == value)
		? Id{ qFromBigEndian<quint64>(bytes.constData()), qFromBigEndian<quint64>(bytes.constData() + 8) }
		: Id();
}

std::filesystem::path NativePath(const QString &path) {
	return Storage::NativeFilePath(QFileInfo(path).filePath());
}

std::filesystem::path DataRoot(const MigrationController &workspace) {
	return NativePath(QFileInfo(workspace.workspacePath()).path());
}

#ifdef Q_OS_MAC
std::optional<EA::ScopedWebviewStoreIds> ReadNamedWebviewStores(
		const MigrationController &workspace,
		const AccountKey &key,
		QString locator,
		uint64_t userId) {
	const auto paths = Storage::ScopedAccountPaths(workspace.accountStorageRoot(),
		locator);
	const auto localKey = paths ? ProfileAccountStorageKey(key) : nullptr;
	const auto read = localKey ? Storage::ReadScopedWebviewTokens(*paths, localKey, UserId(userId)) : std::nullopt;
	if (!read) {
		return std::nullopt;
	}
	auto result = EA::ScopedWebviewStoreIds();
	result.reserve(read->size());
	for (const auto &value : *read) {
		auto token = EA::ScopedWebviewStoreId();
		if (size_t(value.size()) != token.size()) {
			return std::nullopt;
		}
		std::ranges::copy(BytesOf(value), token.begin());
		result.push_back(token);
	}
	return result;
}

std::optional<EA::ScopedWebviewStoreIds> ReadNamedWebviewStores(
		const MigrationController &workspace,
		const EA::EmergencyExecutionAccount &account) {
	const auto id = StorageId<AccountId>(account.accountId.value);
	if (!id || !account.remoteIdentity) {
		return std::nullopt;
	}
	auto key = AccountKey{ id, ByteArrayOf(account.scopedKey) };
	const auto wipe = gsl::finally([&] {
		OPENSSL_cleanse(key.key.data(), size_t(key.key.size()));
	});
	return ReadNamedWebviewStores(workspace, key, QString::fromStdString(account.locator),
		account.remoteIdentity->userId);
}
#endif // Q_OS_MAC

bool VerifyRecoveryReceipt(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt) {
	if (!record.hasNamedWebviewProof) {
		return true;
	}
#ifdef Q_OS_MAC
	return EA::VerifyMacScopedWebviewRecoveryReceipt(record.journal.installationId,
		record.journal.operationId, record.admissionGeneration, DataRoot(workspace), BytesOf(receipt));
#else
	return false;
#endif // Q_OS_MAC
}

std::vector<MigrationInput> BaseArtifacts(const CommittedMigration &current) {
	return {
		{ MigrationArtifact::ProfileVault, current.profileVault },
		{ MigrationArtifact::AccountKeyring, current.accountKeyring },
	};
}

std::optional<EA::EmergencyRecoveryRecord> OpenRecovery(const CommittedMigration &current) {
	const auto vault = ParseProfileVault(current.profileVault);
	return vault ? EA::DecodeEmergencyRecoveryRecord(BytesOf(current.emergencyRecovery),
		EA::InstallationId(vault->id.toHex().toStdString()), current.transactionId.toHex().toStdString())
		: std::nullopt;
}

bool CheckSuccessor(const ProfileVault &original, const QByteArray &candidate) {
	const auto vault = ParseProfileVault(candidate);
	return vault && vault->version == kProfileVaultVersion && vault->id == original.id
		&& vault->salt == original.salt && vault->kdf == original.kdf
		&& vault->adminVerifier == original.adminVerifier;
}

class Clock final : public EA::CoordinatorClock {
public:
	TimePoint now() const override { return std::chrono::steady_clock::now(); }
};

class LocalReset final : public EA::LocalAccountEffect {
public:
	LocalReset(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt);
	EA::EffectResult clear(const EA::AccountId &account) override;
	[[nodiscard]] bool confirmLocalCleanup();
	[[nodiscard]] std::optional<QByteArray> finish();

private:
	[[nodiscard]] bool retireGrants();

	const MigrationController &_workspace;
	const EA::EmergencyRecoveryRecord &_record;
	const QByteArray &_receipt;
	EA::ScopedAccountClear _clear;
	bool _retired = false;
};

LocalReset::LocalReset(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt)
: _workspace(workspace)
, _record(record)
, _receipt(receipt)
, _clear(record.journal.installationId, DataRoot(workspace), {
	.installationId = record.journal.installationId,
	.accountStorageRoot = NativePath(workspace.accountStorageRoot()),
	.accounts = record.accounts,
}
#ifdef Q_OS_MAC
, record.hasNamedWebviewProof ? EA::ClearScopedWebviewStores(EA::ClearMacScopedWebviewStores)
	: EA::ClearScopedWebviewStores()
#endif // Q_OS_MAC
) {
}

bool LocalReset::retireGrants() {
	if (_retired) {
		return true;
	}
	const auto current = _workspace.LoadCommitted();
	const auto checkpoint = current && current->emergencyRecovery == _receipt
		? OpenRecovery(*current) : std::nullopt;
	if (!checkpoint || checkpoint->journal.operationId != _record.journal.operationId
		|| !VerifyRecoveryReceipt(_workspace, *checkpoint, _receipt)) {
		return false;
	}
	const auto successor = TransactionId(_record.successorGeneration);
	const auto vault = ByteArrayOf(_record.sealedProfileVault);
	const auto keyring = ByteArrayOf(_record.sealedAccountKeyring);
	if (checkpoint->phase == EA::EmergencyRecoveryPhase::Admission) {
		const auto original = ParseProfileVault(current->profileVault);
		if (!original || !CheckSuccessor(*original, vault)
			|| !_workspace.ReplaceCommitted(current->transactionId, {
				{ MigrationArtifact::ProfileVault, vault },
				{ MigrationArtifact::AccountKeyring, keyring },
				{ MigrationArtifact::EmergencyRecovery, current->emergencyRecovery },
			}, [&](const CommittedMigration &candidate) {
				return candidate.profileVault == vault && candidate.accountKeyring == keyring
					&& candidate.transactionId == successor
					&& candidate.emergencyRecovery == current->emergencyRecovery;
			}, nullptr, successor)) {
			return false;
		}
	} else if (current->profileVault != vault || current->accountKeyring != keyring) {
		return false;
	}
	_retired = _workspace.RetireInactiveGenerations(successor);
	return _retired;
}

EA::EffectResult LocalReset::clear(const EA::AccountId &account) {
	return retireGrants() ? _clear.clear(account) : EA::EffectResult::ConfirmedFailure;
}

bool LocalReset::confirmLocalCleanup() {
	if (!retireGrants()) {
		return false;
	}
	for (const auto &target : _record.accounts) {
		if (_clear.clear(target.accountId) != EA::EffectResult::ConfirmedSuccess) {
			return false;
		}
	}
	return true;
}

std::optional<QByteArray> LocalReset::finish() {
	if (!confirmLocalCleanup()) {
		return std::nullopt;
	}
	const auto current = _workspace.LoadCommitted();
	const auto checkpoint = current && current->emergencyRecovery == _receipt
		? OpenRecovery(*current) : std::nullopt;
	if (!checkpoint || checkpoint->phase != EA::EmergencyRecoveryPhase::Successor
		|| checkpoint->journal.operationId != _record.journal.operationId) {
		return std::nullopt;
	}
	const auto finished = _workspace.ReplaceCommitted(current->transactionId,
		BaseArtifacts(*current), [&](const CommittedMigration &candidate) {
			return candidate.profileVault == current->profileVault
				&& candidate.accountKeyring == current->accountKeyring
				&& candidate.emergencyRecovery.isEmpty();
		});
	if (!finished || !_workspace.RetireInactiveGenerations(finished->transactionId)) {
		return std::nullopt;
	}
#ifdef Q_OS_MAC
	if (_record.hasNamedWebviewProof && !EA::RetireMacScopedWebviewRecoveryReceipt(
			_record.journal.installationId, _record.journal.operationId,
			_record.admissionGeneration, DataRoot(_workspace), BytesOf(_receipt))) {
		LOG(("Could not retire the completed Mini App cleanup receipt."));
	}
#endif // Q_OS_MAC
	return finished->transactionId;
}

class ProtectedDestination final : public EA::SafeDestinationEffect {
public:
	EA::EffectResult activate(EA::SafeDestinationKind, const EA::ProfileId&) override {
		return EA::EffectResult::Unconfirmed;
	}
};

std::unique_ptr<EA::RemoteSessionEffect> RemoteEffect(
		const MigrationController &workspace,
		const EA::EmergencyActionJournal &journal,
		std::span<const EA::EmergencyExecutionAccount> accounts) {
	auto access = SetVaultAccess{ .id = SetId{1, 1} };
	auto bindings = std::vector<EA::ScopedSessionBinding>();
	for (const auto &account : accounts) {
		const auto id = StorageId<AccountId>(account.accountId.value);
		if (!id) {
			return nullptr;
		}
		if (!account.remoteIdentity) {
			continue;
		}
		access.accounts.push_back({ id, ByteArrayOf(account.scopedKey) });
		access.locators.push_back({ id, TransactionId(account.locator) });
		bindings.push_back({ account.accountId, id, account.remoteIdentity->userId,
			account.remoteIdentity->environment == EA::EmergencyScopedEnvironment::Test });
	}
	const auto plan = BuildAccountStoragePlan(workspace.accountStorageRoot(), std::move(access), {});
	return plan ? EA::MakeMtprotoSessionEffect(journal.installationId,
		journal, workspace, *plan, bindings) : nullptr;
}

std::optional<QByteArray> RunRecovery(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt,
		EA::RemoteSessionEffect *remote) {
	const auto directory = workspace.emergencyJournalDirectory();
	if (directory.isEmpty() || !VerifyRecoveryReceipt(workspace, record, receipt)) {
		return std::nullopt;
	}
	auto store = EA::FileJournalStore(NativePath(directory));
	const auto lease = store.tryAcquireExecution();
	if (!lease) {
		return std::nullopt;
	}
	const auto seed = EA::EncodeJournal(record.journal);
	const auto created = store.createAtomically(record.journal.operationId, seed);
	auto journal = EA::LoadJournal(store, record.journal.operationId);
	if (!journal || !EA::MatchesEmergencyRecoveryJournal(record, *journal)) {
		return std::nullopt;
	}
	auto local = LocalReset(workspace, record, receipt);
	auto destination = ProtectedDestination();
	const auto report = (created == EA::JournalCreateResult::Created && remote)
		? EA::RunResetCoordinator(*journal, *lease, *remote, local, destination, Clock())
		: EA::ResumeResetCoordinator(*journal, *lease, local, destination);
	return report.localCleanupComplete ? local.finish() : std::nullopt;
}

std::optional<EA::EmergencyActionJournal> PrepareRemovalJournal(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt,
		EA::RemoteSessionEffect *remote) {
	const auto directory = workspace.emergencyJournalDirectory();
	if (directory.isEmpty() || !VerifyRecoveryReceipt(workspace, record, receipt)) {
		return std::nullopt;
	}
	auto store = EA::FileJournalStore(NativePath(directory));
	const auto lease = store.tryAcquireExecution();
	if (!lease) {
		return std::nullopt;
	}
	const auto created = store.createAtomically(record.journal.operationId, EA::EncodeJournal(record.journal));
	auto journal = EA::LoadJournal(store, record.journal.operationId);
	if (!journal || !EA::MatchesEmergencyRecoveryJournal(record, *journal)) {
		return std::nullopt;
	}
	auto local = LocalReset(workspace, record, receipt);
	const auto report = EA::RunInstallationCleanupCoordinator(*journal, *lease,
		(created == EA::JournalCreateResult::Created) ? remote : nullptr, local, Clock());
	if (!report.localCleanupComplete || report.result == EA::CoordinatorResult::CheckpointFailed
		|| !local.confirmLocalCleanup()
		|| EA::BeginEffect(*journal, EA::JournalEffect::InstallationRemoval) != EA::TransitionResult::Applied
		|| !EA::SaveJournal(store, *journal)) {
		return std::nullopt;
	}
	return journal;
}

bool RunRemovalRecovery(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt,
		ApprovedRemovalPackage package,
		EA::RemoteSessionEffect *remote) {
	const auto journal = PrepareRemovalJournal(workspace, record, receipt, remote);
	return journal && LaunchProfileInstallationRemoval(workspace, record, std::move(package), *journal);
}

bool FinishRefusedLegacyRemoval(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt) {
	const auto directory = workspace.emergencyJournalDirectory();
	if (directory.isEmpty() || !VerifyRecoveryReceipt(workspace, record, receipt)) {
		return false;
	}
	auto store = EA::FileJournalStore(NativePath(directory));
	const auto lease = store.tryAcquireExecution();
	const auto journal = lease ? EA::LoadJournal(store, record.journal.operationId) : std::nullopt;
	return journal && EA::MatchesEmergencyRecoveryJournal(record, *journal)
		&& journal->installationRemoval.state == EA::EffectState::Refused
		&& LocalReset(workspace, record, receipt).finish().has_value();
}

bool UsesNamedWebviewStores(const RevocableEmergencyCheckpoint &checkpoint) {
	return !checkpoint.accounts.empty() && checkpoint.accounts.front().namedWebviewStores.has_value();
}

bool VerifyRevocableReceipt(
		const MigrationController &workspace,
		const RevocableEmergencyCheckpoint &checkpoint,
		const QByteArray &receipt) {
	if (!UsesNamedWebviewStores(checkpoint)) {
		return true;
	}
#ifdef Q_OS_MAC
	return EA::VerifyMacScopedWebviewRecoveryReceipt(checkpoint.journal.installationId,
		checkpoint.journal.operationId, checkpoint.activeTransactionId.toHex().toStdString(),
		DataRoot(workspace), BytesOf(receipt));
#else
	return false;
#endif // Q_OS_MAC
}

class RevocableLocalReset final : public EA::LocalAccountEffect {
public:
	RevocableLocalReset(
			const MigrationController &workspace,
			const MigrationGenerationProof &proof,
			const RevocableEmergencyCheckpoint &checkpoint,
			const QByteArray &receipt)
	: _workspace(workspace)
	, _proof(proof)
	, _receipt(receipt)
	, _clear(checkpoint.journal.installationId, DataRoot(workspace), {
		.installationId = checkpoint.journal.installationId,
		.accountStorageRoot = NativePath(workspace.accountStorageRoot()),
		.accounts = checkpoint.accounts,
	}
#ifdef Q_OS_MAC
	, UsesNamedWebviewStores(checkpoint) ? EA::ClearScopedWebviewStores(EA::ClearMacScopedWebviewStores)
		: EA::ClearScopedWebviewStores()
#endif // Q_OS_MAC
	) {
	}

	EA::EffectResult clear(const EA::AccountId &account) override {
		auto result = EA::EffectResult::ConfirmedFailure;
		const auto matches = _workspace.WithCurrentRevocableRecovery(_proof, [&](const auto &active) {
			if (active.revocableEmergencyRecovery != _receipt) {
				return false;
			}
			result = _clear.clear(account);
			return true;
		});
		return matches ? result : EA::EffectResult::ConfirmedFailure;
	}

private:
	const MigrationController &_workspace;
	const MigrationGenerationProof &_proof;
	const QByteArray &_receipt;
	EA::ScopedAccountClear _clear;

};

struct RevocableCleanup final {
	std::optional<MigrationGenerationProof> completed;
	bool removalReady = false;
};

std::vector<MigrationInput> RevocableArtifacts(
		const CommittedMigration &active,
		const QByteArray &gates,
		const QByteArray &rules) {
	return {
		{ MigrationArtifact::ProfileVault, active.profileVault },
		{ MigrationArtifact::AccountGateTable, gates },
		{ MigrationArtifact::RevocableEmergencyRules, rules },
	};
}

bool CanOpenRevocableSafeSet(const OpenedProfileGeneration &opened, SetId expected) {
	const auto access = opened.access();
	return access.role == ProfileGenerationRole::Set && access.setId == expected
		&& std::ranges::all_of(opened.plan().targets(), [&](const auto &account) {
			const auto key = opened.plan().keyFor(account.id);
			const auto local = key ? ProfileAccountStorageKey(*key) : nullptr;
			return local && Storage::ValidateScopedAccountForStartup(account.paths, local).has_value();
		});
}

RevocableCleanup RunRevocableRecovery(
		const MigrationController &workspace,
		const CommittedMigration &active,
		EA::RemoteSessionEffect *remote) {
	const auto &encoded = active.revocableEmergencyRecovery;
	const auto checkpoint = ParseRevocableEmergencyCheckpoint(active.installationId,
		active.transactionId, active.accountGateTable, active.revocableEmergencyRules, encoded);
	if (!checkpoint || !VerifyRevocableReceipt(workspace, *checkpoint, encoded)
		|| !workspace.RetireRevocableGenerations(active.proof())) {
		return {};
	}
	const auto &seed = checkpoint->journal;
	const auto removing = (seed.action == EA::EmergencyAction::RemoveInstallation);
	auto package = removing ? ReadRemovalPackage(workspace, seed.installationId) : std::nullopt;
	if (package && package->digest != checkpoint->installationPackageDigest) {
		package.reset();
	}
	const auto directory = workspace.emergencyJournalDirectory();
	if (directory.isEmpty()) {
		return {};
	}
	auto store = EA::FileJournalStore(NativePath(directory));
	auto lease = store.tryAcquireExecution();
	if (!lease) {
		return {};
	}
	const auto created = store.createAtomically(seed.operationId, EA::EncodeJournal(seed));
	auto journal = EA::LoadJournal(store, seed.operationId);
	auto receipt = EA::EmergencyRecoveryRecord{ .journal = seed };
	if (!journal || !EA::MatchesEmergencyRecoveryJournal(receipt, *journal)) {
		return {};
	}
	const auto proof = active.proof();
	auto local = RevocableLocalReset(workspace, proof, *checkpoint, encoded);
	auto destination = ProtectedDestination();
	const auto attemptRemote = (created == EA::JournalCreateResult::Created) ? remote : nullptr;
	const auto report = removing
		? EA::RunInstallationCleanupCoordinator(*journal, *lease, attemptRemote, local, Clock())
		: attemptRemote ? EA::RunResetCoordinator(*journal, *lease, *attemptRemote, local, destination, Clock())
		: EA::ResumeResetCoordinator(*journal, *lease, local, destination);
	if (!report.localCleanupComplete || report.result == EA::CoordinatorResult::CheckpointFailed
		|| !std::ranges::all_of(checkpoint->accounts, [&](const auto &account) {
			return local.clear(account.accountId) == EA::EffectResult::ConfirmedSuccess;
		})) {
		return {};
	}
	if (removing && journal->installationRemoval.state != EA::EffectState::Refused) {
		if (package) {
			if (EA::BeginEffect(*journal, EA::JournalEffect::InstallationRemoval) != EA::TransitionResult::Applied
				|| !EA::SaveJournal(store, *journal)) {
				return {};
			}
			receipt.admissionGeneration = receipt.successorGeneration = active.transactionId.toHex().toStdString();
			const auto digest = BytesOf(checkpoint->installationPackageDigest);
			receipt.installationDigest.assign(digest.begin(), digest.end());
			lease.reset();
			return { .removalReady = LaunchProfileInstallationRemoval(workspace, receipt, std::move(*package), *journal) };
		}
		if (EA::MarkInstallationRemovalRefused(*journal) != EA::TransitionResult::Applied
			|| !EA::SaveJournal(store, *journal)) {
			return {};
		}
	}
	const auto finished = workspace.ReplaceRevocableCommitted(proof, active.installationId,
		RevocableArtifacts(active, active.accountGateTable, active.revocableEmergencyRules),
		[&](const auto &candidate) {
			return candidate.profileVault == active.profileVault && candidate.accountGateTable == active.accountGateTable
				&& candidate.revocableEmergencyRules == active.revocableEmergencyRules
				&& candidate.revocableEmergencyRecovery.isEmpty();
		});
	if (!finished || !workspace.RetireRevocableGenerations(finished->proof())) {
		return {};
	}
#ifdef Q_OS_MAC
	if (UsesNamedWebviewStores(*checkpoint) && !EA::RetireMacScopedWebviewRecoveryReceipt(seed.installationId,
			seed.operationId, active.transactionId.toHex().toStdString(), DataRoot(workspace), BytesOf(encoded))) {
		LOG(("Could not retire the completed Mini App cleanup receipt."));
	}
#endif // Q_OS_MAC
	return { .completed = finished->proof() };
}

std::optional<OpenedProfileGeneration> SubmitRevocableEmergency(
		const MigrationController &workspace,
		const CommittedMigration &current,
		const DerivedCredential &credential,
		Error &error) {
	if (!current.revocableEmergencyRecovery.isEmpty()) {
		error = Error::EmergencyRecoveryRequired;
		return std::nullopt;
	} else if (current.revocableEmergencyRules.isEmpty()) {
		return std::nullopt;
	}
	const auto readPackage = [&](const EA::InstallationId &id)
			-> std::optional<EA::EmergencyExecutionCapsuleDigest> {
		const auto package = ReadRemovalPackage(workspace, id);
		if (!package || package->digest.size() != qsizetype(EA::kEmergencyInstallationDigestBytes)) {
			return std::nullopt;
		}
		auto result = EA::EmergencyExecutionCapsuleDigest();
		std::ranges::copy(BytesOf(package->digest), result.begin());
		return result;
	};
	auto readNamed = ResolveRevocableEmergencyNamedStores();
#ifdef Q_OS_MAC
	if (QOperatingSystemVersion::current().majorVersion() >= 14) {
		readNamed = [&](const AccountKey &key, const AccountGateBinding &binding,
				const EA::EmergencyScopedRemoteIdentity &identity) {
			return ReadNamedWebviewStores(workspace, key, QString::fromLatin1(binding.locator.toHex()),
				identity.userId);
		};
	}
#endif // Q_OS_MAC
	const auto preparedResult = PrepareRevocableEmergencyAdmission(current,
		MigrationController::NewTransactionId(), credential, readPackage, readNamed);
	if (const auto consumed = std::get_if<ConsumedRevocableEmergencyAdmission>(&preparedResult);
		consumed && !consumed->enrollmentOperation.isEmpty()) {
		return OpenRevocableEmergencyEnrollment(workspace, current.proof(),
			consumed->enrollmentOperation, credential, &error);
	}
	const auto prepared = std::get_if<PreparedRevocableEmergencyAdmission>(&preparedResult);
	if (!prepared) {
		if (!std::holds_alternative<EA::WrongPasscode>(preparedResult)
			&& !std::holds_alternative<ConsumedRevocableEmergencyAdmission>(preparedResult)) {
			error = Error::InvalidPlan;
		}
		return std::nullopt;
	}
	const auto &checkpoint = prepared->checkpoint();
#ifdef Q_OS_MAC
	if (UsesNamedWebviewStores(checkpoint) && !EA::BindMacScopedWebviewRecoveryReceipt(
			checkpoint.journal.installationId, checkpoint.journal.operationId,
			checkpoint.activeTransactionId.toHex().toStdString(), DataRoot(workspace), BytesOf(prepared->receipt()))) {
		error = Error::InvalidPlan;
		return std::nullopt;
	}
#endif // Q_OS_MAC
	auto inputs = RevocableArtifacts(current, prepared->gateTable(), prepared->rules());
	inputs.push_back({ MigrationArtifact::RevocableEmergencyRecovery, prepared->receipt() });
	const auto accepted = workspace.ReplaceRevocableCommitted(prepared->sourceProof(), current.installationId,
		inputs, [&](const auto &candidate) {
			return candidate.transactionId == prepared->nextTransactionId()
				&& candidate.profileVault == current.profileVault && candidate.accountGateTable == prepared->gateTable()
				&& candidate.revocableEmergencyRules == prepared->rules()
				&& candidate.revocableEmergencyRecovery == prepared->receipt();
		}, nullptr, prepared->nextTransactionId());
	if (!accepted) {
		error = Error::EmergencyRecoveryRequired;
		return std::nullopt;
	}
	auto remoteAccounts = std::vector<EA::EmergencyExecutionAccount>();
	for (const auto &account : prepared->remoteAccounts()) {
		remoteAccounts.push_back({ account.accountId, account.binding.locator.toHex().toStdString(),
			BytesOf(account.key.key), account.identity });
	}
	const auto remote = RemoteEffect(workspace, checkpoint.journal, remoteAccounts);
	const auto outcome = RunRevocableRecovery(workspace, *accepted, remote.get());
	if (outcome.removalReady) {
		error = Error::InstallationRemovalReady;
		return std::nullopt;
	} else if (!outcome.completed) {
		error = Error::EmergencyRecoveryRequired;
		return std::nullopt;
	}
	const auto enrollment = RevocableEnrollmentOperation(checkpoint.journal.operationId);
	if (const auto &safe = prepared->safeSet()) {
		auto opened = AuthenticateCommittedRevocableProfileGeneration(workspace,
			safe->credential, *outcome.completed, &error);
		if (opened && CanOpenRevocableSafeSet(*opened, safe->id)) {
			return opened;
		}
	}
	if (checkpoint.journal.action == EA::EmergencyAction::ResetAccountData) {
		auto opened = OpenRevocableEmergencyEnrollment(workspace, *outcome.completed,
			enrollment, credential, &error);
		if (opened) {
			error = Error::EmergencyResetComplete;
			return opened;
		}
	}
	error = Error::EmergencyResetComplete;
	return std::nullopt;
}

} // namespace

std::optional<OpenedProfileGeneration> SubmitProfileEmergencyOnWorker(
		const MigrationController &workspace,
		const CommittedMigration &committed,
		const DerivedCredential &credential,
		ProfileGenerationError &error) {
	if (committed.layout == MigrationGenerationLayout::RevocableGates) {
		return SubmitRevocableEmergency(workspace, committed, credential, error);
	}
	if (committed.emergencyRules.isEmpty()) {
		return std::nullopt;
	}
	const auto bundle = ReadProfileEmergencyBundle(committed);
	if (!bundle || !committed.emergencyRecovery.isEmpty()) {
		error = Error::EmergencyRecoveryRequired;
		return std::nullopt;
	}
	auto authenticated = EA::AuthenticateEmergencyRule(
		bundle->authority, BytesOf(bundle->rules), BytesOf(credential.key));
	if (std::holds_alternative<EA::WrongPasscode>(authenticated)) {
		return std::nullopt;
	}
	const auto ticket = std::get_if<EA::EmergencyRuleTicket>(&authenticated);
	if (!ticket || !ticket->details().executionCapsuleDigest) {
		error = Error::InvalidVault;
		return std::nullopt;
	}
	const auto capsule = bundle->capsules.find(ByteArrayOf(*ticket->details().executionCapsuleDigest));
	const auto admission = MigrationController::NewTransactionId();
	auto resolveWebviewStores = EA::ResolveScopedWebviewStores();
#ifdef Q_OS_MAC
	if (QOperatingSystemVersion::current().majorVersion() >= 14) {
		resolveWebviewStores = [&](const EA::EmergencyExecutionAccount &account) {
			return ReadNamedWebviewStores(workspace, account);
		};
	}
#endif // Q_OS_MAC
	const auto prepared = capsule != end(bundle->capsules) ? EA::PrepareEmergencyRecoveryRecord(
		*ticket, BytesOf(capsule->second), BytesOf(credential.key),
		admission.toHex().toStdString(), resolveWebviewStores) : std::nullopt;
	if (!prepared) {
		error = Error::InvalidVault;
		return std::nullopt;
	}
	const auto receipt = ByteArrayOf(prepared->bytes);
	const auto record = EA::DecodeEmergencyRecoveryRecord(BytesOf(receipt),
		bundle->authority.generation.installationId, admission.toHex().toStdString());
	if (!record) {
		error = Error::InvalidPlan;
		return std::nullopt;
	}
	const auto removesInstallation = record->journal.action == EA::EmergencyAction::RemoveInstallation;
	auto package = removesInstallation ? ReadRemovalPackage(workspace, record->journal.installationId) : std::nullopt;
	if (removesInstallation && (!package || package->digest != ByteArrayOf(record->installationDigest))) {
		error = Error::InvalidPlan;
		return std::nullopt;
	}
#ifdef Q_OS_MAC
	if (record->hasNamedWebviewProof && !EA::BindMacScopedWebviewRecoveryReceipt(
			record->journal.installationId, record->journal.operationId, record->admissionGeneration,
			DataRoot(workspace), BytesOf(receipt))) {
		error = Error::InvalidPlan;
		return std::nullopt;
	}
#endif // Q_OS_MAC
	auto inputs = BaseArtifacts(committed);
	inputs.push_back({ MigrationArtifact::EmergencyRecovery, receipt });
	const auto accepted = workspace.ReplaceCommitted(committed.transactionId, inputs,
		[&](const CommittedMigration &candidate) {
			return candidate.transactionId == admission && candidate.profileVault == committed.profileVault
				&& candidate.accountKeyring == committed.accountKeyring && candidate.emergencyRecovery == receipt;
		}, nullptr, admission);
	if (!accepted) {
		error = Error::EmergencyRecoveryRequired;
		return std::nullopt;
	}
	const auto remote = RemoteEffect(workspace, record->journal, prepared->capsule.accounts());
	if (package) {
		error = RunRemovalRecovery(workspace, *record, receipt, std::move(*package), remote.get())
			? Error::InstallationRemovalReady : Error::EmergencyRecoveryRequired;
		return std::nullopt;
	}
	const auto installed = RunRecovery(workspace, *record, receipt, remote.get());
	if (!installed) {
		error = Error::EmergencyRecoveryRequired;
		return std::nullopt;
	}
	if (const auto &safe = prepared->capsule.safeDestination(); safe && safe->sealedSetGrant.size() == 64) {
		const auto bytes = safe->sealedSetGrant;
		auto opened = AuthenticateCommittedProfileGeneration(workspace, {}, {
			.verifier = ByteArrayOf(bytes.first(32)), .key = ByteArrayOf(bytes.last(32)),
		}, {}, {}, {}, {}, *installed, &error);
		if (opened && opened->access().role == ProfileGenerationRole::Set
			&& opened->access().setId == StorageId<SetId>(safe->profileId.value)) {
			return opened;
		}
	} else if (record->journal.safeDestination == EA::SafeDestinationKind::AddAccount) {
		auto opened = AuthenticateCommittedProfileGeneration(workspace, {}, credential,
			{}, {}, {}, {}, *installed, &error);
		if (opened && opened->access().role == ProfileGenerationRole::Set
			&& opened->plan().targets().empty()) {
			error = Error::EmergencyResetComplete;
			return opened;
		}
	}
	error = Error::EmergencyResetComplete;
	return std::nullopt;
}

ProfileEmergencyRecoveryResult FinishProfileEmergencyRecovery(const QString &dataDirectory) {
	using Result = ProfileEmergencyRecoveryResult;
	const auto workspace = MigrationController::OpenProfileWorkspace(dataDirectory);
	const auto committed = workspace ? workspace->LoadCommitted() : std::nullopt;
	if (!committed) {
		return Result::Failed;
	} else if (committed->layout == MigrationGenerationLayout::RevocableGates) {
		if (committed->revocableEmergencyRecovery.isEmpty()) {
			return Result::Ready;
		}
		const auto result = RunRevocableRecovery(*workspace, *committed, nullptr);
		return result.removalReady ? Result::InstallationRemovalReady
			: result.completed ? Result::Ready : Result::Failed;
	} else if (committed->emergencyRecovery.isEmpty()) {
		return Result::Ready;
	}
	const auto record = OpenRecovery(*committed);
	if (!record) {
		return Result::Failed;
	} else if (record->journal.action == EA::EmergencyAction::RemoveInstallation) {
		if (FinishRefusedLegacyRemoval(*workspace, *record, committed->emergencyRecovery)) {
			return Result::Ready;
		}
		auto package = ReadRemovalPackage(*workspace, record->journal.installationId);
		return (package && package->digest == ByteArrayOf(record->installationDigest)
				&& RunRemovalRecovery(*workspace, *record, committed->emergencyRecovery, std::move(*package), nullptr))
			? Result::InstallationRemovalReady : Result::Failed;
	}
	return RunRecovery(*workspace, *record, committed->emergencyRecovery, nullptr)
		? Result::Ready : Result::Failed;
}

} // namespace Ayu::ProfileSets
