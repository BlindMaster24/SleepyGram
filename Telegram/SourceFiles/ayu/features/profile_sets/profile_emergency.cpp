// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_emergency.h"

#include "ayu/features/emergency_actions/emergency_recovery_record.h"
#include "ayu/features/emergency_actions/mtproto_session_effect_transport.h"
#include "ayu/features/profile_sets/profile_emergency_bundle.h"

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
	return QFileInfo(path).filesystemFilePath();
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
, _clear(record.journal.installationId, NativePath(QFileInfo(workspace.workspacePath()).path()), {
	.installationId = record.journal.installationId,
	.accountStorageRoot = NativePath(workspace.accountStorageRoot()),
	.accounts = record.accounts,
}) {
}

bool LocalReset::retireGrants() {
	if (_retired) {
		return true;
	}
	const auto current = _workspace.LoadCommitted();
	const auto checkpoint = current && current->emergencyRecovery == _receipt
		? OpenRecovery(*current) : std::nullopt;
	if (!checkpoint || checkpoint->journal.operationId != _record.journal.operationId) {
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

std::optional<QByteArray> LocalReset::finish() {
	if (!retireGrants()) {
		return std::nullopt;
	}
	for (const auto &target : _record.accounts) {
		if (_clear.clear(target.accountId) != EA::EffectResult::ConfirmedSuccess) {
			return std::nullopt;
		}
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
	return (finished && _workspace.RetireInactiveGenerations(finished->transactionId))
		? std::optional(finished->transactionId) : std::nullopt;
}

class ProtectedDestination final : public EA::SafeDestinationEffect {
public:
	EA::EffectResult activate(EA::SafeDestinationKind, const EA::ProfileId&) override {
		return EA::EffectResult::Unconfirmed;
	}
};

std::unique_ptr<EA::RemoteSessionEffect> RemoteEffect(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const EA::OpenedEmergencyExecutionCapsule &capsule) {
	auto access = SetVaultAccess{ .id = SetId{1, 1} };
	auto bindings = std::vector<EA::ScopedSessionBinding>();
	for (const auto &account : capsule.accounts()) {
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
	return plan ? EA::MakeMtprotoSessionEffect(record.journal.installationId,
		record.journal, workspace, *plan, bindings) : nullptr;
}

std::optional<QByteArray> RunRecovery(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		const QByteArray &receipt,
		EA::RemoteSessionEffect *remote) {
	const auto directory = workspace.emergencyJournalDirectory();
	if (directory.isEmpty()) {
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

} // namespace

std::optional<OpenedProfileGeneration> SubmitProfileEmergencyOnWorker(
		const MigrationController &workspace,
		const CommittedMigration &committed,
		const DerivedCredential &credential,
		ProfileGenerationError &error) {
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
	const auto prepared = capsule != end(bundle->capsules) ? EA::PrepareEmergencyRecoveryRecord(
		*ticket, BytesOf(capsule->second), BytesOf(credential.key), admission.toHex().toStdString()) : std::nullopt;
	if (!prepared) {
		error = Error::InvalidVault;
		return std::nullopt;
	}
	const auto receipt = ByteArrayOf(prepared->bytes);
	const auto record = EA::DecodeEmergencyRecoveryRecord(BytesOf(receipt),
		bundle->authority.generation.installationId, admission.toHex().toStdString());
	if (!record || record->journal.action != EA::EmergencyAction::ResetAccountData) {
		error = Error::InvalidPlan;
		return std::nullopt;
	}
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
	const auto remote = RemoteEffect(workspace, *record, prepared->capsule);
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
	}
	error = Error::EmergencyResetComplete;
	return std::nullopt;
}

bool FinishProfileEmergencyRecovery(const QString &dataDirectory) {
	const auto workspace = MigrationController::OpenProfileWorkspace(dataDirectory);
	const auto committed = workspace ? workspace->LoadCommitted() : std::nullopt;
	if (!committed) {
		return false;
	} else if (committed->emergencyRecovery.isEmpty()) {
		return true;
	}
	const auto record = OpenRecovery(*committed);
	return record && RunRecovery(*workspace, *record, committed->emergencyRecovery, nullptr).has_value();
}

} // namespace Ayu::ProfileSets
