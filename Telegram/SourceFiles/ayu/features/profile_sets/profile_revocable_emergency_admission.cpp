// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_emergency_admission.h"

#include <QtCore/QCryptographicHash>

#include <openssl/crypto.h>

#include <algorithm>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;

constexpr auto kIdSize = qsizetype(16);
constexpr auto kDigestSize = qsizetype(32);

std::span<const uint8_t> Bytes(QByteArrayView value) {
	return { reinterpret_cast<const uint8_t*>(value.data()), size_t(value.size()) };
}

QByteArray ByteArray(std::span<const uint8_t> value) {
	return { reinterpret_cast<const char*>(value.data()), qsizetype(value.size()) };
}

QByteArray Digest(QByteArrayView value) {
	return QCryptographicHash::hash(value, QCryptographicHash::Sha256);
}

bool Nonzero(QByteArrayView value, qsizetype size) {
	return value.size() == size && std::ranges::any_of(value, [](char byte) {
		return byte != 0;
	});
}

void Wipe(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
	}
}

bool CanPrepare(
		const CommittedMigration &committed,
		QByteArrayView next,
		const DerivedCredential &credential) {
	return committed.layout == MigrationGenerationLayout::RevocableGates
		&& !committed.retirementPending
		&& Nonzero(committed.installationId, kIdSize)
		&& Nonzero(committed.transactionId, kIdSize)
		&& Nonzero(committed.manifestDigest, kDigestSize)
		&& Nonzero(next, kIdSize) && next != committed.transactionId
		&& !committed.profileVault.isEmpty()
		&& !committed.accountGateTable.isEmpty() && !committed.revocableEmergencyRules.isEmpty()
		&& committed.accountKeyring.isEmpty() && committed.legacyRetirement.isEmpty()
		&& committed.emergencyRules.isEmpty() && committed.emergencyRecovery.isEmpty()
		&& committed.revocableEmergencyRecovery.isEmpty()
		&& Nonzero(credential.verifier, kVerifierSize) && Nonzero(credential.key, kProfileVaultKeySize);
}

bool MatchesActiveScope(
		const EA::DryRunPlan &plan,
		const AccountGateTable &gates,
		std::span<const RevocableEmergencyAccount> targets) {
	if (plan.targetScope == EA::TargetScope::SelectedAccounts) {
		return true;
	}
	auto bindings = std::vector<AccountGateBinding>();
	bindings.reserve(targets.size());
	for (const auto &target : targets) {
		bindings.push_back(target.handle.binding());
	}
	return gates.coversActiveBindings(bindings);
}

} // namespace

struct PreparedRevocableEmergencyAdmission::Data final {
	~Data() {
		for (auto &account : remoteAccounts) {
			Wipe(account.key.key);
		}
		if (safeSet) {
			Wipe(safeSet->credential.verifier);
			Wipe(safeSet->credential.key);
		}
	}

	MigrationGenerationProof sourceProof;
	RevocableEmergencyCheckpoint checkpoint;
	QByteArray gateTable;
	QByteArray rules;
	QByteArray receipt;
	std::vector<RevocableEmergencyRemoteAccount> remoteAccounts;
	std::optional<SetGrantCredential> safeSet;
};

PreparedRevocableEmergencyAdmission::PreparedRevocableEmergencyAdmission(std::unique_ptr<Data> data)
: _data(std::move(data)) {
}

PreparedRevocableEmergencyAdmission::PreparedRevocableEmergencyAdmission(
	PreparedRevocableEmergencyAdmission&&) noexcept = default;
PreparedRevocableEmergencyAdmission::~PreparedRevocableEmergencyAdmission() = default;

const MigrationGenerationProof &PreparedRevocableEmergencyAdmission::sourceProof() const {
	return _data->sourceProof;
}

const QByteArray &PreparedRevocableEmergencyAdmission::nextTransactionId() const {
	return _data->checkpoint.activeTransactionId;
}

const QByteArray &PreparedRevocableEmergencyAdmission::gateTable() const {
	return _data->gateTable;
}

const QByteArray &PreparedRevocableEmergencyAdmission::rules() const {
	return _data->rules;
}

const QByteArray &PreparedRevocableEmergencyAdmission::receipt() const {
	return _data->receipt;
}

const RevocableEmergencyCheckpoint &PreparedRevocableEmergencyAdmission::checkpoint() const {
	return _data->checkpoint;
}

auto PreparedRevocableEmergencyAdmission::remoteAccounts() const
-> std::span<const RevocableEmergencyRemoteAccount> {
	return _data->remoteAccounts;
}

const std::optional<SetGrantCredential> &PreparedRevocableEmergencyAdmission::safeSet() const {
	return _data->safeSet;
}

RevocableEmergencyAdmissionResult PrepareRevocableEmergencyAdmission(
		const CommittedMigration &committed,
		QByteArrayView nextTransactionId,
		const DerivedCredential &credential,
		const ResolveRevocableEmergencyPackage &resolvePackage,
		const ResolveRevocableEmergencyNamedStores &resolveNamedStores) {
	constexpr auto invalid = InvalidRevocableEmergencyAdmission();
	if (!CanPrepare(committed, nextTransactionId, credential)) {
		return invalid;
	}
	const auto bundle = ParseRevocableProfileEmergencyBundle(
		committed.installationId, committed.revocableEmergencyRules);
	if (!bundle) {
		return invalid;
	}
	const auto authenticated = EA::AuthenticateEmergencyRule(
		bundle->rules.authority, Bytes(bundle->rules.rules), Bytes(credential.key));
	if (std::holds_alternative<EA::WrongPasscode>(authenticated)) {
		return EA::WrongPasscode();
	}
	const auto ticket = std::get_if<EA::EmergencyRuleTicket>(&authenticated);
	if (!ticket || !ticket->details().executionCapsuleDigest) {
		return invalid;
	}
	const auto capsuleDigest = ByteArray(*ticket->details().executionCapsuleDigest);
	if (bundle->consumed.contains(capsuleDigest)) {
		const auto landing = bundle->landings.find(capsuleDigest);
		if (landing == bundle->landings.end()) {
			return ConsumedRevocableEmergencyAdmission();
		}
		return (landing->second == RevocableEnrollmentOperation(ticket->details().operationId))
			? RevocableEmergencyAdmissionResult(ConsumedRevocableEmergencyAdmission{ landing->second })
			: RevocableEmergencyAdmissionResult(invalid);
	}
	const auto capsule = bundle->rules.capsules.find(capsuleDigest);
	const auto gates = ParseAccountGateTable(committed.accountGateTable, committed.installationId);
	if (capsule == bundle->rules.capsules.end() || !gates) {
		return invalid;
	}
	auto package = std::optional<EA::EmergencyExecutionCapsuleDigest>();
	if (ticket->details().rule.action == EA::EmergencyAction::RemoveInstallation) {
		if (!resolvePackage) {
			return invalid;
		}
		try {
			package = resolvePackage(ticket->authority().generation.installationId);
		} catch (...) {
			return invalid;
		}
		if (!package) {
			return invalid;
		}
	}
	auto opened = OpenRevocableEmergencyCapability(bundle->rules.authority.generation,
		*ticket, *gates, Bytes(capsule->second), package, Bytes(credential.key));
	if (const auto revoked = std::get_if<RevokedRevocableEmergencyTargets>(&opened)) {
		return std::move(*revoked);
	}
	const auto capability = std::get_if<OpenedRevocableEmergencyCapability>(&opened);
	if (!capability || !MatchesActiveScope(capability->plan(), *gates, capability->accounts())) {
		return invalid;
	}
	const auto journal = EA::MakeJournal(capability->plan());
	const auto resetsAccounts = (capability->plan().action == EA::EmergencyAction::ResetAccountData);
	const auto enrollment = resetsAccounts ? RevocableEnrollmentOperation(ticket->details().operationId) : QByteArray();
	const auto consumed = ConsumeRevocableProfileEmergencyRule(*bundle, capsuleDigest, enrollment);
	if (!journal || !consumed || (resetsAccounts && enrollment.isEmpty())) {
		return invalid;
	}
	auto accounts = std::move(*capability).takeAccounts();
	auto permits = std::vector<AccountGateRevocationPermit>();
	permits.reserve(accounts.size());
	for (auto &account : accounts) {
		permits.push_back(std::move(account.permit));
	}
	const auto nextGates = permits.empty() ? gates : RevokeAccountGates(*gates, permits);
	if (!nextGates) {
		return invalid;
	}
	auto data = std::make_unique<PreparedRevocableEmergencyAdmission::Data>();
	data->sourceProof = committed.proof();
	data->gateTable = SerializeAccountGateTable(*nextGates);
	data->rules = SerializeRevocableProfileEmergencyBundle(*consumed);
	const auto parsedGates = ParseAccountGateTable(data->gateTable, committed.installationId);
	if (data->rules.isEmpty() || !parsedGates
		|| !std::ranges::all_of(accounts, [&](const auto &account) {
			return InspectAccountGate(*parsedGates, account.handle) == AccountGateStatus::Revoked;
		})) {
		return invalid;
	}
	auto keys = std::vector<AccountKey>();
	const auto wipeKeys = gsl::finally([&] {
		for (auto &key : keys) {
			Wipe(key.key);
		}
	});
	keys.reserve(accounts.size());
	for (const auto &account : accounts) {
		if (resolveNamedStores && !account.remoteIdentity) {
			return invalid;
		}
		auto key = OpenAccountGate(*gates, account.handle);
		const auto open = std::get_if<AccountKey>(&key);
		if (!open) {
			return invalid;
		}
		keys.push_back(std::move(*open));
	}
	data->checkpoint = RevocableEmergencyCheckpoint{
		.activeTransactionId = nextTransactionId.toByteArray(),
		.gateTableDigest = Digest(data->gateTable),
		.rulesDigest = Digest(data->rules),
		.installationPackageDigest = package ? ByteArray(*package) : QByteArray(),
		.journal = *journal,
	};
	data->checkpoint.accounts.reserve(accounts.size());
	data->remoteAccounts.reserve(accounts.size());
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto &account = accounts[i];
		const auto &id = journal->accounts[i].accountId;
		const auto &binding = account.handle.binding();
		auto stores = std::optional<EA::ScopedWebviewStoreIds>();
		if (resolveNamedStores) {
			try {
				stores = resolveNamedStores(keys[i], binding, *account.remoteIdentity);
			} catch (...) {
				return invalid;
			}
			if (!stores || !EA::ValidScopedWebviewStoreIds(*stores)) {
				return invalid;
			}
		}
		data->checkpoint.accounts.push_back({ id, binding.locator.toHex().toStdString(), std::move(stores) });
		if (account.remoteIdentity) {
			data->remoteAccounts.push_back({ id, binding, std::move(keys[i]), *account.remoteIdentity });
		}
	}
	data->receipt = SerializeRevocableEmergencyCheckpoint(data->checkpoint);
	if (data->receipt.isEmpty() || !ParseRevocableEmergencyCheckpoint(committed.installationId,
			nextTransactionId, data->gateTable, data->rules, data->receipt)) {
		return invalid;
	}
	if (const auto &safeSet = capability->safeSet()) {
		data->safeSet = SetGrantCredential{ safeSet->id, {
			.verifier = safeSet->verifier.toByteArray(),
			.key = safeSet->key.toByteArray(),
		} };
	}
	return PreparedRevocableEmergencyAdmission(std::move(data));
}

} // namespace Ayu::ProfileSets
