// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_generation.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_admission.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_bundle.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_capability.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_rebind.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QTemporaryDir>
#include <QtCore/QtEndian>

#include <algorithm>
#include <array>
#include <cstdio>

namespace {

using namespace Ayu::ProfileSets;
namespace EA = Ayu::EmergencyActions;

QByteArray Array(std::span<const uint8_t> bytes) {
	return { reinterpret_cast<const char*>(bytes.data()), qsizetype(bytes.size()) };
}

EA::CredentialVerifier Filled(uint8_t value) {
	auto result = EA::CredentialVerifier();
	result.fill(value);
	return result;
}

DerivedCredential Credential(uint8_t verifier, uint8_t key) {
	return { Array(Filled(verifier)), Array(Filled(key)) };
}

std::string Hex(AccountId id) {
	auto bytes = QByteArray(16, Qt::Uninitialized);
	qToBigEndian(id.high, bytes.data());
	qToBigEndian(id.low, bytes.data() + 8);
	return bytes.toHex().toStdString();
}

constexpr auto kSafeId = SetId{ 2, 9 };

struct ArmedRules final {
	RevocableProfileEmergencyBundle bundle;
	QByteArray consumed;
	QByteArray sibling;
	QByteArray allAccounts;
	QByteArray installation;
	QByteArray operationTag;
};

std::optional<ArmedRules> ArmForReset(
		const AccountGateTable &gates,
		const RevocableAdminVaultAccess &master,
		AccountId a,
		AccountId b) {
	const auto installation = EA::InstallationId(gates.installationId().toHex().toStdString());
	const auto epoch = EA::EmergencyRuleGeneration{ installation, std::string(32, 'e') };
	const auto accounts = std::array{ EA::AccountId(Hex(a)), EA::AccountId(Hex(b)) };
	const auto safe = EA::ProfileId(Hex(AccountId{ kSafeId.high, kSafeId.low }));
	const auto safeCredential = Credential(81, 82);
	const auto live = EA::LiveInstallation{
		.id = installation,
		.accounts = {
			{ accounts[0], EA::SessionId("current"), { EA::SessionId("current") } },
			{ accounts[1], EA::SessionId("current"), { EA::SessionId("current") } },
		},
		.profiles = { { safe, { accounts[0] } } },
	};
	auto configuration = EA::RuleConfiguration{
		.activeInstallationId = installation,
		.masterVerifier = Filled(1),
	};
	const auto names = std::array{ "landing", "sibling", "all-accounts", "installation" };
	const auto operations = std::array{
		EA::OperationId("landing-op"), EA::OperationId("sibling-op"),
		EA::OperationId("all-accounts-op"), EA::OperationId("installation-op"),
	};
	const auto keys = std::array{ Filled(42), Filled(62), Filled(102), Filled(112) };
	const auto verifiers = std::array{ Filled(41), Filled(61), Filled(101), Filled(111) };
	for (auto i = size_t(0); i != names.size(); ++i) {
		const auto action = (i == 3) ? EA::EmergencyAction::RemoveInstallation
			: EA::EmergencyAction::ResetAccountData;
		const auto scope = (i == 3) ? EA::TargetScope::CurrentInstallation
			: (i == 2) ? EA::TargetScope::AllAccounts : EA::TargetScope::SelectedAccounts;
		configuration.emergencyRules.push_back({
			.id = EA::EmergencyActionId(names[i]),
			.rule = {
				.id = EA::RuleId(names[i]), .installationId = installation,
				.action = action,
				.targetScope = scope,
				.selectedAccountIds = (i < 2) ? std::vector{ accounts[i] } : std::vector<EA::AccountId>(),
				.safeProfileId = (i == 1) ? safe : EA::ProfileId(),
			},
			.verifier = verifiers[i],
		});
	}
	auto bundle = RevocableProfileEmergencyBundle();
	auto input = std::vector<EA::EmergencyRuleSealInput>();
	for (auto i = size_t(0); i != names.size(); ++i) {
		const auto &rule = configuration.emergencyRules[i];
		const auto reviewed = EA::PreviewEmergencyRule(configuration, rule.id, live, operations[i]);
		if (!reviewed || !EA::ConfirmEmergencyRule(configuration, *reviewed, live, true)) {
			return std::nullopt;
		}
		auto targets = std::vector<RevocableEmergencyAccount>();
		for (auto j = size_t(0); j != master.accounts.size(); ++j) {
			if (i < 2 && i != j) {
				continue;
			}
			auto handle = AccountGateHandle::Parse(master.accounts[j].handle.serialize());
			auto permit = AccountGateRevocationPermit::Parse(master.accounts[j].permit.serialize());
			if (!handle || !permit) {
				return std::nullopt;
			}
			targets.push_back({ std::move(*handle), std::move(*permit) });
		}
		const auto destination = (i == 1) ? std::optional(RevocableEmergencySafeSetView{
			kSafeId, safeCredential.verifier, safeCredential.key,
		}) : std::nullopt;
		const auto package = (i == 3) ? std::optional(Filled(123)) : std::nullopt;
		const auto capability = SealRevocableEmergencyCapability(epoch, {
			.actionId = rule.id, .rule = rule.rule, .operationId = operations[i], .revision = rule.revision,
		}, live, gates, targets, destination, package, keys[i]);
		if (!capability) {
			return std::nullopt;
		}
		bundle.rules.capsules.emplace(Array(capability->digest), Array(capability->bytes));
		input.push_back({ rule.id, names[i], verifiers[i], keys[i], capability->digest });
	}
	const auto sealed = EA::SealEmergencyRules(epoch, Filled(2), configuration, live, input);
	if (!sealed) {
		return std::nullopt;
	}
	bundle.rules.authority = sealed->authority;
	bundle.rules.rules = Array(sealed->bytes);
	const auto consumed = Array(*input.front().executionCapsuleDigest);
	const auto operationTag = RevocableEnrollmentOperation(operations.front());
	auto resulting = ConsumeRevocableProfileEmergencyRule(bundle, consumed, operationTag);
	return resulting ? std::optional(ArmedRules{
		.bundle = std::move(*resulting),
		.consumed = consumed,
		.sibling = Array(*input[1].executionCapsuleDigest),
		.allAccounts = Array(*input[2].executionCapsuleDigest),
		.installation = Array(*input[3].executionCapsuleDigest),
		.operationTag = operationTag,
	}) : std::nullopt;
}

int RunChecks() {
	auto failures = 0;
	const auto check = [&](bool condition, const char *name) {
		std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
		failures += !condition;
	};
	const auto fixture = QTemporaryDir();
	const auto workspace = MigrationController::CreateProfileWorkspace(fixture.path());
	const auto admin = Credential(1, 2);
	const auto original = Credential(11, 12);
	const auto emergency = Credential(41, 42);
	const auto newPassword = Credential(71, 72);
	const auto siblingPassword = Credential(61, 62);
	const auto set = SetId{ 2, 1 };
	const auto keyA = AccountKey{ { 1, 1 }, QByteArray(32, 'a') };
	const auto keyB = AccountKey{ { 1, 2 }, QByteArray(32, 'b') };
	const auto keyC = AccountKey{ { 1, 3 }, QByteArray(32, 'c') };
	const auto locatorA = QByteArray(16, 'A');
	const auto locatorB = QByteArray(16, 'B');
	const auto locatorC = QByteArray(16, 'C');
	const auto metadata = Metadata{
		.verifierSalt = QByteArray(kVerifierSaltSize, 's'),
		.verifierKdf = { .kind = 1, .memory = 8192, .time = 1, .parallel = 1 },
		.masterVerifier = admin.verifier,
		.sets = { { set, u"Original"_q, original.verifier, { keyA.id, keyB.id } } },
	};
	const auto legacy = SealProfileVault(metadata, { keyA, keyB }, {
		{ keyA.id, locatorA }, { keyB.id, locatorB },
	}, admin, { { set, original } });
	if (!workspace || !legacy || !workspace->Stage({
			{ MigrationArtifact::ProfileVault, SerializeProfileVault(*legacy) },
			{ MigrationArtifact::AccountKeyring, SealAccountKeyring({ keyA, keyB }, admin.key) },
		})) {
		return 1;
	}
	const auto yes = [](const auto&) { return true; };
	const auto pending = workspace->CommitVerified(yes);
	const auto promoted = pending ? PromoteFreshRevocableProfileSetup(
		*workspace, pending->proof(), admin, original, yes) : std::nullopt;
	if (!promoted || !workspace->RetireRevocableGenerations(*promoted)) {
		return 1;
	}
	auto withSafe = metadata;
	const auto safePassword = Credential(81, 82);
	withSafe.sets.push_back({ kSafeId, u"Safe"_q, safePassword.verifier, { keyA.id } });
	const auto scopedSafe = UpdateCommittedRevocableProfileSets(
		*workspace, *promoted, withSafe, admin, { { kSafeId, safePassword } });
	if (!scopedSafe || !workspace->RetireRevocableGenerations(*scopedSafe)) {
		return 1;
	}
	const auto typed = LoadRevocableProfileGeneration(*workspace);
	const auto master = typed ? typed->vault.openMaster(admin) : std::nullopt;
	if (!master || master->accounts.size() != 2) {
		return 1;
	}
	const auto armed = ArmForReset(typed->gates, *master, keyA.id, keyB.id);
	const auto gates = RevokeAccountGates(typed->gates, std::span(&master->accounts[0].permit, 1));
	if (!armed || !gates) {
		return 1;
	}
	const auto rules = SerializeRevocableProfileEmergencyBundle(armed->bundle);
	const auto armedGeneration = workspace->ReplaceRevocableCommitted(*scopedSafe, legacy->id, {
		{ MigrationArtifact::ProfileVault, typed->vault.serialize() },
		{ MigrationArtifact::AccountGateTable, SerializeAccountGateTable(*gates) },
		{ MigrationArtifact::RevocableEmergencyRules, rules },
	}, yes);
	if (!armedGeneration || !workspace->RetireRevocableGenerations(armedGeneration->proof())) {
		return 1;
	}
	const auto proof = armedGeneration->proof();
	const auto landing = OpenRevocableEmergencyEnrollment(*workspace, proof, armed->operationTag, emergency);
	const auto restarted = MigrationController::OpenProfileWorkspace(fixture.path());
	const auto reopened = restarted
		? OpenRevocableEmergencyEnrollment(*restarted, proof, armed->operationTag, emergency)
		: std::nullopt;
	const auto futureSet = RevocableEnrollmentSetId(legacy->id, armed->operationTag);
	check(landing && reopened && landing->access().enrollment && landing->access().setId,
		"pending consumed rule reopens after restart");
	if (!landing || !reopened || !landing->access().enrollment) {
		return 1;
	}
	check(landing->plan().targets().empty() && !landing->plan().keyFor(keyB.id)
		&& landing->access().enrollment->futureSetId == futureSet
		&& landing->access().enrollment->operationTag == armed->operationTag
		&& landing->access().setId != futureSet && landing->settingsKey().size() == 32
		&& landing->settingsKey() == reopened->settingsKey() && landing->access().setId == reopened->access().setId,
		"landing has no old keys and uses stable but separate provisional settings");
	check(!OpenRevocableEmergencyEnrollment(*workspace, proof, armed->operationTag, siblingPassword)
		&& !OpenRevocableEmergencyEnrollment(*workspace, proof, QByteArray(16, 'X'), emergency)
		&& !OpenRevocableEmergencyEnrollment(*workspace, *promoted, armed->operationTag, emergency),
		"landing authenticates exact current proof, operation and consumed slot");

	const auto allRevoked = RevokeAccountGates(*gates, std::span(&master->accounts[1].permit, 1));
	auto existing = allRevoked ? CreateAccountGate(*allRevoked, keyC, locatorC) : std::nullopt;
	auto stillPopulated = CreateAccountGate(*gates, keyC, locatorC);
	if (!existing || !stillPopulated) {
		return 1;
	}
	const auto existingVault = typed->vault.enrolled(admin, set, original, *allRevoked,
		{ std::move(existing->handle), std::move(existing->permit) }, {});
	const auto populated = typed->vault.enrolled(admin, set, original, *gates,
		{ std::move(stillPopulated->handle), std::move(stillPopulated->permit) }, {});
	const auto existingAccess = existingVault ? existingVault->open(original)
		: RevocableProfileVaultAccess(WrongPassword());
	const auto previousAccess = typed->vault.open(original);
	const auto previousSet = std::get_if<RevocableSetVaultAccess>(&previousAccess);
	const auto existingSet = std::get_if<RevocableSetVaultAccess>(&existingAccess);
	check(!populated && existingSet && previousSet && existingSet->id() == set
		&& existingSet->settingsKey() == previousSet->settingsKey()
		&& existingSet->handles().size() == 1
		&& existingSet->handles().front().binding().id == keyC.id,
		"genuine empty set accepts its own password and retains its settings key");

	auto newGate = CreateAccountGate(*gates, keyC, locatorC);
	const auto completed = CompleteRevocableProfileEmergencyEnrollment(armed->bundle, armed->operationTag);
	if (!newGate || !completed) {
		return 1;
	}
	const auto copyNewGrant = [&]() -> std::optional<RevocableAccountGrant> {
		auto handle = AccountGateHandle::Parse(newGate->handle.serialize());
		auto permit = AccountGateRevocationPermit::Parse(newGate->permit.serialize());
		return (handle && permit)
			? std::optional(RevocableAccountGrant{ std::move(*handle), std::move(*permit) })
			: std::nullopt;
	};
	auto newGrant = copyNewGrant();
	auto fallbackGrant = copyNewGrant();
	if (!newGrant || !fallbackGrant) {
		return 1;
	}
	const auto newVault = typed->vault.enrolled(admin, futureSet, newPassword, *gates,
		std::move(*newGrant), u"New set"_q);
	const auto nextMaster = newVault ? newVault->openMaster(admin) : std::nullopt;
	if (!nextMaster) {
		return 1;
	}
	const auto completedBytes = SerializeRevocableProfileEmergencyBundle(*completed);
	const auto newIdentity = EA::EmergencyScopedRemoteIdentity{
		207, EA::EmergencyScopedEnvironment::Production,
	};
	const auto resolvePackage = [&](const EA::InstallationId &installation) {
		return (installation == EA::InstallationId(legacy->id.toHex().toStdString()))
			? std::optional(Filled(123)) : std::nullopt;
	};
	check(!RebindRevocableEmergencyRulesForEnrollment(completedBytes, admin, *master,
		nextMaster->metadata, *gates, *newGate, newIdentity),
		"current-installation rule requires the approved package before enrollment");
	const auto changedFallback = typed->vault.enrolled(admin, kSafeId, safePassword, *gates,
		std::move(*fallbackGrant), {});
	const auto nextFallback = changedFallback ? changedFallback->openMaster(admin) : std::nullopt;
	check(nextFallback && !RebindRevocableEmergencyRulesForEnrollment(completedBytes, admin, *master,
		nextFallback->metadata, *gates, *newGate, newIdentity, resolvePackage),
		"enrollment into an approved fallback requires review of its new membership");
	const auto rebound = RebindRevocableEmergencyRulesForEnrollment(completedBytes, admin, *master,
		nextMaster->metadata, *gates, *newGate, newIdentity, resolvePackage);
	if (!rebound) {
		return 1;
	}
	const auto persisted = workspace->ReplaceRevocableCommitted(proof, legacy->id, {
		{ MigrationArtifact::ProfileVault, newVault->serialize() },
		{ MigrationArtifact::AccountGateTable, SerializeAccountGateTable(newGate->table) },
		{ MigrationArtifact::RevocableEmergencyRules, *rebound },
	}, yes);
	if (!persisted || !workspace->RetireRevocableGenerations(persisted->proof())) {
		return 1;
	}
	const auto newScope = AuthenticateCommittedRevocableProfileGeneration(*workspace, newPassword, persisted->proof());
	const auto originalScope = AuthenticateCommittedRevocableProfileGeneration(*workspace, original, persisted->proof());
	check(newScope && newScope->access().setId == futureSet && !newScope->access().enrollment
		&& newScope->plan().targets().size() == 1 && newScope->plan().keyFor(keyC.id)
		&& originalScope && originalScope->plan().targets().size() == 1
		&& originalScope->plan().keyFor(keyB.id) && !originalScope->plan().keyFor(keyC.id)
		&& newScope->settingsKey() != landing->settingsKey(),
		"completion creates only the new set and scopes its actual key");
	const auto readRules = ParseRevocableProfileEmergencyBundle(legacy->id, persisted->revocableEmergencyRules);
	check(readRules && readRules->consumed.contains(armed->consumed) && readRules->landings.empty()
		&& readRules->rules.authority.generation == armed->bundle.rules.authority.generation
		&& readRules->rules.capsules.contains(armed->sibling)
		&& readRules->rules.capsules.at(armed->sibling) == armed->bundle.rules.capsules.at(armed->sibling)
		&& !readRules->rules.capsules.contains(armed->allAccounts)
		&& !readRules->rules.capsules.contains(armed->installation)
		&& !OpenRevocableEmergencyEnrollment(*workspace, persisted->proof(), armed->operationTag, emergency),
		"completed landing cannot reopen and sibling rule bytes survive");
	const auto active = workspace->LoadCommitted();
	check(active && std::holds_alternative<PreparedRevocableEmergencyAdmission>(
		PrepareRevocableEmergencyAdmission(*active, MigrationController::NewTransactionId(),
			siblingPassword, {}, {})),
		"the unrelated selected-account rule still prepares with the new account present");
	if (!active) {
		return 1;
	}
	const auto transaction = MigrationController::NewTransactionId();
	const auto wideAdmission = PrepareRevocableEmergencyAdmission(*active, transaction, Credential(101, 102));
	const auto removalAdmission = PrepareRevocableEmergencyAdmission(
		*active, transaction, Credential(111, 112), resolvePackage);
	const auto coversRemainingAccounts = [&](const RevocableEmergencyAdmissionResult &admission) {
		const auto prepared = std::get_if<PreparedRevocableEmergencyAdmission>(&admission);
		if (!prepared) {
			return false;
		}
		const auto &accounts = prepared->checkpoint().journal.accounts;
		const auto enrolled = std::ranges::find_if(accounts, [&](const EA::JournalAccount &account) {
			return account.accountId == EA::AccountId(Hex(keyC.id));
		});
		return accounts.size() == 2 && enrolled != accounts.end()
			&& enrolled->remoteSessionTarget == EA::RemoteSessionTargetKind::None
			&& std::ranges::any_of(accounts, [&](const EA::JournalAccount &account) {
				return account.accountId == EA::AccountId(Hex(keyB.id));
			});
	};
	check(coversRemainingAccounts(wideAdmission),
		"original all-account password covers the remaining and newly enrolled accounts");
	const auto removal = std::get_if<PreparedRevocableEmergencyAdmission>(&removalAdmission);
	check(coversRemainingAccounts(removalAdmission) && removal
		&& removal->checkpoint().installationPackageDigest == Array(Filled(123)),
		"original installation password covers the new account and exact approved package");
	check(active && CommitRevocableProfileSetChange(*workspace, active->proof(), {
			.kind = ProfileSetChangeKind::Edit, .id = set, .name = u"Renamed"_q, .accounts = { keyB.id },
		}, admin, {}) == ProfileGenerationError::None,
		"renaming an unrelated set leaves authenticated emergency rules usable");
	const auto renamed = workspace->LoadCommitted();
	if (!renamed) {
		return 1;
	}
	const auto safeRename = ProfileSetChange{
		.kind = ProfileSetChangeKind::Edit, .id = kSafeId, .name = u"New safe name"_q,
	};
	check(renamed->revocableEmergencyRules == persisted->revocableEmergencyRules
		&& CommitRevocableProfileSetChange(*workspace, renamed->proof(),
			safeRename, admin, Credential(91, 92)) == ProfileGenerationError::SettingsRejected
		&& CommitRevocableProfileSetChange(*workspace, renamed->proof(),
			safeRename, admin, {}) == ProfileGenerationError::None,
		"changing fallback credentials requires review while a name-only edit keeps exact rules");
	const auto safeRenamed = LoadRevocableProfileGeneration(*workspace);
	auto afterRemoval = safeRenamed ? safeRenamed->vault.openMaster(admin) : std::nullopt;
	if (!afterRemoval) {
		return 1;
	}
	std::erase_if(afterRemoval->metadata.sets, [&](const AccountSet &entry) { return entry.id == futureSet; });
	const auto removed = safeRenamed->vault.updated(admin, afterRemoval->metadata, {});
	const auto afterRemovingSet = removed ? workspace->ReplaceRevocableCommitted(
		safeRenamed->proof, legacy->id, {
			{ MigrationArtifact::ProfileVault, removed->serialize() },
			{ MigrationArtifact::AccountGateTable, persisted->accountGateTable },
			{ MigrationArtifact::RevocableEmergencyRules, persisted->revocableEmergencyRules },
		}, yes) : std::nullopt;
	check(afterRemovingSet && workspace->RetireRevocableGenerations(afterRemovingSet->proof())
		&& !OpenRevocableEmergencyEnrollment(*workspace, afterRemovingSet->proof(),
			armed->operationTag, emergency),
		"deleting the enrolled set cannot reopen the completed landing");
	return failures ? 1 : 0;
}

} // namespace

int main(int argc, char *argv[]) {
	const auto application = QCoreApplication(argc, argv);
	return RunChecks();
}
