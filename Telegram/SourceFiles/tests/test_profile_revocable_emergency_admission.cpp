// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_emergency_admission.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_rebind.h"

#include <QtCore/QtEndian>

#include <cstdio>
#include <type_traits>

namespace {

using namespace Ayu::ProfileSets;
namespace EA = Ayu::EmergencyActions;

static_assert(!std::is_copy_constructible_v<PreparedRevocableEmergencyAdmission>);

template <typename Id>
std::string Hex(Id id) {
	auto bytes = QByteArray(16, Qt::Uninitialized);
	qToBigEndian(id.high, bytes.data());
	qToBigEndian(id.low, bytes.data() + 8);
	return bytes.toHex().toStdString();
}

EA::CredentialVerifier Filled(uint8_t value) {
	auto result = EA::CredentialVerifier();
	result.fill(value);
	return result;
}

QByteArray Array(std::span<const uint8_t> value) {
	return { reinterpret_cast<const char*>(value.data()), qsizetype(value.size()) };
}

struct Rule final {
	EA::EmergencyRuleDetails details;
	EA::CredentialVerifier key;
	EA::CredentialVerifier verifier;
	std::span<const RevocableEmergencyAccount> targets;
	std::optional<RevocableEmergencySafeSetView> safe;
	std::optional<EA::EmergencyExecutionCapsuleDigest> package;

	[[nodiscard]] DerivedCredential credential() const {
		return { Array(verifier), Array(key) };
	}
};

struct Bundle final {
	QByteArray bytes;
	std::vector<QByteArray> digests;
};

std::optional<Bundle> Arm(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::LiveInstallation &live,
		const AccountGateTable &gates,
		std::span<const Rule> rules) {
	auto config = EA::RuleConfiguration{
		.activeInstallationId = epoch.installationId,
		.masterVerifier = Filled(201),
	};
	for (const auto &entry : rules) {
		config.emergencyRules.push_back({
			.id = entry.details.actionId,
			.rule = entry.details.rule,
			.verifier = entry.verifier,
			.revision = entry.details.revision,
		});
	}
	auto bundle = RevocableProfileEmergencyBundle();
	auto inputs = std::vector<EA::EmergencyRuleSealInput>();
	auto result = Bundle();
	for (const auto &entry : rules) {
		const auto &rule = entry.details;
		const auto review = EA::PreviewEmergencyRule(config, rule.actionId, live, rule.operationId);
		const auto capability = SealRevocableEmergencyCapability(epoch, rule, live, gates,
			entry.targets, entry.safe, entry.package, entry.key);
		if (!review || !EA::ConfirmEmergencyRule(config, *review, live, true) || !capability) {
			return std::nullopt;
		}
		result.digests.push_back(Array(capability->digest));
		bundle.rules.capsules.emplace(result.digests.back(), Array(capability->bytes));
		inputs.push_back({ rule.actionId, rule.actionId.value, entry.verifier, entry.key, capability->digest });
	}
	const auto sealed = EA::SealEmergencyRules(epoch, Filled(202), config, live, inputs);
	if (!sealed) {
		return std::nullopt;
	}
	bundle.rules.authority = sealed->authority;
	bundle.rules.rules = Array(sealed->bytes);
	result.bytes = SerializeRevocableProfileEmergencyBundle(bundle);
	return result.bytes.isEmpty() ? std::nullopt : std::optional(std::move(result));
}

CommittedMigration Committed(const AccountGateTable &gates, const Bundle &bundle) {
	return {
		.transactionId = QByteArray(16, 't'),
		.profileVault = QByteArray("fixture verified V3 vault bytes"),
		.layout = MigrationGenerationLayout::RevocableGates,
		.installationId = gates.installationId(),
		.accountGateTable = SerializeAccountGateTable(gates),
		.revocableEmergencyRules = bundle.bytes,
		.manifestDigest = QByteArray(32, 'p'),
	};
}

} // namespace

int main() {
	auto failures = 0;
	const auto check = [&](bool pass, const char *label) {
		std::printf("%s %s\n", pass ? "PASS" : "FAIL", label);
		failures += !pass;
	};
	const auto install = QByteArray(16, 'i');
	const auto epoch = EA::EmergencyRuleGeneration{
		EA::InstallationId(install.toHex().toStdString()), std::string(32, 'a'),
	};
	const auto empty = AccountGateTable::Create(install);
	const auto keyA = AccountKey{ {1, 1}, QByteArray(32, 'A') };
	const auto keyB = AccountKey{ {1, 2}, QByteArray(32, 'B') };
	const auto keyC = AccountKey{ {1, 3}, QByteArray(32, 'C') };
	auto a = empty ? CreateAccountGate(*empty, keyA, QByteArray(16, 'a')) : std::nullopt;
	auto b = a ? CreateAccountGate(a->table, keyB, QByteArray(16, 'b')) : std::nullopt;
	auto c = b ? CreateAccountGate(b->table, keyC, QByteArray(16, 'c')) : std::nullopt;
	if (!c) {
		check(false, "synthetic gate rows created");
		return 1;
	}
	const auto &gates = c->table;
	const auto accounts = std::array{
		RevocableEmergencyAccount{ std::move(a->handle), std::move(a->permit),
			EA::EmergencyScopedRemoteIdentity{ 101, EA::EmergencyScopedEnvironment::Production } },
		RevocableEmergencyAccount{ std::move(b->handle), std::move(b->permit),
			EA::EmergencyScopedRemoteIdentity{ 102, EA::EmergencyScopedEnvironment::Test } },
		RevocableEmergencyAccount{ std::move(c->handle), std::move(c->permit),
			EA::EmergencyScopedRemoteIdentity{ 103, EA::EmergencyScopedEnvironment::Production } },
	};
	const auto idA = EA::AccountId(Hex(keyA.id));
	const auto idB = EA::AccountId(Hex(keyB.id));
	const auto idC = EA::AccountId(Hex(keyC.id));
	const auto safeSet = SetId{2, 1};
	const auto safeId = EA::ProfileId(Hex(safeSet));
	const auto safeVerifier = QByteArray(32, 'V');
	const auto safeKey = QByteArray(32, 'K');
	const auto live = EA::LiveInstallation{
		.id = epoch.installationId,
		.accounts = {
			{ idA, EA::SessionId("current"), { EA::SessionId("current"), EA::SessionId("771") } },
			{ idB, EA::SessionId("current"), { EA::SessionId("current"), EA::SessionId("772") } },
			{ idC, EA::SessionId("current"), { EA::SessionId("current") } },
		},
		.profiles = { { safeId, { idC } } },
	};
	const auto rules = std::array{
		Rule{
			.details = {
				.actionId = EA::EmergencyActionId("reset-alpha"),
				.rule = {
					.id = EA::RuleId("alpha"), .installationId = epoch.installationId,
					.selectedAccountIds = { idA },
					.remoteSessionPolicies = { { idA, EA::RemoteSessionTargetKind::SelectedSessions, { EA::SessionId("771") } } },
					.safeProfileId = safeId,
				},
				.operationId = EA::OperationId("operation-alpha"), .revision = 7,
			},
			.key = Filled(11), .verifier = Filled(21), .targets = std::span(accounts).first(1),
			.safe = RevocableEmergencySafeSetView{ safeSet, safeVerifier, safeKey },
		},
		Rule{
			.details = {
				.actionId = EA::EmergencyActionId("reset-beta"),
				.rule = {
					.id = EA::RuleId("beta"), .installationId = epoch.installationId,
					.selectedAccountIds = { idB },
				},
				.operationId = EA::OperationId("operation-beta"), .revision = 8,
			},
			.key = Filled(12), .verifier = Filled(22), .targets = std::span(accounts).subspan(1, 1),
		},
	};
	const auto bundle = Arm(epoch, live, gates, rules);
	if (!bundle) {
		check(false, "independent stable-epoch V3 rules armed");
		return 1;
	}
	const auto active = Committed(gates, *bundle);
	const auto next = QByteArray(16, 'n');
	const auto invalid = [](const auto &result) {
		return std::holds_alternative<InvalidRevocableEmergencyAdmission>(result);
	};
	auto packageCalls = 0;
	const auto neverPackage = [&](const EA::InstallationId&) -> std::optional<EA::EmergencyExecutionCapsuleDigest> {
		++packageCalls;
		return std::nullopt;
	};
	auto namedCalls = 0;
	const auto names = EA::ScopedWebviewStoreIds{ EA::ScopedWebviewStoreId{ 9, 7 } };
	const auto named = [&](const AccountKey &key, const AccountGateBinding &binding,
			const EA::EmergencyScopedRemoteIdentity &identity) -> std::optional<EA::ScopedWebviewStoreIds> {
		++namedCalls;
		return key == keyA && binding == accounts[0].handle.binding() && identity.userId == 101
			? std::optional(names) : std::nullopt;
	};
	const auto wrong = DerivedCredential{ Array(Filled(41)), Array(Filled(51)) };
	check(std::holds_alternative<EA::WrongPasscode>(
		PrepareRevocableEmergencyAdmission(active, next, wrong, neverPackage, named))
		&& !packageCalls && !namedCalls, "wrong credential does not resolve package or inspect named stores");
	const auto admission = PrepareRevocableEmergencyAdmission(active, next, rules[0].credential(), neverPackage, named);
	const auto prepared = std::get_if<PreparedRevocableEmergencyAdmission>(&admission);
	if (!prepared) {
		check(false, "selected-account V3 admission prepared");
		return 1;
	}
	const auto checkpoint = ParseRevocableEmergencyCheckpoint(install, next,
		prepared->gateTable(), prepared->rules(), prepared->receipt());
	check(prepared->sourceProof() == active.proof() && prepared->nextTransactionId() == next
		&& checkpoint && checkpoint->accounts.size() == 1 && checkpoint->accounts[0].accountId == idA
		&& checkpoint->accounts[0].namedWebviewStores == names && namedCalls == 1 && !packageCalls,
		"prepared admission is tied to current CAS proof and checks exact successor bytes");
	const auto remote = prepared->remoteAccounts();
	check(remote.size() == 1 && remote[0].accountId == idA && remote[0].key == keyA
		&& remote[0].binding == accounts[0].handle.binding() && remote[0].identity.userId == 101
		&& prepared->safeSet() && prepared->safeSet()->id == safeSet && prepared->safeSet()->credential.key == safeKey,
		"remote account custody and exact safe credential remain in move-only prepared memory");
	check(!prepared->receipt().contains(keyA.key) && !prepared->gateTable().contains(keyA.key)
		&& !prepared->rules().contains(keyA.key) && !prepared->receipt().contains(safeKey)
		&& !prepared->rules().contains(safeKey), "persisted artifacts contain neither raw account keys nor safe credential");
	const auto updated = ParseAccountGateTable(prepared->gateTable(), install);
	const auto updatedRules = ParseRevocableProfileEmergencyBundle(install, prepared->rules());
	check(updated && updatedRules && updatedRules->consumed == std::set{ bundle->digests[0] }
		&& updatedRules->rules.capsules.contains(bundle->digests[1])
		&& updatedRules->rules.authority.generation == epoch
		&& InspectAccountGate(*updated, accounts[0].handle) == AccountGateStatus::Revoked
		&& InspectAccountGate(*updated, accounts[1].handle) == AccountGateStatus::Active
		&& InspectAccountGate(*updated, accounts[2].handle) == AccountGateStatus::Active,
		"successor revokes only the chosen gate and consumes only its exact capability digest");
	auto advanced = active;
	advanced.accountGateTable = prepared->gateTable();
	const auto stale = PrepareRevocableEmergencyAdmission(advanced, next, rules[0].credential());
	const auto revoked = std::get_if<RevokedRevocableEmergencyTargets>(&stale);
	check(revoked && revoked->accounts == std::vector{ keyA.id },
		"unconsumed authentic rule over an already revoked gate cannot reopen its key");
	advanced.revocableEmergencyRules = prepared->rules();
	check(std::holds_alternative<ConsumedRevocableEmergencyAdmission>(
		PrepareRevocableEmergencyAdmission(advanced, next, rules[0].credential()))
		&& std::holds_alternative<PreparedRevocableEmergencyAdmission>(
			PrepareRevocableEmergencyAdmission(advanced, next, rules[1].credential())),
		"consumed credential is inert and a different exact rule still prepares under the same epoch");
	auto pending = active;
	pending.retirementPending = true;
	check(invalid(PrepareRevocableEmergencyAdmission(pending, next, rules[0].credential(), neverPackage, named))
		&& invalid(PrepareRevocableEmergencyAdmission(active, active.transactionId, rules[0].credential()))
		&& namedCalls == 1, "pending retirement and reused transaction IDs refuse a second admission");
	auto absent = active;
	absent.revocableEmergencyRules.clear();
	check(invalid(PrepareRevocableEmergencyAdmission(absent, next, rules[0].credential())),
		"absent sealed rules cannot authorize admission");
	check(invalid(PrepareRevocableEmergencyAdmission(active, next, rules[0].credential(), {},
		[](const auto&, const auto&, const auto&) -> std::optional<EA::ScopedWebviewStoreIds> { return std::nullopt; })),
		"unavailable named-store proof cannot publish a partial checkpoint");
	auto reviewed = live;
	reviewed.accounts.pop_back();
	reviewed.profiles.clear();
	auto all = rules[0];
	all.details.actionId = EA::EmergencyActionId("reset-all");
	all.details.operationId = EA::OperationId("operation-all");
	all.details.rule.id = EA::RuleId("all");
	all.details.rule.targetScope = EA::TargetScope::AllAccounts;
	all.details.rule.selectedAccountIds.clear();
	all.details.rule.safeProfileId = {};
	all.details.rule.remoteSessionPolicies.push_back({ idB,
		EA::RemoteSessionTargetKind::SelectedSessions, { EA::SessionId("772") } });
	all.key = Filled(13);
	all.verifier = Filled(23);
	all.targets = std::span(accounts).first(2);
	all.safe = std::nullopt;
	const auto allBundle = Arm(epoch, reviewed, gates, std::span(&all, 1));
	const auto removedC = RevokeAccountGates(gates, std::span(&accounts[2].permit, 1));
	check(allBundle && removedC
		&& invalid(PrepareRevocableEmergencyAdmission(Committed(gates, *allBundle), next, all.credential()))
		&& std::holds_alternative<PreparedRevocableEmergencyAdmission>(
			PrepareRevocableEmergencyAdmission(Committed(*removedC, *allBundle), next, all.credential())),
		"all-account scope refuses an unreviewed live gate but accepts an unrelated tombstone");
	auto selectedA = rules[0];
	selectedA.details.rule.safeProfileId = {};
	selectedA.safe = std::nullopt;
	const auto chain = std::array{ selectedA, all };
	const auto chainBundle = Arm(epoch, reviewed, b->table, chain);
	if (chainBundle) {
		auto current = Committed(b->table, *chainBundle);
		const auto firstResult = PrepareRevocableEmergencyAdmission(current, next, selectedA.credential());
		const auto first = std::get_if<PreparedRevocableEmergencyAdmission>(&firstResult);
		if (!first) {
			check(false, "selected reset authenticates first account in two-rule sequence");
			return 1;
		}
		current.transactionId = next;
		current.manifestDigest = QByteArray(32, 's');
		current.accountGateTable = first->gateTable();
		current.revocableEmergencyRules = first->rules();
		const auto nextAll = QByteArray(16, 'o');
		auto resolved = std::vector<AccountId>();
		const auto resolveRemaining = [&](const AccountKey &key, const AccountGateBinding &binding,
				const EA::EmergencyScopedRemoteIdentity &identity) -> std::optional<EA::ScopedWebviewStoreIds> {
			resolved.push_back(key.id);
			return key == keyB && binding == accounts[1].handle.binding() && identity.userId == 102
				? std::optional(names) : std::nullopt;
		};
		const auto secondResult = PrepareRevocableEmergencyAdmission(current, nextAll, all.credential(), {}, resolveRemaining);
		const auto second = std::get_if<PreparedRevocableEmergencyAdmission>(&secondResult);
		const auto finalGates = second ? ParseAccountGateTable(second->gateTable(), install) : std::nullopt;
		const auto finalRules = second ? ParseRevocableProfileEmergencyBundle(install, second->rules()) : std::nullopt;
		check(second && second->sourceProof() == current.proof()
			&& second->checkpoint().journal.targetScope == EA::TargetScope::AllAccounts
			&& second->checkpoint().accounts.size() == 1
			&& second->checkpoint().accounts.front().accountId == idB
			&& second->checkpoint().accounts.front().namedWebviewStores == names
			&& second->checkpoint().journal.accounts.front().sessionIdsForRevoke == std::vector{ EA::SessionId("772") }
			&& second->remoteAccounts().size() == 1 && second->remoteAccounts().front().key == keyB
			&& resolved == std::vector{ keyB.id } && finalGates && finalGates->coversActiveBindings({})
			&& InspectAccountGate(*finalGates, accounts[0].handle) == AccountGateStatus::Revoked
			&& InspectAccountGate(*finalGates, accounts[1].handle) == AccountGateStatus::Revoked
			&& finalRules && finalRules->consumed == std::set(chainBundle->digests.begin(), chainBundle->digests.end()),
			"independent all-account rule resets only B after selected reset of A");
		const auto afterSelected = ParseAccountGateTable(current.accountGateTable, install);
		const auto enrolled = afterSelected
			? CreateAccountGate(*afterSelected, keyC, accounts[2].handle.binding().locator)
			: std::nullopt;
		if (enrolled) {
			current.accountGateTable = SerializeAccountGateTable(enrolled->table);
			check(invalid(PrepareRevocableEmergencyAdmission(current, nextAll, all.credential(), {}, resolveRemaining))
				&& resolved == std::vector{ keyB.id },
				"new enrollment blocks narrowed all-account rule before any key reaches a resolver");
		} else {
			check(false, "synthetic unreviewed enrollment");
		}
	} else {
		check(false, "independent selected and all-account rules armed together");
	}
	auto removalRule = all;
	removalRule.details.rule.action = EA::EmergencyAction::RemoveInstallation;
	removalRule.details.rule.targetScope = EA::TargetScope::CurrentInstallation;
	removalRule.targets = accounts;
	removalRule.package = Filled(71);
	const auto removalBundle = Arm(epoch, live, gates, std::span(&removalRule, 1));
	if (removalBundle) {
		const auto installActive = Committed(gates, *removalBundle);
		const auto package = [&](const EA::InstallationId &owner) {
			++packageCalls;
			return owner == epoch.installationId ? removalRule.package : std::nullopt;
		};
		check(std::holds_alternative<EA::WrongPasscode>(PrepareRevocableEmergencyAdmission(installActive, next, wrong, package))
			&& !packageCalls, "removal package resolver waits for an authenticated removal rule");
		const auto removal = PrepareRevocableEmergencyAdmission(installActive, next, removalRule.credential(), package);
		const auto ready = std::get_if<PreparedRevocableEmergencyAdmission>(&removal);
		check(ready && ready->checkpoint().installationPackageDigest == Array(*removalRule.package)
			&& ready->checkpoint().accounts.size() == 3 && packageCalls == 1
			&& invalid(PrepareRevocableEmergencyAdmission(installActive, next, removalRule.credential(),
				[](const EA::InstallationId&) { return std::optional(Filled(99)); })),
			"removal checkpoint pins the exact independently verified package and all current gates");
		if (removedC) {
			const auto remaining = Committed(*removedC, *removalBundle);
			const auto narrowed = PrepareRevocableEmergencyAdmission(remaining, next, removalRule.credential(), package);
			const auto targets = std::get_if<PreparedRevocableEmergencyAdmission>(&narrowed);
			const auto extra = CreateAccountGate(*removedC, AccountKey{ {1, 4}, QByteArray(32, 'D') },
				QByteArray(16, 'd'));
			check(targets && targets->checkpoint().installationPackageDigest == Array(*removalRule.package)
				&& targets->checkpoint().accounts.size() == 2
				&& targets->checkpoint().accounts[0].accountId == idA && targets->checkpoint().accounts[1].accountId == idB
				&& extra && invalid(PrepareRevocableEmergencyAdmission(Committed(extra->table, *removalBundle),
					next, removalRule.credential(), package)),
				"installation removal permits exact remaining targets and refuses next enrollments");
		} else {
			check(false, "synthetic partial removal gates");
		}
	} else {
		check(false, "synthetic installation removal rule armed");
	}
	auto reviewedRemoval = removalRule;
	reviewedRemoval.details.actionId = EA::EmergencyActionId("remove-package");
	reviewedRemoval.details.operationId = EA::OperationId("operation-remove");
	reviewedRemoval.details.rule.id = EA::RuleId("remove");
	reviewedRemoval.key = Filled(14);
	reviewedRemoval.verifier = Filled(24);
	reviewedRemoval.targets = std::span(accounts).first(2);
	const auto beforeEnrollRules = std::array{ selectedA, rules[1], all, reviewedRemoval };
	const auto beforeEnrollBundle = Arm(epoch, reviewed, b->table, beforeEnrollRules);
	if (!beforeEnrollBundle) {
		check(false, "enrollment regression rules armed");
		return 1;
	}
	const auto revokeFirst = PrepareRevocableEmergencyAdmission(Committed(b->table, *beforeEnrollBundle),
		next, selectedA.credential());
	const auto firstRevoked = std::get_if<PreparedRevocableEmergencyAdmission>(&revokeFirst);
	const auto enrollmentGates = firstRevoked ? ParseAccountGateTable(firstRevoked->gateTable(), install) : std::nullopt;
	const auto newlyEnrolled = enrollmentGates ? CreateAccountGate(*enrollmentGates, keyC, QByteArray(16, 'c')) : std::nullopt;
	if (!firstRevoked || !newlyEnrolled) {
		check(false, "enrollment uses exact current gates including a previously revoked account");
		return 1;
	}
	const auto admin = DerivedCredential{ Array(Filled(201)), Array(Filled(202)) };
	auto master = RevocableAdminVaultAccess{ .metadata = {
		.verifierSalt = QByteArray(32, 's'),
		.masterVerifier = admin.verifier,
		.sets = { { {2, 1}, QString::fromLatin1("Reviewed"), Array(Filled(31)), { keyA.id, keyB.id } } },
	} };
	for (const auto &account : std::span(accounts).first(2)) {
		master.accounts.push_back({ std::move(*AccountGateHandle::Parse(account.handle.serialize())),
			std::move(*AccountGateRevocationPermit::Parse(account.permit.serialize())) });
	}
	auto enrolledMetadata = master.metadata;
	enrolledMetadata.sets.push_back({ {2, 2}, QString::fromLatin1("New"), Array(Filled(32)), { keyC.id } });
	const auto newIdentity = EA::EmergencyScopedRemoteIdentity{ 103, EA::EmergencyScopedEnvironment::Production };
	const auto resolveExact = [&](const EA::InstallationId &id) {
		return id == epoch.installationId ? reviewedRemoval.package : std::nullopt;
	};
	const auto rebind = [&](const ResolveRevocableEmergencyPackage &resolve, const Metadata &after,
			std::optional<EA::EmergencyScopedRemoteIdentity> identity = std::nullopt) {
		return RebindRevocableEmergencyRulesForEnrollment(firstRevoked->rules(), admin, master,
			after, *enrollmentGates, *newlyEnrolled, identity.value_or(newIdentity), resolve);
	};
	const auto rebound = rebind(resolveExact, enrolledMetadata);
	const auto encapsulated = rebound ? ParseRevocableProfileEmergencyBundle(install, *rebound) : std::nullopt;
	const auto priorEncapsulated = ParseRevocableProfileEmergencyBundle(install, firstRevoked->rules());
	const auto &digests = beforeEnrollBundle->digests;
	check(encapsulated && priorEncapsulated && encapsulated->rules.authority.generation == epoch
		&& encapsulated->consumed == priorEncapsulated->consumed && encapsulated->landings == priorEncapsulated->landings
		&& encapsulated->rules.capsules.size() == priorEncapsulated->rules.capsules.size()
		&& encapsulated->rules.capsules.contains(digests[1])
		&& encapsulated->rules.capsules.at(digests[1]) == priorEncapsulated->rules.capsules.at(digests[1])
		&& !encapsulated->rules.capsules.contains(digests[2]) && !encapsulated->rules.capsules.contains(digests[3]),
		"enrollment replaces only active wide capabilities under the same epoch and preserves selected and consumed records");
	if (rebound) {
		const auto postEnroll = Committed(newlyEnrolled->table, Bundle{ .bytes = *rebound });
		const auto decision = PrepareRevocableEmergencyAdmission(postEnroll, next, all.credential());
		const auto wide = std::get_if<PreparedRevocableEmergencyAdmission>(&decision);
		const auto keepSelected = PrepareRevocableEmergencyAdmission(postEnroll, next, rules[1].credential());
		const auto selected = std::get_if<PreparedRevocableEmergencyAdmission>(&keepSelected);
		check(wide && wide->checkpoint().journal.operationId == all.details.operationId
			&& wide->checkpoint().journal.accounts.size() == 2
			&& wide->checkpoint().journal.accounts[0].accountId == idB
			&& wide->checkpoint().journal.accounts[0].sessionIdsForRevoke == std::vector{ EA::SessionId("772") }
			&& wide->checkpoint().journal.accounts[1].accountId == idC
			&& wide->checkpoint().journal.accounts[1].remoteSessionTarget == EA::RemoteSessionTargetKind::None
			&& wide->checkpoint().journal.accounts[1].currentSessionLogout.state == EA::EffectState::Pending
			&& wide->remoteAccounts().size() == 2
			&& wide->remoteAccounts()[1].identity.userId == newIdentity.userId
			&& wide->remoteAccounts()[1].identity.environment == newIdentity.environment
			&& selected && selected->checkpoint().accounts.size() == 1 && selected->checkpoint().accounts[0].accountId == idB,
			"original passwords prepare exact rebound targets: former tombstone excluded and new account has current-session logout only");
		const auto uninstall = PrepareRevocableEmergencyAdmission(postEnroll, next, reviewedRemoval.credential(), resolveExact);
		const auto removal = std::get_if<PreparedRevocableEmergencyAdmission>(&uninstall);
		check(removal && removal->checkpoint().journal.operationId == reviewedRemoval.details.operationId
			&& removal->checkpoint().installationPackageDigest == Array(*reviewedRemoval.package)
			&& removal->checkpoint().accounts.size() == 2 && removal->checkpoint().accounts[1].accountId == idC,
			"rebound installation rule keeps its exact package and operation ID");
	}
	auto collidingMetadata = enrolledMetadata;
	collidingMetadata.sets.back().verifier = Array(all.verifier);
	check(!rebind({}, enrolledMetadata) && !rebind(resolveExact, collidingMetadata)
		&& !rebind([](const EA::InstallationId&) { return std::optional(Filled(99)); }, enrolledMetadata),
		"verified package and normal passcode collision lock enrollment rebind fail closed");
	const auto reenrolled = rebind(resolveExact, enrolledMetadata, accounts[0].remoteIdentity);
	if (reenrolled) {
		const auto reenrolledGeneration = Committed(newlyEnrolled->table, Bundle{ .bytes = *reenrolled });
		const auto result = PrepareRevocableEmergencyAdmission(reenrolledGeneration, next, all.credential());
		const auto ready = std::get_if<PreparedRevocableEmergencyAdmission>(&result);
		check(ready && ready->remoteAccounts().size() == 2
			&& ready->remoteAccounts()[1].accountId == idC
			&& ready->remoteAccounts()[1].identity.userId == accounts[0].remoteIdentity->userId
			&& !rebind(resolveExact, enrolledMetadata, accounts[1].remoteIdentity),
			"reenrolling the user of a tombstone stays safe while duplicating a live identity is rejected");
	} else {
		check(false, "reenrollment of a tombstoned Telegram identity is allowed");
	}
	const auto emptyLive = EA::LiveInstallation{ .id = epoch.installationId };
	removalRule.targets = {};
	const auto emptyBundle = Arm(epoch, emptyLive, *empty, std::span(&removalRule, 1));
	if (emptyBundle) {
		const auto emptyActive = Committed(*empty, *emptyBundle);
		const auto removal = PrepareRevocableEmergencyAdmission(emptyActive, next,
			removalRule.credential(), [&](const EA::InstallationId&) { return removalRule.package; });
		const auto ready = std::get_if<PreparedRevocableEmergencyAdmission>(&removal);
		check(ready && ready->gateTable() == emptyActive.accountGateTable
			&& ready->checkpoint().accounts.empty() && ready->remoteAccounts().empty(),
			"approved installation removal can start with an empty verified gate table");
	} else {
		check(false, "account-free installation removal rule armed");
	}
	return failures ? 1 : 0;
}
