// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_emergency_capability.h"

#include "ayu/features/emergency_actions/emergency_rule_vault.h"

#include <QtCore/QtEndian>

#include <algorithm>
#include <cstdio>

namespace {

namespace EA = Ayu::EmergencyActions;
using namespace Ayu::ProfileSets;

template <typename Id>
std::string IdHex(Id id) {
	auto bytes = QByteArray(16, Qt::Uninitialized);
	qToBigEndian(id.high, bytes.data());
	qToBigEndian(id.low, bytes.data() + 8);
	return bytes.toHex().toStdString();
}

EA::CredentialVerifier FixtureBytes(uint8_t byte) {
	auto result = EA::CredentialVerifier();
	result.fill(byte);
	return result;
}

std::optional<EA::EmergencyRuleTicket> Ticket(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::EmergencyRuleDetails &details,
		const EA::LiveInstallation &live,
		const EA::EmergencyExecutionCapsuleDigest &digest,
		const EA::CredentialVerifier &key,
		EA::SealedEmergencyRules *sealed = nullptr) {
	const auto verifier = FixtureBytes(0x51);
	const auto masterKey = FixtureBytes(0x52);
	auto config = EA::RuleConfiguration{
		.activeInstallationId = epoch.installationId,
		.masterVerifier = FixtureBytes(0x53),
		.emergencyRules = {{
			.id = details.actionId,
			.rule = details.rule,
			.verifier = verifier,
			.revision = details.revision,
		}},
	};
	const auto preview = EA::PreviewEmergencyRule(config, details.actionId, live, details.operationId);
	if (!preview || !EA::ConfirmEmergencyRule(config, *preview, live, true)) {
		return std::nullopt;
	}
	const auto entries = std::array{ EA::EmergencyRuleSealInput{
		.actionId = details.actionId,
		.name = "Fixture capability",
		.verifier = verifier,
		.key = key,
		.executionCapsuleDigest = digest,
	} };
	const auto rules = EA::SealEmergencyRules(epoch, masterKey, config, live, entries);
	if (!rules) {
		return std::nullopt;
	}
	auto auth = EA::AuthenticateEmergencyRule(rules->authority, rules->bytes, key);
	const auto ticket = std::get_if<EA::EmergencyRuleTicket>(&auth);
	if (ticket && sealed) {
		*sealed = *rules;
	}
	return ticket ? std::optional(std::move(*ticket)) : std::nullopt;
}

} // namespace

int main() {
	auto failures = 0;
	const auto check = [&](bool valid, const char *message) {
		std::printf("%s %s\n", valid ? "PASS" : "FAIL", message);
		failures += !valid;
	};
	const auto install = QByteArray(16, 'i');
	const auto epoch = EA::EmergencyRuleGeneration{
		EA::InstallationId(install.toHex().toStdString()), std::string(32, 'a'),
	};
	const auto localAlpha = AccountKey{ AccountId{1, 1}, QByteArray(32, 'A') };
	const auto localBeta = AccountKey{ AccountId{1, 2}, QByteArray(32, 'B') };
	const auto table = AccountGateTable::Create(install);
	auto alpha = table ? CreateAccountGate(*table, localAlpha, QByteArray(16, 'a')) : std::nullopt;
	auto beta = alpha ? CreateAccountGate(alpha->table, localBeta, QByteArray(16, 'b')) : std::nullopt;
	if (!alpha || !beta) {
		check(false, "synthetic independent gate tables");
		return 1;
	}
	const auto &gates = beta->table;
	const auto alphaId = EA::AccountId(IdHex(localAlpha.id));
	const auto betaId = EA::AccountId(IdHex(localBeta.id));
	const auto safeAccount = EA::AccountId(IdHex(AccountId{1, 3}));
	const auto safe = SetId{2, 1};
	const auto safeProfile = EA::ProfileId(IdHex(safe));
	const auto live = EA::LiveInstallation{
		.id = epoch.installationId,
		.accounts = {
			{ alphaId, EA::SessionId("current"), { EA::SessionId("current"), EA::SessionId("421") } },
			{ betaId, EA::SessionId("current"), { EA::SessionId("current") } },
			{ safeAccount, EA::SessionId("current"), { EA::SessionId("current") } },
		},
		.profiles = { { safeProfile, { safeAccount } } },
	};
	const auto details = EA::EmergencyRuleDetails{
		.actionId = EA::EmergencyActionId("fixture-action"),
		.rule = {
			.id = EA::RuleId("fixture-rule"), .installationId = epoch.installationId,
			.action = EA::EmergencyAction::ResetAccountData, .targetScope = EA::TargetScope::SelectedAccounts,
			.selectedAccountIds = { alphaId, betaId },
			.remoteSessionPolicies = { { alphaId, EA::RemoteSessionTargetKind::SelectedSessions, { EA::SessionId("421") } } },
			.safeProfileId = safeProfile,
		},
		.operationId = EA::OperationId("fixture-operation"), .revision = 1,
	};
	const auto key = FixtureBytes(0x42);
	const auto verifier = QByteArray(32, 'v');
	const auto safeKey = QByteArray(32, 's');
	const auto safeGrant = RevocableEmergencySafeSetView{ safe, verifier, safeKey };
	const auto accounts = std::array{
		RevocableEmergencyAccount{ std::move(beta->handle), std::move(beta->permit), std::nullopt },
		RevocableEmergencyAccount{ std::move(alpha->handle), std::move(alpha->permit),
			EA::EmergencyScopedRemoteIdentity{ 123, EA::EmergencyScopedEnvironment::Test } },
	};
	const auto seal = [&] {
		return SealRevocableEmergencyCapability(epoch, details, live, gates, accounts, safeGrant, {}, key);
	};
	const auto sealed = seal();
	auto masterRules = EA::SealedEmergencyRules();
	const auto ticket = sealed ? Ticket(epoch, details, live, sealed->digest, key, &masterRules) : std::nullopt;
	if (!ticket) {
		check(false, "V3 fixture safely seals and authenticates through the current rule ticket");
		return 1;
	}
	const auto invalid = [](const auto &value) {
		return std::holds_alternative<InvalidRevocableEmergencyCapability>(value);
	};
	const auto open = [&](const AccountGateTable &current) {
		return OpenRevocableEmergencyCapability(epoch, *ticket, current, sealed->bytes, {}, key);
	};
	auto opened = open(gates);
	const auto clear = std::get_if<OpenedRevocableEmergencyCapability>(&opened);
	check(clear && clear->accounts().size() == 2 && clear->accounts()[0].handle.binding().id == localAlpha.id
		&& clear->accounts()[0].handle.matches(clear->accounts()[0].permit)
		&& clear->accounts()[0].remoteIdentity->userId == 123
		&& clear->accounts()[1].handle.binding().id == localBeta.id
		&& clear->safeSet() && clear->safeSet()->id == safe && clear->safeSet()->verifier == verifier
		&& clear->safeSet()->key == safeKey && !clear->packageDigest()
		&& clear->plan().accounts[0].sessionIdsForRevokeRequest == std::vector{ EA::SessionId("421") },
		"authenticated V3 opening returns canonical typed targets and exact optional safe set");
	const auto expectedMasterKey = FixtureBytes(0x52);
	auto sharedKey = EA::CredentialVerifier();
	const auto keyDerived = EA::details::DeriveRebindableEmergencyCapsuleKey(key, sharedKey);
	auto directions = false;
	const auto unchanged = EA::RewriteEmergencyRulesForMaster(masterRules.authority, masterRules.bytes,
		{ expectedMasterKey, FixtureBytes(0x53), {} },
		[&](const EA::EmergencyRuleTicket &current, EA::EmergencyExecutionCapsuleKey masterKey)
		-> EA::EmergencyRuleRewriteDecision {
			const auto fromRaw = OpenRevocableEmergencyCapabilityForRebind(
				epoch, current, gates, sealed->bytes, {}, masterKey);
			const auto fromMaster = SealRevocableEmergencyCapabilityForRebind(
				epoch, details, live, gates, accounts, safeGrant, {}, masterKey);
			const auto newTicket = fromMaster ? Ticket(epoch, details, live, fromMaster->digest, key) : std::nullopt;
			directions = keyDerived && std::ranges::equal(masterKey, sharedKey) && newTicket
				&& std::holds_alternative<OpenedRevocableEmergencyCapability>(fromRaw)
				&& std::holds_alternative<OpenedRevocableEmergencyCapability>(OpenRevocableEmergencyCapability(
					epoch, *newTicket, gates, fromMaster->bytes, {}, key));
			return EA::KeepEmergencyRule();
		});
	check(unchanged && directions && unchanged->bytes == masterRules.bytes,
		"raw and master-derived V3 capability keys interoperate in both directions");
	const auto v3WithoutDomain = SealRevocableEmergencyCapabilityForRebind(
		epoch, details, live, gates, accounts, safeGrant, {}, key);
	const auto domainTicket = v3WithoutDomain ? Ticket(epoch, details, live, v3WithoutDomain->digest, key) : std::nullopt;
	check(domainTicket && invalid(OpenRevocableEmergencyCapability(
			epoch, *domainTicket, gates, v3WithoutDomain->bytes, {}, key))
		&& invalid(OpenRevocableEmergencyCapabilityForRebind(epoch, *ticket, gates, sealed->bytes, {}, key)),
		"raw credential cannot stand in for a domain-separated V3 rebind key");
	const auto again = seal();
	check(again && again->bytes != sealed->bytes && again->digest != sealed->digest
		&& std::ranges::equal(kRevocableEmergencyCapabilityMagic,
			std::span(sealed->bytes).first(kRevocableEmergencyCapabilityMagic.size())),
		"sealing uses distinct randomized envelopes under the published V3 prefix");
	auto damaged = sealed->bytes;
	damaged.back() ^= 1;
	check(invalid(OpenRevocableEmergencyCapability(epoch, *ticket, gates, damaged, {}, key))
		&& invalid(OpenRevocableEmergencyCapability(epoch, *ticket, gates, sealed->bytes, {}, FixtureBytes(0x43)))
		&& invalid(OpenRevocableEmergencyCapability(epoch, *ticket, gates, std::span(sealed->bytes).first(10), {}, key)),
		"ciphertext tampering, wrong credential and short frames fail closed");
	check(again && invalid(OpenRevocableEmergencyCapability(epoch, *ticket, gates, again->bytes, {}, key)),
		"the ticket digest pins the exact encrypted capability");
	auto next = epoch;
	next.transactionId = std::string(32, 'b');
	const auto nextTicket = Ticket(next, details, live, sealed->digest, key);
	check(nextTicket && invalid(OpenRevocableEmergencyCapability(next, *nextTicket, gates, sealed->bytes, {}, key))
		&& invalid(OpenRevocableEmergencyCapability(next, *ticket, gates, sealed->bytes, {}, key)),
		"independent and authenticated rule epochs cannot substitute one another");
	for (auto change = 0; change != 3; ++change) {
		auto modified = details;
		if (change == 0) ++modified.revision;
		if (change == 1) modified.actionId = EA::EmergencyActionId("another-action");
		if (change == 2) modified.operationId = EA::OperationId("another-operation");
		const auto changed = Ticket(epoch, modified, live, sealed->digest, key);
		check(changed && invalid(OpenRevocableEmergencyCapability(epoch, *changed, gates, sealed->bytes, {}, key)),
			"authenticated revision, action ID and operation ID are bound to the ciphertext");
	}
	auto changedLive = live;
	changedLive.profiles.front().accountIds.clear();
	const auto changedMembership = Ticket(epoch, details, changedLive, sealed->digest, key);
	check(changedMembership && invalid(OpenRevocableEmergencyCapability(epoch, *changedMembership, gates, sealed->bytes, {}, key)),
		"safe-set membership is bound independently of its ID");
	auto changedScope = details;
	changedScope.rule.remoteSessionPolicies.front().kind = EA::RemoteSessionTargetKind::AllOtherSessions;
	changedScope.rule.remoteSessionPolicies.front().selectedSessionIds.clear();
	const auto broadened = Ticket(epoch, changedScope, live, sealed->digest, key);
	changedScope = details;
	changedScope.rule.selectedAccountIds.back() = safeAccount;
	const auto substituted = Ticket(epoch, changedScope, changedLive, sealed->digest, key);
	check(broadened && invalid(OpenRevocableEmergencyCapability(epoch, *broadened, gates, sealed->bytes, {}, key))
		&& substituted && invalid(OpenRevocableEmergencyCapability(epoch, *substituted, gates, sealed->bytes, {}, key)),
		"authenticated tickets cannot substitute an account or broaden its remote logout scope");
	changedLive.profiles.front().accountIds = { alphaId };
	check(!SealRevocableEmergencyCapability(epoch, details, changedLive, gates, accounts, safeGrant, {}, key)
		&& !SealRevocableEmergencyCapability(epoch, details, live, gates, accounts,
			RevocableEmergencySafeSetView{ SetId{4, 4}, verifier, safeKey }, {}, key),
		"overlapping or substituted safe sets cannot be sealed");
	const auto badPair = std::array{
		RevocableEmergencyAccount{ std::move(*AccountGateHandle::Parse(accounts[0].handle.serialize())),
			std::move(*AccountGateRevocationPermit::Parse(accounts[1].permit.serialize())), std::nullopt },
		RevocableEmergencyAccount{ std::move(*AccountGateHandle::Parse(accounts[1].handle.serialize())),
			std::move(*AccountGateRevocationPermit::Parse(accounts[1].permit.serialize())), accounts[1].remoteIdentity },
	};
	check(!SealRevocableEmergencyCapability(epoch, details, live, gates, badPair, safeGrant, {}, key)
		&& !SealRevocableEmergencyCapability(epoch, details, live, gates, std::span(accounts).first(1), safeGrant, {}, key),
		"mismatched permits and incomplete target lists cannot be sealed");
	const auto revoked = RevokeAccountGates(gates, std::span(&accounts[1].permit, 1));
	const auto missing = RevokeAccountGates(alpha->table, std::span(&accounts[1].permit, 1));
	if (revoked) {
		const auto result = open(*revoked);
		const auto effective = std::get_if<OpenedRevocableEmergencyCapability>(&result);
		check(clear && effective && effective->accounts().size() == 1
			&& effective->accounts().front().handle.binding().id == localBeta.id
			&& effective->accounts().front().handle.matches(effective->accounts().front().permit)
			&& effective->plan().accounts == std::vector{ clear->plan().accounts[1] }
			&& effective->safeSet() && effective->safeSet()->id == safe
			&& effective->safeSet()->verifier == verifier && effective->safeSet()->key == safeKey,
			"selected rule shrinks only authenticated tombstones and retains the exact safe set");
		const auto noTargets = RevokeAccountGates(*revoked, std::span(&accounts[0].permit, 1));
		if (noTargets) {
			const auto stale = open(*noTargets);
			const auto already = std::get_if<RevokedRevocableEmergencyTargets>(&stale);
			check(already && already->accounts == std::vector{ localAlpha.id, localBeta.id },
				"fully revoked selected rule is stale and exposes no handles");
		} else {
			check(false, "synthetic remaining gate revocation succeeded");
		}
	} else {
		check(false, "synthetic gate revocation succeeded");
	}
	check(missing && invalid(open(*missing)) && invalid(open(*table)),
		"a missing row is invalid even when a different target is already revoked");
	const auto foreign = AccountGateTable::Create(QByteArray(16, 'f'));
	check(foreign && invalid(open(*foreign)), "a gate table from another installation is rejected");
	auto remove = details;
	remove.rule.action = EA::EmergencyAction::RemoveInstallation;
	remove.rule.targetScope = EA::TargetScope::CurrentInstallation;
	remove.rule.selectedAccountIds.clear();
	remove.rule.safeProfileId = {};
	auto removingLive = live;
	removingLive.accounts.pop_back();
	removingLive.profiles.clear();
	const auto package = FixtureBytes(0x73);
	check(!SealRevocableEmergencyCapability(epoch, details, live, gates, accounts, safeGrant, package, key)
		&& !SealRevocableEmergencyCapability(epoch, remove, removingLive, gates, accounts, {}, {}, key)
		&& !SealRevocableEmergencyCapability(epoch, remove, removingLive, gates, accounts, {}, FixtureBytes(0), key),
		"only an approved installation removal can carry a nonzero package digest");
	const auto removal = SealRevocableEmergencyCapability(epoch, remove, removingLive, gates, accounts, {}, package, key);
	const auto removalTicket = removal ? Ticket(epoch, remove, removingLive, removal->digest, key) : std::nullopt;
	if (removalTicket) {
		const auto result = OpenRevocableEmergencyCapability(epoch, *removalTicket, gates, removal->bytes, package, key);
		const auto verified = std::get_if<OpenedRevocableEmergencyCapability>(&result);
		check(verified && verified->packageDigest() == package
			&& invalid(OpenRevocableEmergencyCapability(epoch, *removalTicket, gates, removal->bytes, FixtureBytes(0x74), key))
			&& invalid(OpenRevocableEmergencyCapability(epoch, *removalTicket, gates, removal->bytes, {}, key)),
			"installation removal opens only against the independently verified exact package digest");
	} else {
		check(false, "authenticated installation removal fixture");
	}
	return failures ? 1 : 0;
}
