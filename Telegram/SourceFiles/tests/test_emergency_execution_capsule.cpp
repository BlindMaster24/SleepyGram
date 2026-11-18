#include "ayu/features/emergency_actions/emergency_execution_capsule.h"

#include <algorithm>
#include <cstdio>
#include <ranges>
#include <string_view>
#include <type_traits>

namespace {

using namespace Ayu::EmergencyActions;

auto failures = 0;

void Check(const char *name, bool passed) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
	failures += !passed;
}

std::array<uint8_t, 32> Bytes(uint8_t tag) {
	auto result = std::array<uint8_t, 32>{};
	for (auto i = size_t(0); i != result.size(); ++i) {
		result[i] = uint8_t(tag + i);
	}
	return result;
}

template <size_t Size>
constexpr auto Hex(const char (&hex)[Size]) {
	static_assert((Size - 1) % 2 == 0);
	constexpr auto digits = std::string_view("0123456789abcdef");
	auto result = std::array<uint8_t, (Size - 1) / 2>{};
	for (auto i = size_t(0); i != result.size(); ++i) {
		result[i] = uint8_t(digits.find(hex[2 * i]) * 16 + digits.find(hex[2 * i + 1]));
	}
	return result;
}

struct Fixture final {
	EmergencyRuleGeneration generation = {
		.installationId = InstallationId("fixture-installation"),
		.transactionId = std::string(32, 'a'),
	};
	LiveInstallation live = {
		.id = generation.installationId,
		.accounts = {
			{ AccountId("selected-one"), SessionId("current-one"),
				{ SessionId("current-one"), SessionId("selected-device") } },
			{ AccountId("selected-two"), SessionId("current-two"),
				{ SessionId("current-two") } },
			{ AccountId("retained-other"), SessionId("current-three"),
				{ SessionId("current-three") } },
		},
		.profiles = {
			{ ProfileId("reviewed-safe-set"), { AccountId("retained-other") } },
		},
	};
	EmergencyRuleDetails details = {
		.actionId = EmergencyActionId("fixture-action"),
		.rule = {
			.id = RuleId("fixture-rule"),
			.installationId = generation.installationId,
			.action = EmergencyAction::ResetAccountData,
			.targetScope = TargetScope::SelectedAccounts,
			.selectedAccountIds = { live.accounts[0].id, live.accounts[1].id },
			.remoteSessionPolicies = {
				{ live.accounts[0].id, RemoteSessionTargetKind::SelectedSessions,
					{ SessionId("selected-device") } },
			},
			.safeProfileId = live.profiles.front().id,
		},
		.operationId = OperationId("fixture-operation"),
		.revision = 2,
	};
	std::array<uint8_t, 32> emergencyKey = Bytes(22);
	std::array<uint8_t, 32> masterKey = Bytes(44);
	std::array<uint8_t, 32> accountKeyOne = Bytes(66);
	std::array<uint8_t, 32> accountKeyTwo = Bytes(88);
	std::array<uint8_t, 32> accountKeyOther = Bytes(110);
	std::array<uint8_t, 32> vault = Bytes(132);
	std::array<uint8_t, 32> keyring = Bytes(154);
	std::array<uint8_t, 32> safeGrant = Bytes(176);
	std::array<EmergencyExecutionAccount, 2> accounts = {{
		{
			.accountId = live.accounts[0].id,
			.locator = std::string(32, 'f'),
			.scopedKey = accountKeyOne,
			.remoteIdentity = EmergencyScopedRemoteIdentity{
				.userId = 1111,
				.environment = EmergencyScopedEnvironment::Test,
			},
		},
		{
			.accountId = live.accounts[1].id,
			.locator = std::string(32, 'd'),
			.scopedKey = accountKeyTwo,
			.remoteIdentity = std::nullopt,
		},
	}};
	EmergencyExecutionSuccessor successor = {
		.transactionId = std::string(32, 'b'),
		.sealedProfileVault = vault,
		.sealedAccountKeyring = keyring,
	};
	std::optional<EmergencyExecutionSafeDestination> safe = {{
		.profileId = live.profiles.front().id,
		.sealedSetGrant = safeGrant,
	}};

	[[nodiscard]] DryRunPlan plan() const {
		return BuildDryRunPlan(details.operationId, details.rule, live);
	}

	[[nodiscard]] std::optional<SealedEmergencyExecutionCapsule> seal() const {
		return SealEmergencyExecutionCapsule(
			generation,
			details,
			plan(),
			accounts,
			successor,
			safe,
			emergencyKey);
	}

	[[nodiscard]] std::optional<SealedEmergencyRules> sealRule(
			std::optional<EmergencyExecutionCapsuleDigest> capsuleDigest) const {
		auto config = RuleConfiguration{
			.activeInstallationId = generation.installationId,
			.masterVerifier = Bytes(11),
			.emergencyRules = {{
				.id = details.actionId,
				.rule = details.rule,
				.verifier = Bytes(12),
				.revision = details.revision,
			}},
		};
		const auto preview = PreviewEmergencyRule(config, details.actionId, live, details.operationId);
		if (!preview || !ConfirmEmergencyRule(config, *preview, live, true)) {
			return std::nullopt;
		}
		const auto entries = std::array{
			EmergencyRuleSealInput{
				.actionId = details.actionId,
				.name = "Reviewed test rule",
				.verifier = Bytes(12),
				.key = emergencyKey,
				.executionCapsuleDigest = capsuleDigest,
				.capsuleVersion = details.capsuleVersion,
			},
		};
		return SealEmergencyRules(generation, masterKey, config, live, entries);
	}

	[[nodiscard]] std::optional<EmergencyRuleTicket> authenticate(
			std::optional<EmergencyExecutionCapsuleDigest> capsuleDigest) const {
		const auto rules = sealRule(capsuleDigest);
		if (!rules) {
			return std::nullopt;
		}
		auto opened = AuthenticateEmergencyRule(rules->authority, rules->bytes, emergencyKey);
		auto ticket = std::get_if<EmergencyRuleTicket>(&opened);
		return ticket ? std::optional(std::move(*ticket)) : std::nullopt;
	}
};

void CapsuleRequiresAnExactAndSafeReview() {
	auto f = Fixture();
	Check("valid-reviewed-targets-and-safe-grant-can-be-sealed", bool(f.seal()));
	f.accounts[1].accountId = f.live.accounts[2].id;
	f.accounts[1].scopedKey = f.accountKeyOther;
	Check("capsule-rejects-unapproved-account", !f.seal());
	f.accounts[1].accountId = f.live.accounts[0].id;
	Check("capsule-rejects-duplicated-approved-account", !f.seal());
	auto duplicate = Fixture();
	duplicate.accounts[1].scopedKey = duplicate.accountKeyOne;
	Check("capsule-rejects-shared-scoped-keys", !duplicate.seal());
	duplicate.accounts[1].scopedKey = duplicate.accountKeyTwo;
	duplicate.accounts[1].locator = duplicate.accounts[0].locator;
	Check("capsule-rejects-shared-storage-locators", !duplicate.seal());
	duplicate.accounts[1].locator = std::string(32, 'D');
	Check("capsule-rejects-noncanonical-storage-locator", !duplicate.seal());
	auto remote = Fixture();
	remote.accounts[0].remoteIdentity.reset();
	Check("selected-remote-device-requires-expected-user-and-environment", !remote.seal());
	remote.accounts[0].remoteIdentity = {
		.userId = uint64_t(0x1000000000000ULL),
		.environment = EmergencyScopedEnvironment::Test,
	};
	Check("remote-user-id-width-is-bounded", !remote.seal());
	remote.accounts[0].remoteIdentity = {
		.userId = 1111,
		.environment = EmergencyScopedEnvironment(99),
	};
	Check("unknown-remote-environment-is-rejected", !remote.seal());
	auto unsafe = Fixture();
	unsafe.safe->profileId = ProfileId("unknown-safe-set");
	Check("safe-authority-cannot-substitute-a-different-set", !unsafe.seal());
	unsafe.safe.reset();
	unsafe.live.profiles.front().accountIds.push_back(unsafe.live.accounts[0].id);
	Check("unsafe-review-cannot-carry-capsule", !unsafe.seal());
	auto reused = Fixture();
	reused.successor.transactionId = reused.generation.transactionId;
	Check("successor-cannot-reuse-current-generation", !reused.seal());
	reused.successor.transactionId = std::string(32, 'b');
	reused.successor.sealedAccountKeyring = {};
	Check("successor-requires-both-sealed-profile-artifacts", !reused.seal());
}

void CapsuleOpensOnlyThroughItsAuthenticatedRuleTicket() {
	const auto f = Fixture();
	auto sealed = f.seal();
	const auto repeated = f.seal();
	if (!sealed || !repeated) {
		Check("fixture-capsules-sealed", false);
		return;
	}
	const auto hiding = [&](std::span<const uint8_t> secret) {
		return std::ranges::search(sealed->bytes, secret).empty();
	};
	Check("capsule-reencrypts-account-keys-and-opaque-successor",
		sealed->digest != repeated->digest && sealed->bytes != repeated->bytes
		&& sealed->bytes.size() <= MaximumEmergencyExecutionCapsuleSize()
		&& hiding(f.accountKeyOne) && hiding(f.accountKeyTwo)
		&& hiding(f.vault) && hiding(f.keyring) && hiding(f.safeGrant));
	const auto ticket = f.authenticate(sealed->digest);
	if (!ticket || ticket->details().executionCapsuleDigest != sealed->digest) {
		Check("rule-ticket-authenticates-capsule-digest", false);
		return;
	}
	auto opened = OpenEmergencyExecutionCapsule(*ticket, f.plan(), sealed->bytes, f.emergencyKey);
	if (!opened) {
		Check("approved-capsule-opens", false);
		return;
	}
	static_assert(!std::is_copy_constructible_v<OpenedEmergencyExecutionCapsule>);
	auto moved = std::move(*opened);
	const auto accounts = moved.accounts();
	Check("opening-retains-exact-scoped-keys-and-remote-identity",
		accounts.size() == 2 && accounts[0].accountId == f.accounts[0].accountId
		&& accounts[1].locator == f.accounts[1].locator
		&& std::ranges::equal(accounts[0].scopedKey, f.accountKeyOne)
		&& std::ranges::equal(accounts[1].scopedKey, f.accountKeyTwo)
		&& accounts[0].remoteIdentity && accounts[0].remoteIdentity->userId == 1111
		&& accounts[0].remoteIdentity->environment == EmergencyScopedEnvironment::Test
		&& !accounts[1].remoteIdentity);
	Check("opening-retains-only-approved-successor-and-safe-authority",
		moved.successor().transactionId == f.successor.transactionId
		&& std::ranges::equal(moved.successor().sealedProfileVault, f.vault)
		&& std::ranges::equal(moved.successor().sealedAccountKeyring, f.keyring)
		&& moved.safeDestination() && moved.safeDestination()->profileId == f.safe->profileId
		&& std::ranges::equal(moved.safeDestination()->sealedSetGrant, f.safeGrant));
	Check("master-key-cannot-open-emergency-capsule-with-another-ticket",
		!OpenEmergencyExecutionCapsule(*ticket, f.plan(), sealed->bytes, f.masterKey));
	Check("independently-reencrypted-capsule-does-not-match-ticket-digest",
		!OpenEmergencyExecutionCapsule(*ticket, f.plan(), repeated->bytes, f.emergencyKey));
	sealed->bytes.back() ^= 1;
	Check("capsule-tampering-is-rejected", !OpenEmergencyExecutionCapsule(
		*ticket, f.plan(), sealed->bytes, f.emergencyKey));
	sealed->bytes.back() ^= 1;
	const auto legacyTicket = f.authenticate(std::nullopt);
	Check("rule-without-capsule-digest-cannot-open-a-capsule",
		legacyTicket && !legacyTicket->reviewedLive() && !OpenEmergencyExecutionCapsule(
			*legacyTicket, f.plan(), sealed->bytes, f.emergencyKey));
	auto changedPlan = f.plan();
	changedPlan.accounts.pop_back();
	Check("current-review-count-must-match-capsule",
		!OpenEmergencyExecutionCapsule(*ticket, changedPlan, sealed->bytes, f.emergencyKey));
	changedPlan = f.plan();
	changedPlan.accounts[1].accountId = f.live.accounts[2].id;
	Check("current-review-target-ids-must-match-capsule",
		!OpenEmergencyExecutionCapsule(*ticket, changedPlan, sealed->bytes, f.emergencyKey));
	changedPlan = f.plan();
	changedPlan.accounts.front().sessionIdsForRevokeRequest = { SessionId("unreviewed-device") };
	Check("supplied-plan-cannot-substitute-a-different-device",
		!OpenEmergencyExecutionCapsule(*ticket, changedPlan, sealed->bytes, f.emergencyKey));
	changedPlan = f.plan();
	changedPlan.safeProfileAccountIds = { AccountId("unreviewed-safe-member") };
	Check("supplied-plan-cannot-substitute-safe-set-membership",
		!OpenEmergencyExecutionCapsule(*ticket, changedPlan, sealed->bytes, f.emergencyKey));
	const auto rules = f.sealRule(sealed->digest);
	const auto next = EmergencyRuleGeneration{
		.installationId = f.generation.installationId,
		.transactionId = std::string(32, 'e'),
	};
	const auto master = EmergencyRuleMasterContext{
		.derivedKey = f.masterKey,
		.verifier = Bytes(11),
	};
	Check("master-must-reprepare-generation-bound-rule-capsules",
		rules && !RebindEmergencyRulesForMaster(
			rules->authority, rules->bytes, f.masterKey, next, f.live, master));
}

void RuleTicketProvidesOnlyTheConfirmedLiveData() {
	auto f = Fixture();
	f.live.accounts[0].sessionIds.push_back(SessionId("unselected-device"));
	f.live.accounts[1].sessionIds.push_back(SessionId("irrelevant-device"));
	f.live.profiles.push_back({ ProfileId("unselected-profile"), { f.live.accounts[1].id } });
	const auto sealed = f.seal();
	const auto ticket = sealed ? f.authenticate(sealed->digest) : std::nullopt;
	const auto reviewed = ticket ? ticket->reviewedLive() : nullptr;
	Check("ticket-reconstructs-exact-plan-using-only-approved-data",
		reviewed && reviewed->id == f.live.id
		&& BuildDryRunPlan(f.details.operationId, f.details.rule, *reviewed) == f.plan());
	Check("ticket-omits-unapproved-accounts-devices-and-profiles",
		reviewed && reviewed->accounts.size() == 2 && reviewed->profiles.size() == 1
		&& reviewed->accounts[0].id == f.live.accounts[0].id
		&& reviewed->accounts[0].sessionIds == std::vector<SessionId>{
			SessionId("current-one"), SessionId("selected-device") }
		&& reviewed->accounts[1].id == f.live.accounts[1].id
		&& reviewed->accounts[1].sessionIds == std::vector<SessionId>{ SessionId("current-two") }
		&& reviewed->profiles.front().id == f.live.profiles.front().id
		&& reviewed->profiles.front().accountIds == f.live.profiles.front().accountIds);
	auto all = Fixture();
	all.details.rule.targetScope = TargetScope::AllAccounts;
	all.details.rule.selectedAccountIds.clear();
	all.details.rule.remoteSessionPolicies.front().kind = RemoteSessionTargetKind::AllOtherSessions;
	all.details.rule.remoteSessionPolicies.front().selectedSessionIds.clear();
	all.live.profiles.front().accountIds.clear();
	all.live.accounts.front().sessionIds.push_back(SessionId("another-reviewed-device"));
	const auto allTicket = all.authenticate(Bytes(220));
	const auto allReviewed = allTicket ? allTicket->reviewedLive() : nullptr;
	Check("reset-all-snapshot-includes-all-current-accounts-and-reviewed-other-devices",
		allReviewed && allReviewed->accounts.size() == 3
		&& BuildDryRunPlan(all.details.operationId, all.details.rule, *allReviewed) == all.plan());
	for (auto i = 0; i != 129; ++i) {
		all.live.accounts.front().sessionIds.emplace_back("extra-device-" + std::to_string(i));
	}
	Check("oversized-confirmed-device-inventory-is-rejected",
		!all.sealRule(Bytes(220)));
}

void CapsuleCryptographicallyBindsTheRuleAndItsGeneration() {
	const auto original = Fixture();
	const auto sealed = original.seal();
	if (!sealed) {
		Check("binding-fixture-sealed", false);
		return;
	}
	const auto rejects = [&](const Fixture &changed) {
		const auto ticket = changed.authenticate(sealed->digest);
		return ticket && !OpenEmergencyExecutionCapsule(
			*ticket, changed.plan(), sealed->bytes, changed.emergencyKey);
	};
	auto next = Fixture();
	next.generation.transactionId = std::string(32, 'c');
	Check("old-capsule-rejected-under-new-generation", rejects(next));
	auto operation = Fixture();
	operation.details.operationId = OperationId("another-operation-id");
	Check("old-capsule-rejected-under-new-operation-id", rejects(operation));
	auto revision = Fixture();
	++revision.details.revision;
	Check("old-capsule-rejected-under-new-rule-revision", rejects(revision));
	auto remotePolicy = Fixture();
	remotePolicy.details.rule.remoteSessionPolicies.clear();
	Check("old-capsule-rejected-under-a-different-remote-policy", rejects(remotePolicy));
	auto rule = Fixture();
	rule.details.rule.id = RuleId("another-rule-id");
	Check("old-capsule-rejected-under-new-rule-id", rejects(rule));
	auto action = Fixture();
	action.details.actionId = EmergencyActionId("another-action-id");
	Check("old-capsule-rejected-under-new-action-id", rejects(action));
	auto installation = Fixture();
	installation.generation.installationId = InstallationId("another-installation");
	installation.details.rule.installationId = installation.generation.installationId;
	installation.live.id = installation.generation.installationId;
	Check("old-capsule-rejected-under-another-installation", rejects(installation));
}

void LegacyCapsulesRemainUsableButCannotBeRebound() {
	constexpr auto sealed = Hex(
		"534745430000000149bdaf3823b9942989daddb764f836391e7f7fb45c0d7228"
		"8c1990771c6b5f69f20b020247e2c61135a3cc47bd4179632666dab2aa1e0f8b"
		"dd45f5b164a3c62879c954c730014ea9ead05b5670381fca3944c1a5766ee9fa"
		"22e42e16e27f0fef4f06e68bfe4892b330f080a1dc2b90e36e45e3e38a5b418f"
		"c85028d13d2025f47cd92884bf6301e2ba9cd2da322feae30fd22816dc813836"
		"7533d80e25727d9e91012014daa884f2eb556e5a8cea69eab204a3c530d76c13"
		"f8d942eb051cc8ed9107192c9cb982ce47724e6f106b04e64ebd39974273cf7d"
		"8f391c725650cd426316b47116e9355d47653db2c75d35eebcb63d7cd182df16"
		"65287e4647ff1b47480e681444476d4ec00b749cf16c4a7498ba0d44a4abd3d5"
		"f19a713a105e262c789d1c4e10f6e2702380071faa75eceabc6b38fbcdedbd49"
		"79e354b7a096b9825c6996136f92a50fb75a61be2f6fe5cb0b0f62f28629df75"
		"aeacf3167217a12d741a20d19d14c935ce192ea0adfe379e4408");
	constexpr auto digest = Hex(
		"09483497a5ad12437044a17d4fba8a3572424b47494f3b8563ff8f759d19badf");
	auto fixture = Fixture();
	const auto mismatched = fixture.authenticate(digest);
	Check("legacy-bytes-cannot-be-used-with-a-v2-rule-record",
		mismatched && !OpenEmergencyExecutionCapsule(
			*mismatched, fixture.plan(), sealed, fixture.emergencyKey));
	fixture.details.capsuleVersion = EmergencyExecutionCapsuleVersion::Legacy;
	const auto ticket = fixture.authenticate(digest);
	const auto opened = ticket ? OpenEmergencyExecutionCapsule(
		*ticket, fixture.plan(), sealed, fixture.emergencyKey) : std::nullopt;
	Check("historical-v1-capsule-retains-its-keys-and-exact-safe-grant",
		opened && opened->accounts().size() == fixture.accounts.size()
		&& std::ranges::equal(opened->accounts().front().scopedKey, fixture.accountKeyOne)
		&& opened->safeDestination()
		&& std::ranges::equal(opened->safeDestination()->sealedSetGrant, fixture.safeGrant));
	Check("legacy-capsule-cannot-use-a-rebind-capability",
		ticket && !OpenEmergencyExecutionCapsuleForRebind(*ticket, sealed, fixture.emergencyKey));
	const auto rules = fixture.sealRule(digest);
	const auto next = EmergencyRuleGeneration{
		.installationId = fixture.generation.installationId,
		.transactionId = std::string(32, 'e'),
	};
	auto called = false;
	Check("legacy-capsule-prevents-rebind-even-with-a-rebuild-callback",
		rules && !RebindEmergencyRulesForMaster(rules->authority, rules->bytes, fixture.masterKey,
			next, fixture.live, { fixture.masterKey, Bytes(11), {} },
			[&](const auto &, const auto &, const auto &, auto) {
				called = true;
				return std::optional(Bytes(77));
			}) && !called);
}

void MasterRebindsResetAllForNewlyEnrolledAccounts(bool withSafeGrant) {
	auto fixture = Fixture();
	fixture.live.accounts.resize(2);
	fixture.live.profiles.front().accountIds.clear();
	fixture.details.rule.targetScope = TargetScope::AllAccounts;
	fixture.details.rule.selectedAccountIds.clear();
	if (!withSafeGrant) {
		fixture.details.rule.safeProfileId = {};
		fixture.safe.reset();
	}
	const auto sealed = fixture.seal();
	const auto rules = sealed ? fixture.sealRule(sealed->digest) : std::nullopt;
	if (!rules) {
		Check("rebind-fixture-sealed", false);
		return;
	}
	const auto next = EmergencyRuleGeneration{
		.installationId = fixture.generation.installationId,
		.transactionId = std::string(32, 'e'),
	};
	auto live = fixture.live;
	const auto enrolled = AccountId("new-enrollee");
	live.accounts.push_back({ enrolled, SessionId("new-current"), { SessionId("new-current") } });
	auto accounts = std::vector(fixture.accounts.begin(), fixture.accounts.end());
	accounts.push_back({ enrolled, std::string(32, 'c'), fixture.accountKeyOther });
	const auto master = EmergencyRuleMasterContext{ fixture.masterKey, Bytes(11), {} };
	Check("master-rebind-cannot-retain-the-previous-capsule-digest",
		!RebindEmergencyRulesForMaster(rules->authority, rules->bytes, fixture.masterKey,
			next, live, master, [&](const auto &, const auto &, const auto &, auto) {
				return std::optional(sealed->digest);
			}));
	auto callbackCount = 0;
	auto nextCapsule = std::optional<SealedEmergencyExecutionCapsule>();
	const auto rebuild = [&](const EmergencyRuleTicket &previous, const EmergencyRuleDetails &details,
			const DryRunPlan &plan, EmergencyExecutionCapsuleKey key) {
		++callbackCount;
		const auto reviewed = previous.reviewedLive();
		const auto old = OpenEmergencyExecutionCapsuleForRebind(previous, sealed->bytes, key);
		if (!old || bool(old->safeDestination()) != withSafeGrant
			|| (withSafeGrant && !std::ranges::equal(old->safeDestination()->sealedSetGrant, fixture.safeGrant))
			|| !reviewed || reviewed->accounts.size() != 2
			|| (fixture.plan().safeDestination == SafeDestinationKind::Profile) != withSafeGrant
			|| details.operationId == previous.details().operationId) {
			return std::optional<EmergencyExecutionCapsuleDigest>();
		}
		nextCapsule = SealEmergencyExecutionCapsuleForRebind(
			next, details, plan, accounts, fixture.successor, old->safeDestination(), key);
		return nextCapsule ? std::optional(nextCapsule->digest) : std::nullopt;
	};
	Check("emergency-key-cannot-request-master-rebind",
		!RebindEmergencyRulesForMaster(rules->authority, rules->bytes, fixture.emergencyKey,
			next, live, master, rebuild) && !callbackCount);
	const auto rebound = RebindEmergencyRulesForMaster(
		rules->authority, rules->bytes, fixture.masterKey, next, live, master, rebuild);
	if (!rebound || !nextCapsule) {
		Check("master-rebind-produced-a-sealed-rule-and-capsule", false);
		return;
	}
	auto auth = AuthenticateEmergencyRule(rebound->authority, rebound->bytes, fixture.emergencyKey);
	const auto ticket = std::get_if<EmergencyRuleTicket>(&auth);
	const auto reviewed = ticket ? ticket->reviewedLive() : nullptr;
	auto plan = reviewed ? BuildDryRunPlan(ticket->details().operationId, ticket->details().rule, *reviewed)
		: DryRunPlan();
	const auto opened = ticket ? OpenEmergencyExecutionCapsule(
		*ticket, plan, nextCapsule->bytes, fixture.emergencyKey) : std::nullopt;
	const auto added = std::ranges::find(plan.accounts, enrolled, &AccountDryRun::accountId);
	Check(withSafeGrant ? "master-rebind-retains-safe-grant-and-adds-new-account"
		: "master-rebind-retains-empty-fallback-and-adds-new-account",
		callbackCount == 1 && opened && reviewed && opened->accounts().size() == 3
		&& bool(opened->safeDestination()) == withSafeGrant
		&& added != end(plan.accounts) && added->remoteTarget == RemoteSessionTargetKind::None
		&& !OpenEmergencyExecutionCapsule(*ticket, plan, sealed->bytes, fixture.emergencyKey)
		&& OpenEmergencyRulesForMaster(rebound->authority, rebound->bytes, fixture.masterKey)
		&& !OpenEmergencyRulesForMaster(rebound->authority, rebound->bytes, fixture.emergencyKey));
}

void InstallationDigestRemainsBoundToTheCapsule() {
	auto fixture = Fixture();
	fixture.live.accounts.resize(2);
	fixture.details.rule.action = EmergencyAction::RemoveInstallation;
	fixture.details.rule.targetScope = TargetScope::CurrentInstallation;
	fixture.details.rule.selectedAccountIds.clear();
	fixture.details.rule.safeProfileId = {};
	fixture.safe.reset();
	const auto installationDigest = Bytes(199);
	Check("v2-installation-removal-requires-the-installation-digest", !fixture.seal());
	fixture.successor.installationDigest = installationDigest;
	const auto sealed = fixture.seal();
	const auto ticket = sealed ? fixture.authenticate(sealed->digest) : std::nullopt;
	const auto opened = ticket ? OpenEmergencyExecutionCapsule(
		*ticket, fixture.plan(), sealed->bytes, fixture.emergencyKey) : std::nullopt;
	Check("v2-installation-digest-round-trips-in-authenticated-payload",
		opened && std::ranges::equal(opened->successor().installationDigest, installationDigest));
}

} // namespace

int main() {
	CapsuleRequiresAnExactAndSafeReview();
	CapsuleOpensOnlyThroughItsAuthenticatedRuleTicket();
	RuleTicketProvidesOnlyTheConfirmedLiveData();
	CapsuleCryptographicallyBindsTheRuleAndItsGeneration();
	LegacyCapsulesRemainUsableButCannotBeRebound();
	MasterRebindsResetAllForNewlyEnrolledAccounts(true);
	MasterRebindsResetAllForNewlyEnrolledAccounts(false);
	InstallationDigestRemainsBoundToTheCapsule();
	return failures ? 1 : 0;
}
