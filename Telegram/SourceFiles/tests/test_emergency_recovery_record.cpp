#include "ayu/features/emergency_actions/emergency_recovery_record.h"

#include <algorithm>
#include <cstdio>
#include <ranges>

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

struct Fixture final {
	const EmergencyRuleGeneration source = {
		.installationId = InstallationId("recovery-fixture-install"),
		.transactionId = std::string(32, 'a'),
	};
	const std::string admission = std::string(32, 'b');
	const LiveInstallation live = {
		.id = source.installationId,
		.accounts = {
			{
				AccountId("target-alpha"),
				SessionId("alpha-current"),
				{ SessionId("alpha-current"), SessionId("alpha-selected") },
			},
			{ AccountId("target-beta"), SessionId("beta-current"), { SessionId("beta-current") } },
			{ AccountId("retained-account"), SessionId("safe-current"), { SessionId("safe-current") } },
		},
		.profiles = {
			{ ProfileId("safe-profile"), { AccountId("retained-account") } },
		},
	};
	const EmergencyRuleDetails details = {
		.actionId = EmergencyActionId("recovery-fixture-action"),
		.rule = {
			.id = RuleId("recovery-fixture-rule"),
			.installationId = source.installationId,
			.action = EmergencyAction::ResetAccountData,
			.targetScope = TargetScope::SelectedAccounts,
			.selectedAccountIds = { live.accounts[0].id, live.accounts[1].id },
			.remoteSessionPolicies = {
				{
					live.accounts[0].id,
					RemoteSessionTargetKind::SelectedSessions,
					{ SessionId("alpha-selected") },
				},
			},
			.safeProfileId = live.profiles.front().id,
		},
		.operationId = OperationId("recovery-fixture-operation"),
		.revision = 7,
	};
	const std::array<uint8_t, 32> emergencyKey = Bytes(24);
	const std::array<uint8_t, 32> masterKey = Bytes(48);
	const std::array<uint8_t, 32> alphaKey = Bytes(72);
	const std::array<uint8_t, 32> betaKey = Bytes(96);
	const std::array<uint8_t, 32> vault = Bytes(120);
	const std::array<uint8_t, 32> keyring = Bytes(144);
	const std::array<uint8_t, 32> safeCredential = Bytes(168);
	const std::array<EmergencyExecutionAccount, 2> accounts = {{
		{
			.accountId = live.accounts[1].id,
			.locator = std::string(32, 'f'),
			.scopedKey = betaKey,
			.remoteIdentity = std::nullopt,
		},
		{
			.accountId = live.accounts[0].id,
			.locator = std::string(32, 'e'),
			.scopedKey = alphaKey,
			.remoteIdentity = EmergencyScopedRemoteIdentity{
				.userId = 100,
				.environment = EmergencyScopedEnvironment::Test,
			},
		},
	}};
	const EmergencyExecutionSuccessor successor = {
		.transactionId = std::string(32, 'c'),
		.sealedProfileVault = vault,
		.sealedAccountKeyring = keyring,
	};

	[[nodiscard]] std::optional<SealedEmergencyExecutionCapsule> sealCapsule() const {
		const auto plan = BuildDryRunPlan(details.operationId, details.rule, live);
		return SealEmergencyExecutionCapsule(
			source,
			details,
			plan,
			accounts,
			successor,
			EmergencyExecutionSafeDestination{
				.profileId = live.profiles.front().id,
				.sealedSetGrant = safeCredential,
			},
			emergencyKey);
	}

	[[nodiscard]] std::optional<EmergencyRuleTicket> openRule(
			std::optional<EmergencyExecutionCapsuleDigest> capsuleDigest) const {
		const auto verifier = Bytes(8);
		auto config = RuleConfiguration{
			.activeInstallationId = source.installationId,
			.masterVerifier = Bytes(4),
			.emergencyRules = {{
				.id = details.actionId,
				.rule = details.rule,
				.verifier = verifier,
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
				.name = "Fixture",
				.verifier = verifier,
				.key = emergencyKey,
				.executionCapsuleDigest = capsuleDigest,
			},
		};
		const auto rule = SealEmergencyRules(source, masterKey, config, live, entries);
		if (!rule) {
			return std::nullopt;
		}
		auto route = AuthenticateEmergencyRule(rule->authority, rule->bytes, emergencyKey);
		const auto ticket = std::get_if<EmergencyRuleTicket>(&route);
		return ticket ? std::optional(std::move(*ticket)) : std::nullopt;
	}
};

size_t Read32(std::span<const uint8_t> value) {
	auto result = size_t(0);
	for (auto i = size_t(0); i != 4; ++i) {
		result |= size_t(value[i]) << (8 * i);
	}
	return result;
}

void RunFixture() {
	const auto f = Fixture();
	const auto seal = f.sealCapsule();
	const auto ticket = seal ? f.openRule(seal->digest) : std::nullopt;
	if (!ticket) {
		Check("verified-rule-and-capsule-fixture", false);
		return;
	}
	const auto prepare = [&] {
		return PrepareEmergencyRecoveryRecord(*ticket, seal->bytes, f.emergencyKey, f.admission);
	};
	const auto prepared = prepare();
	if (!prepared) {
		Check("verified-recovery-record-prepared", false);
		return;
	}
	const auto &storage = prepared->bytes;
	const auto decode = [&](std::span<const uint8_t> bytes) {
		return DecodeEmergencyRecoveryRecord(bytes, f.source.installationId, f.admission);
	};
	const auto contains = [&](std::span<const uint8_t> bytes) {
		return !std::ranges::search(storage, bytes).empty();
	};
	Check("record-excludes-password-account-keys-and-safe-credentials",
		!contains(f.emergencyKey) && !contains(f.masterKey)
		&& !contains(f.alphaKey) && !contains(f.betaKey) && !contains(f.safeCredential));
	Check("prepared-opened-capsule-retains-only-in-memory-execution-access",
		prepared->capsule.accounts().size() == 2 && prepared->capsule.safeDestination()
		&& std::ranges::equal(prepared->capsule.accounts()[0].scopedKey, f.betaKey));
	const auto admission = decode(storage);
	const auto successor = DecodeEmergencyRecoveryRecord(
		storage, f.source.installationId, f.successor.transactionId);
	Check("decoder-accepts-only-explicit-admission-and-successor-phases",
		admission && admission->phase == EmergencyRecoveryPhase::Admission
		&& successor && successor->phase == EmergencyRecoveryPhase::Successor
		&& !DecodeEmergencyRecoveryRecord(storage, f.source.installationId, f.source.transactionId)
		&& !DecodeEmergencyRecoveryRecord(storage, f.source.installationId, std::string(32, 'd')));
	Check("foreign-installation-recovery-is-refused",
		!DecodeEmergencyRecoveryRecord(storage, InstallationId("foreign-install"), f.admission));
	if (!admission || !successor) return;
	const auto review = BuildDryRunPlan(f.details.operationId, f.details.rule, f.live);
	const auto initial = MakeJournal(review);
	Check("record-restores-exact-production-initial-journal-and-successor",
		initial && EncodeJournal(admission->journal) == EncodeJournal(*initial)
		&& EncodeJournal(successor->journal) == EncodeJournal(*initial)
		&& admission->sourceGeneration == f.source.transactionId
		&& admission->admissionGeneration == f.admission
		&& admission->successorGeneration == f.successor.transactionId
		&& std::ranges::equal(admission->sealedProfileVault, f.vault)
		&& std::ranges::equal(admission->sealedAccountKeyring, f.keyring));
	Check("locators-bind-once-to-exact-journal-targets-despite-input-order",
		admission->accounts.size() == 2
		&& admission->accounts[0].accountId == f.live.accounts[0].id
		&& admission->accounts[0].locator == f.accounts[1].locator
		&& admission->accounts[1].accountId == f.live.accounts[1].id
		&& admission->accounts[1].locator == f.accounts[0].locator);
	const auto another = f.sealCapsule();
	Check("admission-rejects-capsules-authenticated-by-a-different-digest",
		another && !PrepareEmergencyRecoveryRecord(
			*ticket, another->bytes, f.emergencyKey, f.admission));
	const auto legacy = f.openRule(std::nullopt);
	Check("digestless-v1-rule-cannot-prepare-recovery",
		legacy && !PrepareEmergencyRecoveryRecord(*legacy, seal->bytes, f.emergencyKey, f.admission));
	Check("admission-needs-exact-credential-and-new-distinct-generation",
		!PrepareEmergencyRecoveryRecord(*ticket, seal->bytes, f.masterKey, f.admission)
		&& !PrepareEmergencyRecoveryRecord(*ticket, seal->bytes, f.emergencyKey, f.source.transactionId)
		&& !PrepareEmergencyRecoveryRecord(*ticket, seal->bytes, f.emergencyKey, f.successor.transactionId)
		&& !PrepareEmergencyRecoveryRecord(*ticket, seal->bytes, f.emergencyKey, std::string(32, 'B')));
	auto damaged = storage;
	damaged.front() ^= 1;
	Check("magic-and-version-are-checked", !decode(damaged));
	damaged = storage;
	damaged.pop_back();
	Check("truncated-record-is-rejected", !decode(damaged));
	damaged = storage;
	damaged.push_back(0);
	Check("trailing-bytes-are-rejected", !decode(damaged));

	constexpr auto journalSizeOffset = size_t(8 + 3 * 32);
	const auto journalBytes = Read32(std::span(storage).subspan(journalSizeOffset, 4));
	const auto journalOffset = journalSizeOffset + 4;
	const auto mappingCount = journalOffset + journalBytes;
	const auto locatorOffset = mappingCount + 2;
	damaged = storage;
	damaged[mappingCount] = 1;
	Check("partial-target-mapping-is-rejected", !decode(damaged));
	damaged = storage;
	std::fill_n(damaged.begin() + locatorOffset, 32, uint8_t('F'));
	Check("noncanonical-locator-is-rejected", !decode(damaged));
	damaged = storage;
	std::copy_n(storage.begin() + locatorOffset, 32, damaged.begin() + locatorOffset + 32);
	Check("duplicate-locator-is-rejected", !decode(damaged));
	damaged = storage;
	std::fill_n(damaged.begin() + locatorOffset + 2 * 32, 4, uint8_t(0));
	Check("missing-successor-artifact-is-rejected", !decode(damaged));

	auto checkpoint = admission->journal;
	const auto started = BeginEffect(
		checkpoint, JournalEffect::RemoteSessionRevoke, f.live.accounts.front().id);
	Check("checkpoint-with-same-frozen-plan-matches-after-stage-advance",
		started == TransitionResult::Applied && MatchesEmergencyRecoveryJournal(*admission, checkpoint));
	const auto advanced = EncodeJournal(checkpoint);
	damaged = storage;
	if (advanced.size() == journalBytes) {
		for (auto i = size_t(0); i != journalBytes; ++i) {
			damaged[journalOffset + i] = std::to_integer<uint8_t>(advanced[i]);
		}
	}
	Check("already-started-phase-cannot-be-initial-committed-recovery",
		advanced.size() == journalBytes && !decode(damaged));
	checkpoint.accounts.front().sessionIdsForRevoke = { SessionId("different-session") };
	Check("checkpoint-cannot-override-selected-remote-device",
		!MatchesEmergencyRecoveryJournal(*admission, checkpoint));
	checkpoint = admission->journal;
	checkpoint.accounts.front().accountId = AccountId("different-target");
	Check("checkpoint-cannot-override-the-frozen-account-map",
		!MatchesEmergencyRecoveryJournal(*admission, checkpoint));
}

} // namespace

int main() {
	RunFixture();
	return failures ? 1 : 0;
}
