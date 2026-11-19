// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_emergency_rebind.h"

#include <QtCore/QtEndian>

#include <openssl/crypto.h>

#include <algorithm>
#include <set>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;

std::span<const uint8_t> Bytes(QByteArrayView value) {
	return { reinterpret_cast<const uint8_t*>(value.data()), size_t(value.size()) };
}

QByteArray ByteArray(std::span<const uint8_t> value) {
	return { reinterpret_cast<const char*>(value.data()), qsizetype(value.size()) };
}

template <typename Id>
std::string Identifier(Id id) {
	auto bytes = std::array<char, 16>();
	qToBigEndian(id.high, bytes.data());
	qToBigEndian(id.low, bytes.data() + 8);
	return QByteArrayView(bytes.data(), bytes.size()).toByteArray().toHex().toStdString();
}

bool MatchesEnrollment(
		const DerivedCredential &master,
		const RevocableAdminVaultAccess &before,
		const Metadata &after,
		const AccountGateTable &current,
		const CreatedAccountGate &added,
		const EA::EmergencyScopedRemoteIdentity &identity) {
	const auto id = added.handle.binding().id;
	if (!master.valid() || master.verifier != before.metadata.masterVerifier
		|| after.masterVerifier != master.verifier
		|| after.verifierSalt != before.metadata.verifierSalt
		|| after.verifierKdf != before.metadata.verifierKdf
		|| !identity.userId || identity.userId > 0xFFFFFFFFFFFFULL
		|| (identity.environment != EA::EmergencyScopedEnvironment::Production
			&& identity.environment != EA::EmergencyScopedEnvironment::Test)
		|| !added.handle.matches(added.permit) || !id
		|| current.installationId() != added.table.installationId()
		|| current.size() != before.accounts.size() || added.table.size() != current.size() + 1
		|| InspectAccountGate(current, added.handle) != AccountGateStatus::Unavailable
		|| InspectAccountGate(added.table, added.handle) != AccountGateStatus::Active
		|| std::ranges::count_if(after.sets, [&](const auto &set) {
			return std::ranges::find(set.accounts, id) != set.accounts.end();
		}) != 1) {
		return false;
	}
	auto active = std::vector<AccountGateBinding>();
	auto known = std::set<AccountId>();
	for (const auto &grant : before.accounts) {
		const auto &binding = grant.handle.binding();
		const auto status = InspectAccountGate(current, grant.handle);
		if (!grant.handle.matches(grant.permit) || !known.insert(binding.id).second
			|| status == AccountGateStatus::Unavailable || status != InspectAccountGate(added.table, grant.handle)) {
			return false;
		}
		if (status == AccountGateStatus::Active) {
			active.push_back(binding);
		}
	}
	if (!current.coversActiveBindings(active)) {
		return false;
	}
	active.push_back(added.handle.binding());
	return added.table.coversActiveBindings(active);
}

std::optional<RevocableEmergencyAccount> NewRuleAccount(
		const CreatedAccountGate &added,
		EA::EmergencyScopedRemoteIdentity identity) {
	auto handleBytes = added.handle.serialize();
	auto permitBytes = added.permit.serialize();
	const auto wipe = gsl::finally([&] {
		OPENSSL_cleanse(handleBytes.data(), size_t(handleBytes.size()));
		OPENSSL_cleanse(permitBytes.data(), size_t(permitBytes.size()));
	});
	auto handle = AccountGateHandle::Parse(handleBytes);
	auto permit = AccountGateRevocationPermit::Parse(permitBytes);
	return (handle && permit)
		? std::optional(RevocableEmergencyAccount{ std::move(*handle), std::move(*permit), identity })
		: std::nullopt;
}

bool CoversCurrentAccounts(
		const AccountGateTable &current,
		std::span<const RevocableEmergencyAccount> reviewed) {
	auto active = std::vector<AccountGateBinding>();
	for (const auto &account : reviewed) {
		if (InspectAccountGate(current, account.handle) == AccountGateStatus::Active) {
			active.push_back(account.handle.binding());
		}
	}
	return current.coversActiveBindings(active);
}

} // namespace

std::optional<QByteArray> RebindRevocableEmergencyRulesForEnrollment(
		QByteArrayView currentRules,
		const DerivedCredential &master,
		const RevocableAdminVaultAccess &before,
		const Metadata &after,
		const AccountGateTable &currentGates,
		const CreatedAccountGate &added,
		EA::EmergencyScopedRemoteIdentity enrolledIdentity,
		const ResolveRevocableEmergencyPackage &resolvePackage) {
	const auto &installation = currentGates.installationId();
	if (!MatchesEnrollment(master, before, after, currentGates, added, enrolledIdentity)) {
		return std::nullopt;
	}
	if (currentRules.isEmpty()) {
		return QByteArray();
	}
	auto bundle = ParseRevocableProfileEmergencyBundle(installation, currentRules);
	if (!bundle) {
		return std::nullopt;
	}
	const auto authority = bundle->rules.authority;
	auto verifier = EA::CredentialVerifier();
	std::ranges::copy(Bytes(master.verifier), verifier.begin());
	auto normals = std::vector<EA::NormalCredential>();
	for (const auto &set : after.sets) {
		auto entry = EA::NormalCredential{ .id = EA::NormalPasscodeId(Identifier(set.id)) };
		if (size_t(set.verifier.size()) != entry.verifier.size()) {
			return std::nullopt;
		}
		std::ranges::copy(Bytes(set.verifier), entry.verifier.begin());
		normals.push_back(std::move(entry));
	}
	const auto masterContext = EA::EmergencyRuleMasterContext{ Bytes(master.key), verifier, normals };
	const auto enrolledId = EA::AccountId(Identifier(added.handle.binding().id));
	auto known = std::set<QByteArray>();
	auto removalPackage = std::optional<EA::EmergencyExecutionCapsuleDigest>();
	const auto expectedRules = bundle->rules.capsules.size() + bundle->consumed.size();
	const auto rewritten = EA::RewriteEmergencyRulesForMaster(authority, Bytes(bundle->rules.rules), masterContext,
		[&](const EA::EmergencyRuleTicket &ticket, EA::EmergencyExecutionCapsuleKey key)
		-> EA::EmergencyRuleRewriteDecision {
			const auto reject = EA::RejectEmergencyRuleRewrite();
			const auto &details = ticket.details();
			const auto previous = ticket.reviewedLive();
			if (!previous || !details.executionCapsuleDigest) {
				return reject;
			}
			const auto digest = ByteArray(*details.executionCapsuleDigest);
			if (!known.insert(digest).second) {
				return reject;
			}
			if (bundle->consumed.contains(digest)) {
				return EA::KeepEmergencyRule();
			}
			const auto capsule = bundle->rules.capsules.find(digest);
			if (capsule == end(bundle->rules.capsules)) {
				return reject;
			}
			if (details.rule.targetScope == EA::TargetScope::SelectedAccounts) {
				return EA::KeepEmergencyRule();
			}
			auto package = std::optional<EA::EmergencyExecutionCapsuleDigest>();
			if (details.rule.action == EA::EmergencyAction::RemoveInstallation) {
				if (!removalPackage && resolvePackage) {
					try {
						removalPackage = resolvePackage(authority.generation.installationId);
					} catch (...) {
						return reject;
					}
				}
				if (!removalPackage) {
					return reject;
				}
				package = removalPackage;
			}
			auto opened = OpenRevocableEmergencyCapabilityForRebind(authority.generation,
				ticket, currentGates, Bytes(capsule->second), package, key, RevocableEmergencyTargets::Reviewed);
			const auto capability = std::get_if<OpenedRevocableEmergencyCapability>(&opened);
			if (!capability || !CoversCurrentAccounts(currentGates, capability->accounts())
				|| std::ranges::any_of(details.rule.remoteSessionPolicies, [&](const auto &policy) {
					return policy.accountId == enrolledId && policy.kind != EA::RemoteSessionTargetKind::None;
				})) {
				return reject;
			}
			auto account = NewRuleAccount(added, enrolledIdentity);
			if (!account) {
				return reject;
			}
			const auto current = EA::SessionId("current");
			auto live = *previous;
			live.accounts.insert(std::ranges::lower_bound(live.accounts, enrolledId, {}, &EA::LiveAccount::id),
				EA::LiveAccount{ enrolledId, current, { current } });
			auto accounts = std::move(*capability).takeAccounts();
			accounts.push_back(std::move(*account));
			const auto replacement = SealRevocableEmergencyCapabilityForRebind(authority.generation,
				details, live, added.table, accounts, capability->safeSet(), package, key,
				RevocableEmergencyTargets::Reviewed);
			if (!replacement || bundle->consumed.contains(ByteArray(replacement->digest))
				|| !bundle->rules.capsules.emplace(ByteArray(replacement->digest), ByteArray(replacement->bytes)).second) {
				return reject;
			}
			bundle->rules.capsules.erase(capsule);
			return EA::EmergencyRuleRewrite{ std::move(live), replacement->digest };
		});
	if (!rewritten || known.size() != expectedRules || rewritten->authority.generation != authority.generation) {
		return std::nullopt;
	}
	bundle->rules.authority = rewritten->authority;
	bundle->rules.rules = ByteArray(rewritten->bytes);
	auto sealed = SerializeRevocableProfileEmergencyBundle(*bundle);
	if (sealed.isEmpty() || !CanKeepRevocableProfileEmergencyRules(installation, sealed, master, before.metadata, after)) {
		return std::nullopt;
	}
	return sealed;
}

} // namespace Ayu::ProfileSets
