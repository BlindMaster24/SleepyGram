// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_rule_vault.h"

#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <memory>
#include <ranges>
#include <set>
#include <string_view>

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kHeader = std::array<uint8_t, 8>{ 'S', 'G', 'E', 'R', 0, 0, 0, 1 };
constexpr auto kKeyBytes = size_t(32);
constexpr auto kNonceBytes = size_t(12);
constexpr auto kTagBytes = size_t(16);
constexpr auto kOverhead = kNonceBytes + kTagBytes;
constexpr auto kMasterBytes = size_t(8192);
constexpr auto kRuleBytes = size_t(65536);
constexpr auto kSealedSlotBytes = kRuleBytes + kOverhead;
constexpr auto kRecordsOffset = kHeader.size() + kMasterBytes + kOverhead;
constexpr auto kSealedBytes = kRecordsOffset + kMaxSealedEmergencyRules * kSealedSlotBytes;
constexpr auto kMasterSlot = kMaxSealedEmergencyRules;
constexpr auto kMaxIdBytes = size_t(128);
constexpr auto kMaxNameBytes = size_t(256);
constexpr auto kMaxNormalCredentials = size_t(256);
constexpr auto kMaxAccounts = size_t(64);
constexpr auto kMaxSessionsPerAccount = size_t(128);
constexpr auto kMaxSessionsPerRule = size_t(256);
constexpr auto kMaxSnapshotSessions = kMaxSessionsPerRule + kMaxAccounts;
constexpr auto kMaxSafeProfileAccounts = size_t(256);
constexpr auto kReviewedSnapshotVersion = uint64_t(1);

template <size_t Size>
class Secret final {
public:
	Secret() = default;
	Secret(const Secret&) = delete;
	Secret &operator=(const Secret&) = delete;
	~Secret() {
		OPENSSL_cleanse(data.data(), data.size());
	}

	std::array<uint8_t, Size> data{};

};

using Key = Secret<kKeyBytes>;

struct SlotSecrets final {
	Key key;
	Secret<kCredentialVerifierBytes> verifier;
};

struct MasterRule final {
	NamedEmergencyRule named;
	std::optional<LiveInstallation> reviewedLive;
	std::unique_ptr<SlotSecrets> secrets;
};

struct RuleRecord final {
	EmergencyRuleDetails details;
	std::optional<LiveInstallation> reviewedLive;
};

bool ValidId(std::string_view value) {
	return !value.empty()
		&& value.size() <= kMaxIdBytes
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9')
				|| ch == '-' || ch == '_' || ch == '.' || ch == ':';
		});
}

bool ValidName(std::string_view value) {
	return !value.empty()
		&& value.size() <= kMaxNameBytes
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return ch >= 32 && ch != 127;
		});
}

bool ValidGeneration(const EmergencyRuleGeneration &generation) {
	return ValidId(generation.installationId.value)
		&& ValidId(generation.transactionId);
}

bool ValidKey(std::span<const uint8_t> key) {
	return key.size() == kKeyBytes
		&& std::ranges::any_of(key, [](auto value) { return value != 0; });
}

bool Same(std::span<const uint8_t> first, std::span<const uint8_t> second) {
	return first.size() == second.size()
		&& CRYPTO_memcmp(first.data(), second.data(), first.size()) == 0;
}

bool Hash(std::span<const uint8_t> input, std::span<uint8_t, kKeyBytes> result) {
	auto size = 0U;
	return EVP_Digest(input.data(), input.size(), result.data(), &size,
		EVP_sha256(), nullptr) == 1 && size == result.size();
}

bool DeriveSlotKey(std::span<const uint8_t> key, bool master, Key &result) {
	const auto label = master
		? std::string_view("SleepyGram emergency rule management v1")
		: std::string_view("SleepyGram emergency rule credential v1");
	auto size = 0U;
	return ValidKey(key)
		&& HMAC(
			EVP_sha256(),
			key.data(),
			int(key.size()),
			reinterpret_cast<const uint8_t*>(label.data()),
			label.size(),
			result.data.data(),
			&size)
		&& size == result.data.size();
}

std::string AssociatedData(const EmergencyRuleGeneration &generation, size_t slot) {
	auto result = std::string(kHeader.begin(), kHeader.end());
	result.append(generation.installationId.value);
	result.push_back('\0');
	result.append(generation.transactionId);
	result.push_back('\0');
	result.push_back(char(slot));
	return result;
}

bool Crypt(
		bool encrypt,
		const Key &key,
		std::string_view aad,
		std::span<const uint8_t> nonce,
		std::span<const uint8_t> input,
		std::span<uint8_t> output,
		std::span<uint8_t> tag) {
	auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
		EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	auto size = 0;
	if (!context
		|| EVP_CipherInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
			nullptr, nullptr, encrypt ? 1 : 0) != 1
		|| EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
			int(nonce.size()), nullptr) != 1
		|| EVP_CipherInit_ex(context.get(), nullptr, nullptr, key.data.data(),
			nonce.data(), -1) != 1
		|| EVP_CipherUpdate(context.get(), nullptr, &size,
			reinterpret_cast<const uint8_t*>(aad.data()), int(aad.size())) != 1
		|| EVP_CipherUpdate(context.get(), output.data(), &size,
			input.data(), int(input.size())) != 1
		|| size != int(input.size())) {
		return false;
	}
	if (!encrypt && EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
			int(tag.size()), tag.data()) != 1) {
		return false;
	}
	auto tail = std::array<uint8_t, EVP_MAX_BLOCK_LENGTH>{};
	const auto final = EVP_CipherFinal_ex(context.get(), tail.data(), &size);
	OPENSSL_cleanse(tail.data(), tail.size());
	return final == 1 && size == 0
		&& (!encrypt || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
			int(tag.size()), tag.data()) == 1);
}

bool SealSlot(
		const Key &key,
		const EmergencyRuleGeneration &generation,
		size_t slot,
		std::span<const uint8_t> plaintext,
		std::span<uint8_t> output) {
	const auto nonce = output.first(kNonceBytes);
	return RAND_bytes(nonce.data(), int(nonce.size())) == 1
		&& Crypt(true, key, AssociatedData(generation, slot), nonce, plaintext,
			output.subspan(kNonceBytes, plaintext.size()), output.last(kTagBytes));
}

bool OpenSlot(
		const Key &key,
		const EmergencyRuleGeneration &generation,
		size_t slot,
		std::span<const uint8_t> sealed,
		std::span<uint8_t> plaintext) {
	auto tag = std::array<uint8_t, kTagBytes>{};
	std::ranges::copy(sealed.last(kTagBytes), tag.begin());
	return Crypt(false, key, AssociatedData(generation, slot),
		sealed.first(kNonceBytes), sealed.subspan(kNonceBytes, plaintext.size()),
		plaintext, tag);
}

template <typename Byte>
std::span<Byte> RuleSlot(std::span<Byte> sealed, size_t index) {
	return sealed.subspan(kRecordsOffset + index * kSealedSlotBytes, kSealedSlotBytes);
}

class Writer final {
public:
	explicit Writer(std::span<uint8_t> output) : _available(output) {
	}

	bool write(std::span<const uint8_t> value) {
		if (value.size() > _available.size()) {
			return false;
		}
		std::ranges::copy(value, _available.begin());
		_available = _available.subspan(value.size());
		return true;
	}

	bool number(uint64_t value, size_t length) {
		auto bytes = std::array<uint8_t, sizeof(value)>{};
		for (auto i = size_t(0); i != length; ++i) {
			bytes[i] = uint8_t(value >> (8 * i));
		}
		return write(std::span(bytes).first(length));
	}

	bool string(std::string_view value) {
		return number(value.size(), 2)
			&& write({ reinterpret_cast<const uint8_t*>(value.data()), value.size() });
	}

private:
	std::span<uint8_t> _available;

};

class Reader final {
public:
	explicit Reader(std::span<const uint8_t> input) : _available(input) {
	}

	bool read(std::span<uint8_t> value) {
		if (value.size() > _available.size()) {
			return false;
		}
		std::ranges::copy(_available.first(value.size()), value.begin());
		_available = _available.subspan(value.size());
		return true;
	}

	bool number(uint64_t &value, size_t length) {
		auto bytes = std::array<uint8_t, sizeof(value)>{};
		if (!read(std::span(bytes).first(length))) {
			return false;
		}
		value = 0;
		for (auto i = size_t(0); i != length; ++i) {
			value |= uint64_t(bytes[i]) << (8 * i);
		}
		return true;
	}

	bool string(std::string &value, size_t maximum = kMaxIdBytes) {
		auto size = uint64_t(0);
		if (!number(size, 2) || size > maximum || size > _available.size()) {
			return false;
		}
		value.assign(reinterpret_cast<const char*>(_available.data()), size_t(size));
		_available = _available.subspan(size_t(size));
		return true;
	}

	[[nodiscard]] bool finished() const {
		return std::ranges::all_of(_available, [](auto byte) { return byte == 0; });
	}

private:
	std::span<const uint8_t> _available;

};

template <typename Id>
bool WriteIds(Writer &writer, const std::vector<Id> &ids) {
	return writer.number(ids.size(), 2)
		&& std::ranges::all_of(ids, [&](const auto &id) {
			return writer.string(id.value);
		});
}

template <typename Id>
bool ReadIds(Reader &reader, std::vector<Id> &ids, size_t bound) {
	auto size = uint64_t(0);
	if (!reader.number(size, 2) || size > bound) {
		return false;
	}
	ids.resize(size_t(size));
	return std::ranges::all_of(ids, [&](auto &id) { return reader.string(id.value); });
}

bool ValidRule(
		const EmergencyRuleDetails &record,
		const InstallationId &installation) {
	const auto &rule = record.rule;
	if (!ValidId(record.actionId.value) || !ValidId(record.operationId.value)
		|| !ValidId(rule.id.value) || !record.revision
		|| (record.executionCapsuleDigest
			&& !ValidKey(*record.executionCapsuleDigest))
		|| (!rule.safeProfileId.value.empty() && !ValidId(rule.safeProfileId.value))
		|| rule.installationId != installation
		|| unsigned(rule.action) > unsigned(EmergencyAction::RemoveInstallation)
		|| unsigned(rule.targetScope) > unsigned(TargetScope::CurrentInstallation)
		|| rule.selectedAccountIds.size() > kMaxAccounts
		|| rule.remoteSessionPolicies.size() > kMaxAccounts
		|| !std::ranges::all_of(rule.selectedAccountIds, [](const auto &id) {
			return ValidId(id.value);
		})) {
		return false;
	}
	auto sessions = size_t(0);
	for (const auto &policy : rule.remoteSessionPolicies) {
		sessions += policy.selectedSessionIds.size();
		if (!ValidId(policy.accountId.value)
			|| (rule.targetScope == TargetScope::SelectedAccounts
				&& std::ranges::find(rule.selectedAccountIds, policy.accountId)
					== rule.selectedAccountIds.end())
			|| policy.selectedSessionIds.size() > kMaxSessionsPerAccount
			|| sessions > kMaxSessionsPerRule
			|| !std::ranges::all_of(policy.selectedSessionIds, [](const auto &id) {
				return ValidId(id.value);
			})) {
			return false;
		}
	}
	return BuildDryRunPlan(record.operationId, rule, { .id = installation }).status
		== DryRunStatus::Ready;
}

std::optional<LiveInstallation> ProjectReviewedLive(
		const LiveInstallation &live,
		const DryRunPlan &plan) {
	if (plan.accounts.size() > kMaxAccounts
		|| plan.safeProfileAccountIds.size() > kMaxSafeProfileAccounts) {
		return std::nullopt;
	}
	auto result = LiveInstallation{ .id = live.id };
	auto sessions = size_t(0);
	for (const auto &target : plan.accounts) {
		const auto account = std::ranges::find(live.accounts, target.accountId, &LiveAccount::id);
		const auto &remote = target.sessionIdsForRevokeRequest;
		sessions += remote.size() + 1;
		if (account == live.accounts.end()
			|| !ValidId(account->id.value) || !ValidId(account->currentSessionId.value)
			|| remote.size() > kMaxSessionsPerAccount || sessions > kMaxSnapshotSessions
			|| !std::ranges::all_of(remote, [](const auto &session) {
				return ValidId(session.value);
			})) {
			return std::nullopt;
		}
		auto row = LiveAccount{
			.id = account->id,
			.currentSessionId = account->currentSessionId,
			.sessionIds = { account->currentSessionId },
		};
		row.sessionIds.insert(row.sessionIds.end(), remote.begin(), remote.end());
		result.accounts.push_back(std::move(row));
	}
	if (plan.safeDestination == SafeDestinationKind::Profile) {
		if (!ValidId(plan.safeProfileId.value)
			|| !std::ranges::all_of(plan.safeProfileAccountIds, [](const auto &id) {
				return ValidId(id.value);
			})) {
			return std::nullopt;
		}
		result.profiles.push_back({ plan.safeProfileId, plan.safeProfileAccountIds });
	}
	return result;
}

bool ValidReviewedLive(const EmergencyRuleDetails &record, const LiveInstallation &snapshot) {
	const auto plan = BuildDryRunPlan(record.operationId, record.rule, snapshot);
	const auto projected = ProjectReviewedLive(snapshot, plan);
	return MakeJournal(plan) && projected
		&& std::ranges::equal(snapshot.accounts, projected->accounts,
			[](const auto &first, const auto &second) {
				return first.id == second.id
					&& first.currentSessionId == second.currentSessionId
					&& first.sessionIds == second.sessionIds;
			})
		&& std::ranges::equal(snapshot.profiles, projected->profiles,
			[](const auto &first, const auto &second) {
				return first.id == second.id && first.accountIds == second.accountIds;
			});
}

bool WriteReviewedLive(Writer &writer, const LiveInstallation &live) {
	return writer.number(kReviewedSnapshotVersion, 1)
		&& writer.number(live.accounts.size(), 2)
		&& std::ranges::all_of(live.accounts, [&](const auto &account) {
			const auto otherSessions = std::span(account.sessionIds).subspan(1);
			return writer.string(account.id.value)
				&& writer.string(account.currentSessionId.value)
				&& writer.number(otherSessions.size(), 2)
				&& std::ranges::all_of(otherSessions, [&](const auto &session) {
					return writer.string(session.value);
				});
		})
		&& writer.number(live.profiles.size(), 1)
		&& std::ranges::all_of(live.profiles, [&](const auto &profile) {
			return writer.string(profile.id.value) && WriteIds(writer, profile.accountIds);
		});
}

std::optional<LiveInstallation> ReadReviewedLive(
		Reader &reader,
		const EmergencyRuleDetails &record) {
	auto version = uint64_t(0);
	auto accounts = uint64_t(0);
	if (!reader.number(version, 1) || version != kReviewedSnapshotVersion
		|| !reader.number(accounts, 2) || accounts > kMaxAccounts) {
		return std::nullopt;
	}
	auto live = LiveInstallation{ .id = record.rule.installationId };
	live.accounts.resize(size_t(accounts));
	auto sessions = size_t(0);
	for (auto &account : live.accounts) {
		if (!reader.string(account.id.value)
			|| !reader.string(account.currentSessionId.value)
			|| !ReadIds(reader, account.sessionIds, kMaxSessionsPerAccount)) {
			return std::nullopt;
		}
		sessions += account.sessionIds.size() + 1;
		if (sessions > kMaxSnapshotSessions) {
			return std::nullopt;
		}
		account.sessionIds.insert(account.sessionIds.begin(), account.currentSessionId);
	}
	auto profiles = uint64_t(0);
	if (!reader.number(profiles, 1) || profiles > 1) {
		return std::nullopt;
	}
	if (profiles) {
		auto profile = LiveProfile();
		if (!reader.string(profile.id.value)
			|| !ReadIds(reader, profile.accountIds, kMaxSafeProfileAccounts)) {
			return std::nullopt;
		}
		live.profiles.push_back(std::move(profile));
	}
	return ValidReviewedLive(record, live) ? std::optional(std::move(live)) : std::nullopt;
}

bool WriteRule(
		Writer &writer,
		const EmergencyRuleDetails &record,
		const std::optional<LiveInstallation> &reviewedLive) {
	const auto &rule = record.rule;
	return writer.string(record.actionId.value)
		&& writer.string(record.operationId.value)
		&& writer.number(record.revision, 8)
		&& writer.string(rule.id.value)
		&& writer.number(uint8_t(rule.action), 1)
		&& writer.number(uint8_t(rule.targetScope), 1)
		&& writer.string(rule.safeProfileId.value)
		&& WriteIds(writer, rule.selectedAccountIds)
		&& writer.number(rule.remoteSessionPolicies.size(), 2)
		&& std::ranges::all_of(rule.remoteSessionPolicies, [&](const auto &policy) {
			return writer.string(policy.accountId.value)
				&& writer.number(uint8_t(policy.kind), 1)
				&& WriteIds(writer, policy.selectedSessionIds);
		})
		&& writer.number(record.executionCapsuleDigest.has_value(), 1)
		&& (!record.executionCapsuleDigest
			|| (reviewedLive && writer.write(*record.executionCapsuleDigest)
				&& WriteReviewedLive(writer, *reviewedLive)));
}

std::optional<RuleRecord> ReadRule(
		std::span<const uint8_t> bytes,
		const InstallationId &installation) {
	auto reader = Reader(bytes);
	auto result = RuleRecord();
	auto &record = result.details;
	auto &rule = record.rule;
	rule.installationId = installation;
	auto action = uint64_t(0);
	auto scope = uint64_t(0);
	auto policies = uint64_t(0);
	if (!reader.string(record.actionId.value)
		|| !reader.string(record.operationId.value)
		|| !reader.number(record.revision, 8)
		|| !reader.string(rule.id.value)
		|| !reader.number(action, 1)
		|| !reader.number(scope, 1)
		|| !reader.string(rule.safeProfileId.value)
		|| !ReadIds(reader, rule.selectedAccountIds, kMaxAccounts)
		|| !reader.number(policies, 2) || policies > kMaxAccounts) {
		return std::nullopt;
	}
	rule.action = EmergencyAction(action);
	rule.targetScope = TargetScope(scope);
	rule.remoteSessionPolicies.resize(size_t(policies));
	for (auto &policy : rule.remoteSessionPolicies) {
		auto kind = uint64_t(0);
		if (!reader.string(policy.accountId.value)
			|| !reader.number(kind, 1)
			|| !ReadIds(reader, policy.selectedSessionIds, kMaxSessionsPerAccount)) {
			return std::nullopt;
		}
		policy.kind = RemoteSessionTargetKind(kind);
	}
	// Earlier v1 slots left zero padding here.
	auto hasCapsule = uint64_t(0);
	if (!reader.number(hasCapsule, 1) || hasCapsule > 1) {
		return std::nullopt;
	}
	if (hasCapsule) {
		if (!reader.read(record.executionCapsuleDigest.emplace())) {
			return std::nullopt;
		}
		result.reviewedLive = ReadReviewedLive(reader, record);
		if (!result.reviewedLive) {
			return std::nullopt;
		}
	}
	if (!reader.finished() || !ValidRule(record, installation)) {
		return std::nullopt;
	}
	return result;
}

bool ValidBlob(
		const EmergencyRuleAuthority &authority,
		std::span<const uint8_t> sealed) {
	auto digest = decltype(authority.digest){};
	return ValidGeneration(authority.generation)
		&& sealed.size() == kSealedBytes
		&& std::ranges::equal(kHeader, sealed.first(kHeader.size()))
		&& Hash(sealed, digest)
		&& Same(authority.digest, digest);
}

std::optional<SealedEmergencyRules> SealMasterRules(
		const EmergencyRuleGeneration &generation,
		std::span<const uint8_t> masterDerivedKey,
		std::span<const MasterRule> rules) {
	auto masterKey = Key();
	if (!DeriveSlotKey(masterDerivedKey, true, masterKey)) {
		return std::nullopt;
	}
	auto result = SealedEmergencyRules{ .authority = { .generation = generation } };
	result.bytes.resize(kSealedBytes);
	auto sealed = std::span(result.bytes);
	if (RAND_bytes(sealed.data(), int(sealed.size())) != 1) {
		return std::nullopt;
	}
	std::ranges::copy(kHeader, sealed.begin());
	auto master = Secret<kMasterBytes>();
	auto index = Writer(master.data);
	if (!index.number(rules.size(), 2)) {
		return std::nullopt;
	}
	for (auto i = size_t(0); i != rules.size(); ++i) {
		const auto &rule = rules[i];
		auto plaintext = Secret<kRuleBytes>();
		auto writer = Writer(plaintext.data);
		if (!WriteRule(writer, rule.named.details, rule.reviewedLive)
			|| !index.string(rule.named.name)
			|| !index.write(rule.secrets->verifier.data)
			|| !index.write(rule.secrets->key.data)
			|| !SealSlot(
				rule.secrets->key,
				generation,
				i,
				plaintext.data,
				RuleSlot(sealed, i))) {
			return std::nullopt;
		}
	}
	if (!SealSlot(
			masterKey,
			generation,
			kMasterSlot,
			master.data,
			sealed.subspan(kHeader.size(), kMasterBytes + kOverhead))
		|| !Hash(sealed, result.authority.digest)) {
		return std::nullopt;
	}
	return result;
}

std::optional<std::vector<MasterRule>> OpenMasterRules(
		const EmergencyRuleAuthority &authority,
		std::span<const uint8_t> sealed,
		std::span<const uint8_t> masterDerivedKey) {
	auto key = Key();
	auto master = Secret<kMasterBytes>();
	if (!ValidBlob(authority, sealed)
		|| !DeriveSlotKey(masterDerivedKey, true, key)
		|| !OpenSlot(
			key,
			authority.generation,
			kMasterSlot,
			sealed.subspan(kHeader.size(), kMasterBytes + kOverhead),
			master.data)) {
		return std::nullopt;
	}
	auto index = Reader(master.data);
	auto size = uint64_t(0);
	if (!index.number(size, 2) || size > kMaxSealedEmergencyRules) {
		return std::nullopt;
	}
	auto result = std::vector<MasterRule>();
	auto plaintext = Secret<kRuleBytes>();
	for (auto i = size_t(0); i != size; ++i) {
		auto rule = MasterRule{ .secrets = std::make_unique<SlotSecrets>() };
		if (!index.string(rule.named.name, kMaxNameBytes)
			|| !ValidName(rule.named.name)
			|| !index.read(rule.secrets->verifier.data)
			|| !index.read(rule.secrets->key.data)
			|| !OpenSlot(
				rule.secrets->key,
				authority.generation,
				i,
				RuleSlot(sealed, i),
				plaintext.data)) {
			return std::nullopt;
		}
		auto opened = ReadRule(plaintext.data, authority.generation.installationId);
		if (!opened) {
			return std::nullopt;
		}
		rule.named.details = std::move(opened->details);
		result.push_back(std::move(rule));
	}
	return index.finished() ? std::optional(std::move(result)) : std::nullopt;
}

} // namespace

size_t SealedEmergencyRulesSize() {
	return kSealedBytes;
}

std::optional<SealedEmergencyRules> SealEmergencyRules(
		const EmergencyRuleGeneration &generation,
		std::span<const uint8_t> masterDerivedKey,
		const RuleConfiguration &configuration,
		const LiveInstallation &reviewedLive,
		std::span<const EmergencyRuleSealInput> entries) {
	if (!ValidGeneration(generation)
		|| !ValidKey(masterDerivedKey)
		|| generation.installationId != configuration.activeInstallationId
		|| generation.installationId != reviewedLive.id
		|| configuration.normalCredentials.size() > kMaxNormalCredentials
		|| entries.size() > kMaxSealedEmergencyRules
		|| entries.size() != configuration.emergencyRules.size()
		|| ValidateRuleConfiguration(configuration) != RuleValidationError::None) {
		return std::nullopt;
	}
	auto actionIds = std::set<EmergencyActionId>();
	auto operationIds = std::set<OperationId>();
	auto rules = std::vector<MasterRule>();
	for (const auto &entry : entries) {
		const auto draft = std::ranges::find(
			configuration.emergencyRules,
			entry.actionId,
			&EmergencyRuleDraft::id);
		if (draft == configuration.emergencyRules.end() || !draft->confirmed
			|| !actionIds.insert(entry.actionId).second || !ValidName(entry.name)
			|| !Same(draft->verifier, entry.verifier)
			|| Same(masterDerivedKey, entry.key)) {
			return std::nullopt;
		}
		const auto &reviewed = draft->confirmed->reviewedPlan;
		auto record = EmergencyRuleDetails{
			.actionId = draft->id,
			.rule = draft->rule,
			.operationId = reviewed.operationId,
			.revision = draft->revision,
			.executionCapsuleDigest = entry.executionCapsuleDigest,
		};
		if (!ValidRule(record, generation.installationId)
			|| !operationIds.insert(record.operationId).second
			|| BuildDryRunPlan(record.operationId, record.rule, reviewedLive) != reviewed
			|| !MakeJournal(reviewed)) {
			return std::nullopt;
		}
		auto snapshot = std::optional<LiveInstallation>();
		if (record.executionCapsuleDigest) {
			snapshot = ProjectReviewedLive(reviewedLive, reviewed);
			if (!snapshot || BuildDryRunPlan(record.operationId, record.rule, *snapshot) != reviewed) {
				return std::nullopt;
			}
		}
		auto secrets = std::make_unique<SlotSecrets>();
		if (!DeriveSlotKey(entry.key, false, secrets->key)
			|| std::ranges::any_of(rules, [&](const auto &prior) {
				return Same(prior.secrets->key.data, secrets->key.data);
			})) {
			return std::nullopt;
		}
		secrets->verifier.data = entry.verifier;
		rules.push_back({
			.named = { .name = entry.name, .details = std::move(record) },
			.reviewedLive = std::move(snapshot),
			.secrets = std::move(secrets),
		});
	}
	return SealMasterRules(generation, masterDerivedKey, rules);
}

EmergencyRuleAuthentication AuthenticateEmergencyRule(
		const EmergencyRuleAuthority &authority,
		std::span<const uint8_t> sealed,
		std::span<const uint8_t> derivedKey) {
	if (!ValidBlob(authority, sealed)) {
		return EmergencyVaultUnavailable();
	}
	auto key = Key();
	if (!DeriveSlotKey(derivedKey, false, key)) {
		return WrongPasscode();
	}
	auto opened = std::optional<RuleRecord>();
	auto plaintext = Secret<kRuleBytes>();
	for (auto i = size_t(0); i != kMaxSealedEmergencyRules; ++i) {
		if (OpenSlot(key, authority.generation, i, RuleSlot(sealed, i), plaintext.data)) {
			if (opened) {
				return EmergencyVaultUnavailable();
			}
			opened = ReadRule(plaintext.data, authority.generation.installationId);
			if (!opened) {
				return EmergencyVaultUnavailable();
			}
		}
	}
	if (!opened) {
		return WrongPasscode();
	}
	return EmergencyRuleTicket(
		authority,
		std::move(opened->details),
		std::move(opened->reviewedLive));
}

std::optional<std::vector<NamedEmergencyRule>> OpenEmergencyRulesForMaster(
		const EmergencyRuleAuthority &authority,
		std::span<const uint8_t> sealed,
		std::span<const uint8_t> masterDerivedKey) {
	auto rules = OpenMasterRules(authority, sealed, masterDerivedKey);
	if (!rules) {
		return std::nullopt;
	}
	auto result = std::vector<NamedEmergencyRule>();
	result.reserve(rules->size());
	for (auto &rule : *rules) {
		result.push_back(std::move(rule.named));
	}
	return result;
}

std::optional<SealedEmergencyRules> RebindEmergencyRulesForMaster(
		const EmergencyRuleAuthority &previousAuthority,
		std::span<const uint8_t> previousSealed,
		std::span<const uint8_t> previousMasterDerivedKey,
		const EmergencyRuleGeneration &nextGeneration,
		const LiveInstallation &nextLive,
		const EmergencyRuleMasterContext &nextMaster) {
	if (!ValidGeneration(nextGeneration)
		|| nextGeneration == previousAuthority.generation
		|| nextGeneration.installationId != previousAuthority.generation.installationId
		|| nextGeneration.installationId != nextLive.id
		|| nextMaster.normalCredentials.size() > kMaxNormalCredentials) {
		return std::nullopt;
	}
	const auto base = RuleConfiguration{
		.activeInstallationId = nextGeneration.installationId,
		.masterVerifier = nextMaster.verifier,
		.normalCredentials = {
			nextMaster.normalCredentials.begin(),
			nextMaster.normalCredentials.end(),
		},
	};
	auto nextMasterSlotKey = Key();
	if (ValidateRuleConfiguration(base) != RuleValidationError::None
		|| !DeriveSlotKey(nextMaster.derivedKey, false, nextMasterSlotKey)) {
		return std::nullopt;
	}
	const auto rules = OpenMasterRules(
		previousAuthority,
		previousSealed,
		previousMasterDerivedKey);
	if (!rules) {
		return std::nullopt;
	}
	for (const auto &rule : *rules) {
		const auto &details = rule.named.details;
		const auto &verifier = rule.secrets->verifier.data;
		if (details.executionCapsuleDigest
			|| Same(rule.secrets->key.data, nextMasterSlotKey.data)
			|| Same(verifier, nextMaster.verifier)
			|| std::ranges::any_of(nextMaster.normalCredentials, [&](const auto &normal) {
				return Same(normal.verifier, verifier);
			})
			|| !MakeJournal(BuildDryRunPlan(details.operationId, details.rule, nextLive))) {
			return std::nullopt;
		}
	}
	return SealMasterRules(nextGeneration, nextMaster.derivedKey, *rules);
}

} // namespace Ayu::EmergencyActions
