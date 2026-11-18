// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_execution_capsule.h"

#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <ranges>
#include <set>
#include <string_view>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kLegacyMagic = std::array<uint8_t, 8>{ 'S', 'G', 'E', 'C', 0, 0, 0, 1 };
constexpr auto kRebindableMagic = std::array<uint8_t, 8>{ 'S', 'G', 'E', 'C', 0, 0, 0, 2 };
constexpr auto kKeyBytes = size_t(32);
constexpr auto kNonceBytes = size_t(12);
constexpr auto kTagBytes = size_t(16);
constexpr auto kHeaderBytes = kRebindableMagic.size() + kNonceBytes;
constexpr auto kOverhead = kHeaderBytes + kTagBytes;
constexpr auto kMaxIdentityBytes = size_t(128);
constexpr auto kMaxMetadataBytes = size_t(32) * 1024;
constexpr auto kMaxSessionsPerAccount = size_t(128);
constexpr auto kMaxSessionsPerRule = size_t(256);
constexpr auto kMaxPlaintextBytes = kMaxMetadataBytes
	+ kMaxEmergencyExecutionSuccessorVaultBytes
	+ kMaxEmergencyExecutionSuccessorKeyringBytes
	+ kMaxEmergencyExecutionSafeGrantBytes;
constexpr auto kMaxUserId = uint64_t(0xFFFFFFFFFFFFULL);

struct SecretBytes final {
	SecretBytes() = default;
	SecretBytes(const SecretBytes&) = delete;
	SecretBytes &operator=(const SecretBytes&) = delete;
	~SecretBytes() {
		if (!bytes.empty()) {
			OPENSSL_cleanse(bytes.data(), bytes.size());
		}
	}

	std::vector<uint8_t> bytes;
};

struct Key final {
	Key() = default;
	Key(const Key&) = delete;
	Key &operator=(const Key&) = delete;
	~Key() {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}

	std::array<uint8_t, kKeyBytes> bytes{};
};

bool ValidId(std::string_view id) {
	return !id.empty() && id.size() <= kMaxIdentityBytes
		&& std::ranges::all_of(id, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9')
				|| ch == '-' || ch == '_' || ch == '.' || ch == ':';
		});
}

bool ValidLocator(std::string_view value) {
	return value.size() == 32 && value.find_first_not_of('0') != std::string_view::npos
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9');
		});
}

bool ValidKey(std::span<const uint8_t> key, size_t count) {
	return key.size() == count
		&& std::ranges::any_of(key, [](uint8_t ch) { return ch != 0; });
}

bool ValidRemoteIdentity(const EmergencyScopedRemoteIdentity &identity) {
	return identity.userId && identity.userId <= kMaxUserId
		&& (identity.environment == EmergencyScopedEnvironment::Production
			|| identity.environment == EmergencyScopedEnvironment::Test);
}

bool ValidRuleScope(const EmergencyRule &rule) {
	if (rule.selectedAccountIds.size() > kMaxEmergencyExecutionAccounts
		|| rule.remoteSessionPolicies.size() > kMaxEmergencyExecutionAccounts
		|| (rule.safeProfileId.valid() && !ValidId(rule.safeProfileId.value))
		|| !std::ranges::all_of(rule.selectedAccountIds, [](const auto &id) {
			return ValidId(id.value);
		})) {
		return false;
	}
	auto totalSessions = size_t(0);
	for (const auto &policy : rule.remoteSessionPolicies) {
		if (!ValidId(policy.accountId.value)
			|| policy.selectedSessionIds.size() > kMaxSessionsPerAccount
			|| !std::ranges::all_of(policy.selectedSessionIds, [](const auto &id) {
				return ValidId(id.value);
			})) {
			return false;
		}
		totalSessions += policy.selectedSessionIds.size();
	}
	return totalSessions <= kMaxSessionsPerRule;
}

bool ValidBinding(
		const EmergencyRuleGeneration &generation,
		const EmergencyRuleDetails &details,
		const DryRunPlan &plan) {
	const auto &rule = details.rule;
	return ValidId(generation.installationId.value)
		&& ValidLocator(generation.transactionId)
		&& ValidId(details.actionId.value) && details.revision
		&& ValidRuleScope(rule)
		&& rule.installationId == generation.installationId
		&& plan.installationId == generation.installationId
		&& details.operationId == plan.operationId
		&& rule.id == plan.ruleId && rule.action == plan.action
		&& rule.targetScope == plan.targetScope
		&& plan.accounts.size() <= kMaxEmergencyExecutionAccounts
		&& plan.issues.empty() && MakeJournal(plan)
		&& (plan.safeDestination != SafeDestinationKind::Profile
			|| plan.safeProfileId == rule.safeProfileId)
		&& std::ranges::all_of(plan.accounts, [&](const auto &account) {
			const auto &id = account.accountId;
			return account.wouldClearLocalData
				&& (rule.targetScope != TargetScope::SelectedAccounts
					|| std::ranges::find(rule.selectedAccountIds, id)
						!= rule.selectedAccountIds.end())
				&& std::ranges::find(plan.safeProfileAccountIds, id)
					== plan.safeProfileAccountIds.end();
		});
}

bool ValidPayload(
		const EmergencyRuleGeneration &generation,
		const DryRunPlan &plan,
		std::span<const EmergencyExecutionAccount> accounts,
		const EmergencyExecutionSuccessor &successor,
		const std::optional<EmergencyExecutionSafeDestination> &safeDestination) {
	if (accounts.size() != plan.accounts.size()
		|| !ValidLocator(successor.transactionId)
		|| successor.transactionId == generation.transactionId
		|| successor.sealedProfileVault.empty()
		|| successor.sealedProfileVault.size() > kMaxEmergencyExecutionSuccessorVaultBytes
		|| successor.sealedAccountKeyring.empty()
		|| successor.sealedAccountKeyring.size() > kMaxEmergencyExecutionSuccessorKeyringBytes
		|| (plan.action == EmergencyAction::RemoveInstallation
			? (successor.installationDigest.size() != kEmergencyInstallationDigestBytes
				|| std::ranges::none_of(successor.installationDigest, [](uint8_t byte) { return byte != 0; }))
			: !successor.installationDigest.empty())
		|| (safeDestination
			&& (plan.safeDestination != SafeDestinationKind::Profile
				|| safeDestination->profileId != plan.safeProfileId
				|| safeDestination->sealedSetGrant.empty()
				|| safeDestination->sealedSetGrant.size() > kMaxEmergencyExecutionSafeGrantBytes))) {
		return false;
	}
	auto ids = std::set<AccountId>();
	auto locators = std::set<std::string_view>();
	auto remoteIds = std::set<std::pair<EmergencyScopedEnvironment, uint64_t>>();
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto &account = accounts[i];
		const auto target = std::ranges::find(plan.accounts, account.accountId, &AccountDryRun::accountId);
		if (target == plan.accounts.end()
			|| !ValidId(account.accountId.value)
			|| !ids.insert(account.accountId).second
			|| !ValidLocator(account.locator)
			|| !locators.insert(account.locator).second
			|| !ValidKey(account.scopedKey, kEmergencyExecutionScopedKeyBytes)
			|| std::ranges::any_of(accounts.first(i), [&](const auto &prior) {
				return CRYPTO_memcmp(
					prior.scopedKey.data(),
					account.scopedKey.data(),
					kEmergencyExecutionScopedKeyBytes) == 0;
			})
			|| (!account.remoteIdentity && target->remoteTarget != RemoteSessionTargetKind::None)) {
			return false;
		}
		if (const auto &remote = account.remoteIdentity) {
			if (!ValidRemoteIdentity(*remote)
				|| !remoteIds.emplace(remote->environment, remote->userId).second) {
				return false;
			}
		}
	}
	return true;
}

class Writer final {
public:
	explicit Writer(std::vector<uint8_t> &bytes) : _bytes(bytes) {
	}

	void number(uint64_t value, size_t width) {
		for (auto i = size_t(0); i != width; ++i) {
			_bytes.push_back(uint8_t(value >> (8 * i)));
		}
	}

	void bytes(std::span<const uint8_t> value) {
		_bytes.insert(_bytes.end(), value.begin(), value.end());
	}

	void string(std::string_view value) {
		number(value.size(), 2);
		bytes({ reinterpret_cast<const uint8_t*>(value.data()), value.size() });
	}

	void blob(std::span<const uint8_t> value) {
		number(value.size(), 4);
		bytes(value);
	}

private:
	std::vector<uint8_t> &_bytes;

};

class Reader final {
public:
	explicit Reader(std::span<const uint8_t> bytes) : _available(bytes) {
	}

	bool bytes(std::span<const uint8_t> &result, size_t size) {
		if (size > _available.size()) {
			return false;
		}
		result = _available.first(size);
		_available = _available.subspan(size);
		return true;
	}

	bool number(uint64_t &result, size_t width) {
		auto encoded = std::span<const uint8_t>();
		if (!bytes(encoded, width)) {
			return false;
		}
		result = 0;
		for (auto i = size_t(0); i != width; ++i) {
			result |= uint64_t(encoded[i]) << (8 * i);
		}
		return true;
	}

	bool string(std::string &result) {
		auto size = uint64_t(0);
		auto encoded = std::span<const uint8_t>();
		if (!number(size, 2) || size > kMaxIdentityBytes || !bytes(encoded, size_t(size))) {
			return false;
		}
		result.assign(reinterpret_cast<const char*>(encoded.data()), encoded.size());
		return true;
	}

	bool blob(std::span<const uint8_t> &result, size_t maximum) {
		auto size = uint64_t(0);
		return number(size, 4) && size <= maximum && bytes(result, size_t(size));
	}

	[[nodiscard]] bool finished() const {
		return _available.empty();
	}

private:
	std::span<const uint8_t> _available;

};

std::vector<uint8_t> AssociatedData(
		std::span<const uint8_t> magic,
		const EmergencyRuleGeneration &generation,
		const EmergencyRuleDetails &details) {
	auto result = std::vector<uint8_t>();
	auto writer = Writer(result);
	writer.bytes(magic);
	writer.string(generation.installationId.value);
	writer.string(generation.transactionId);
	writer.string(details.actionId.value);
	writer.string(details.rule.id.value);
	writer.string(details.operationId.value);
	writer.number(details.revision, 8);
	writer.number(uint8_t(details.rule.action), 1);
	writer.number(uint8_t(details.rule.targetScope), 1);
	writer.string(details.rule.safeProfileId.value);
	writer.number(details.rule.selectedAccountIds.size(), 2);
	for (const auto &id : details.rule.selectedAccountIds) {
		writer.string(id.value);
	}
	writer.number(details.rule.remoteSessionPolicies.size(), 2);
	for (const auto &policy : details.rule.remoteSessionPolicies) {
		writer.string(policy.accountId.value);
		writer.number(uint8_t(policy.kind), 1);
		writer.number(policy.selectedSessionIds.size(), 2);
		for (const auto &session : policy.selectedSessionIds) {
			writer.string(session.value);
		}
	}
	return result;
}

bool DeriveLegacyKey(std::span<const uint8_t> input, Key &key) {
	constexpr auto context = std::string_view("SleepyGram emergency execution capsule key v1");
	auto size = 0U;
	return ValidKey(input, kKeyBytes)
		&& HMAC(
			EVP_sha256(),
			input.data(),
			int(input.size()),
			reinterpret_cast<const uint8_t*>(context.data()),
			context.size(),
			key.bytes.data(),
			&size)
		&& size == key.bytes.size();
}

bool Hash(std::span<const uint8_t> input, EmergencyExecutionCapsuleDigest &digest) {
	auto size = 0U;
	return EVP_Digest(input.data(), input.size(), digest.data(), &size,
		EVP_sha256(), nullptr) == 1 && size == digest.size();
}

bool Crypt(
		bool encrypt,
		EmergencyExecutionCapsuleKey key,
		std::span<const uint8_t> nonce,
		std::span<const uint8_t> aad,
		std::span<const uint8_t> input,
		std::span<uint8_t> output,
		std::span<uint8_t> tag) {
	auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
		EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	auto size = 0;
	if (!context || EVP_CipherInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
			key.data(), nonce.data(), encrypt ? 1 : 0) != 1
		|| EVP_CipherUpdate(context.get(), nullptr, &size, aad.data(), int(aad.size())) != 1
		|| EVP_CipherUpdate(context.get(), output.data(), &size,
			input.data(), int(input.size())) != 1
		|| size != int(input.size())
		|| (!encrypt && EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
			int(tag.size()), tag.data()) != 1)) {
		return false;
	}
	auto tail = std::array<uint8_t, EVP_MAX_BLOCK_LENGTH>{};
	const auto finalized = EVP_CipherFinal_ex(context.get(), tail.data(), &size);
	OPENSSL_cleanse(tail.data(), tail.size());
	return finalized == 1 && !size
		&& (!encrypt || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
			int(tag.size()), tag.data()) == 1);
}

} // namespace

struct OpenedEmergencyExecutionCapsule::Data final {
	SecretBytes plaintext;
	std::vector<EmergencyExecutionAccount> accounts;
	EmergencyExecutionSuccessor successor;
	std::optional<EmergencyExecutionSafeDestination> safeDestination;
};

OpenedEmergencyExecutionCapsule::OpenedEmergencyExecutionCapsule(std::unique_ptr<Data> data)
: _data(std::move(data)) {
}

OpenedEmergencyExecutionCapsule::OpenedEmergencyExecutionCapsule(
	OpenedEmergencyExecutionCapsule&&) noexcept = default;

OpenedEmergencyExecutionCapsule &OpenedEmergencyExecutionCapsule::operator=(
	OpenedEmergencyExecutionCapsule&&) noexcept = default;

OpenedEmergencyExecutionCapsule::~OpenedEmergencyExecutionCapsule() = default;

std::span<const EmergencyExecutionAccount> OpenedEmergencyExecutionCapsule::accounts() const {
	return _data->accounts;
}

const EmergencyExecutionSuccessor &OpenedEmergencyExecutionCapsule::successor() const {
	return _data->successor;
}

const std::optional<EmergencyExecutionSafeDestination>
&OpenedEmergencyExecutionCapsule::safeDestination() const {
	return _data->safeDestination;
}

size_t MaximumEmergencyExecutionCapsuleSize() {
	return kMaxPlaintextBytes + kOverhead;
}

std::optional<SealedEmergencyExecutionCapsule> SealEmergencyExecutionCapsule(
		const EmergencyRuleGeneration &generation,
		const EmergencyRuleDetails &details,
		const DryRunPlan &plan,
		std::span<const EmergencyExecutionAccount> accounts,
		const EmergencyExecutionSuccessor &successor,
		const std::optional<EmergencyExecutionSafeDestination> &safeDestination,
		std::span<const uint8_t> emergencyDerivedKey) {
	auto key = Key();
	if (!details::DeriveRebindableEmergencyCapsuleKey(emergencyDerivedKey, key.bytes)) {
		return std::nullopt;
	}
	return SealEmergencyExecutionCapsuleForRebind(
		generation, details, plan, accounts, successor, safeDestination, key.bytes);
}

std::optional<SealedEmergencyExecutionCapsule> SealEmergencyExecutionCapsuleForRebind(
		const EmergencyRuleGeneration &generation,
		const EmergencyRuleDetails &details,
		const DryRunPlan &plan,
		std::span<const EmergencyExecutionAccount> accounts,
		const EmergencyExecutionSuccessor &successor,
		const std::optional<EmergencyExecutionSafeDestination> &safeDestination,
		EmergencyExecutionCapsuleKey key) {
	if (details.capsuleVersion != EmergencyExecutionCapsuleVersion::Rebindable
		|| !ValidBinding(generation, details, plan)
		|| !ValidPayload(generation, plan, accounts, successor, safeDestination)
		|| !ValidKey(key, kKeyBytes)) {
		return std::nullopt;
	}
	auto plaintext = SecretBytes();
	plaintext.bytes.reserve(kMaxMetadataBytes + successor.sealedProfileVault.size()
		+ successor.sealedAccountKeyring.size()
		+ (safeDestination ? safeDestination->sealedSetGrant.size() : 0));
	auto writer = Writer(plaintext.bytes);
	writer.number(accounts.size(), 2);
	for (const auto &account : accounts) {
		writer.string(account.accountId.value);
		writer.string(account.locator);
		writer.bytes(account.scopedKey);
		const auto &remote = account.remoteIdentity;
		writer.number(remote ? uint8_t(remote->environment) : 0, 1);
		writer.number(remote ? remote->userId : 0, 8);
	}
	writer.string(successor.transactionId);
	writer.blob(successor.sealedProfileVault);
	writer.blob(successor.sealedAccountKeyring);
	writer.number(safeDestination.has_value(), 1);
	if (safeDestination) {
		writer.string(safeDestination->profileId.value);
		writer.blob(safeDestination->sealedSetGrant);
	}
	writer.bytes(successor.installationDigest);
	auto result = SealedEmergencyExecutionCapsule();
	result.bytes.resize(kOverhead + plaintext.bytes.size());
	auto buffer = std::span(result.bytes);
	std::ranges::copy(kRebindableMagic, buffer.begin());
	const auto nonce = buffer.subspan(kRebindableMagic.size(), kNonceBytes);
	if (RAND_bytes(nonce.data(), int(nonce.size())) != 1
		|| !Crypt(
			true,
			key,
			nonce,
			AssociatedData(kRebindableMagic, generation, details),
			plaintext.bytes,
			buffer.subspan(kHeaderBytes, plaintext.bytes.size()),
			buffer.last(kTagBytes))
		|| !Hash(buffer, result.digest)) {
		return std::nullopt;
	}
	return result;
}

std::optional<OpenedEmergencyExecutionCapsule> OpenEmergencyExecutionCapsule(
		const EmergencyRuleTicket &ticket,
		const DryRunPlan &plan,
		std::span<const uint8_t> sealed,
		std::span<const uint8_t> emergencyDerivedKey) {
	auto key = Key();
	const auto version = ticket.details().capsuleVersion;
	const auto derived = (version == EmergencyExecutionCapsuleVersion::Legacy)
		? DeriveLegacyKey(emergencyDerivedKey, key)
		: details::DeriveRebindableEmergencyCapsuleKey(emergencyDerivedKey, key.bytes);
	return derived
		? OpenedEmergencyExecutionCapsule::OpenWithKey(ticket, plan, sealed, key.bytes)
		: std::nullopt;
}

std::optional<OpenedEmergencyExecutionCapsule> OpenEmergencyExecutionCapsuleForRebind(
		const EmergencyRuleTicket &ticket,
		std::span<const uint8_t> sealed,
		EmergencyExecutionCapsuleKey key) {
	const auto &details = ticket.details();
	const auto snapshot = ticket.reviewedLive();
	if (details.capsuleVersion != EmergencyExecutionCapsuleVersion::Rebindable
		|| !snapshot) {
		return std::nullopt;
	}
	const auto plan = BuildDryRunPlan(details.operationId, details.rule, *snapshot);
	return OpenedEmergencyExecutionCapsule::OpenWithKey(ticket, plan, sealed, key);
}

std::optional<OpenedEmergencyExecutionCapsule> OpenedEmergencyExecutionCapsule::OpenWithKey(
		const EmergencyRuleTicket &ticket,
		const DryRunPlan &plan,
		std::span<const uint8_t> sealed,
		EmergencyExecutionCapsuleKey key) {
	const auto &generation = ticket.authority().generation;
	const auto &details = ticket.details();
	const auto &expectedDigest = details.executionCapsuleDigest;
	const auto snapshot = ticket.reviewedLive();
	const auto &magic = (details.capsuleVersion == EmergencyExecutionCapsuleVersion::Legacy)
		? kLegacyMagic
		: kRebindableMagic;
	auto digest = EmergencyExecutionCapsuleDigest{};
	if (!expectedDigest || !snapshot
		|| sealed.size() <= kOverhead || sealed.size() > MaximumEmergencyExecutionCapsuleSize()
		|| !std::ranges::equal(magic, sealed.first(magic.size()))
		|| !ValidBinding(generation, details, plan)
		|| BuildDryRunPlan(details.operationId, details.rule, *snapshot) != plan
		|| !Hash(sealed, digest)
		|| CRYPTO_memcmp(expectedDigest->data(), digest.data(), digest.size()) != 0
		|| !ValidKey(key, kKeyBytes)) {
		return std::nullopt;
	}
	auto data = std::make_unique<OpenedEmergencyExecutionCapsule::Data>();
	data->plaintext.bytes.resize(sealed.size() - kOverhead);
	auto tag = std::array<uint8_t, kTagBytes>{};
	std::ranges::copy(sealed.last(kTagBytes), tag.begin());
	if (!Crypt(
			false,
			key,
			sealed.subspan(magic.size(), kNonceBytes),
			AssociatedData(magic, generation, details),
			sealed.subspan(kHeaderBytes, data->plaintext.bytes.size()),
			data->plaintext.bytes,
			tag)) {
		return std::nullopt;
	}
	auto reader = Reader(data->plaintext.bytes);
	auto count = uint64_t(0);
	if (!reader.number(count, 2) || count != plan.accounts.size()) {
		return std::nullopt;
	}
	data->accounts.resize(size_t(count));
	for (auto &account : data->accounts) {
		auto lane = uint64_t(0);
		auto userId = uint64_t(0);
		if (!reader.string(account.accountId.value)
			|| !reader.string(account.locator)
			|| !reader.bytes(account.scopedKey, kEmergencyExecutionScopedKeyBytes)
			|| !reader.number(lane, 1)
			|| !reader.number(userId, 8) || ((lane == 0) != (userId == 0))) {
			return std::nullopt;
		}
		if (lane) {
			account.remoteIdentity = {
				.userId = userId,
				.environment = EmergencyScopedEnvironment(lane),
			};
		}
	}
	auto hasSafe = uint64_t(0);
	auto &successor = data->successor;
	if (!reader.string(successor.transactionId)
		|| !reader.blob(successor.sealedProfileVault, kMaxEmergencyExecutionSuccessorVaultBytes)
		|| !reader.blob(successor.sealedAccountKeyring, kMaxEmergencyExecutionSuccessorKeyringBytes)
		|| !reader.number(hasSafe, 1) || hasSafe > 1) {
		return std::nullopt;
	}
	if (hasSafe) {
		auto &safe = data->safeDestination.emplace();
		if (!reader.string(safe.profileId.value)
			|| !reader.blob(safe.sealedSetGrant, kMaxEmergencyExecutionSafeGrantBytes)) {
			return std::nullopt;
		}
	}
	if (plan.action == EmergencyAction::RemoveInstallation
		&& !reader.bytes(successor.installationDigest, kEmergencyInstallationDigestBytes)) {
		return std::nullopt;
	}
	if (!reader.finished()
		|| !ValidPayload(generation, plan, data->accounts, successor, data->safeDestination)) {
		return std::nullopt;
	}
	return OpenedEmergencyExecutionCapsule(std::move(data));
}

} // namespace Ayu::EmergencyActions
