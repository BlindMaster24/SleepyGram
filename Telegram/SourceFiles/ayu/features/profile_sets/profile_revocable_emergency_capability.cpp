// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_emergency_capability.h"

#include "ayu/features/emergency_actions/emergency_action_journal.h"
#include "storage/details/storage_hkdf.h"

#include <QtCore/QtEndian>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <set>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;

constexpr auto &kMagic = kRevocableEmergencyCapabilityMagic;
constexpr auto kKeyDomain = std::string_view("SleepyGram revocable emergency capability v3");
constexpr auto kNonceSize = size_t(12);
constexpr auto kTagSize = size_t(16);
constexpr auto kHeaderSize = kMagic.size() + kNonceSize;
constexpr auto kOverhead = kHeaderSize + kTagSize;
constexpr auto kIdSize = qsizetype(16);
constexpr auto kKeySize = qsizetype(32);
constexpr auto kAccountSize = AccountGateHandle::kSerializedSize
	+ AccountGateRevocationPermit::kSerializedSize + 1 + qsizetype(sizeof(quint64));
constexpr auto kSafeSize = kIdSize + 2 * kKeySize;
constexpr auto kMinimumPayloadSize = sizeof(quint16) + 1 + kKeySize;
constexpr auto kMaximumPayloadSize = kMinimumPayloadSize + kSafeSize
	+ EA::kMaxEmergencyExecutionAccounts * kAccountSize;
constexpr auto kMaxSafeAccounts = size_t(256);

struct SecretBytes final {
	SecretBytes() = default;
	explicit SecretBytes(QByteArray bytes) : value(std::move(bytes)) {
	}
	SecretBytes(const SecretBytes&) = delete;
	SecretBytes &operator=(const SecretBytes&) = delete;
	~SecretBytes() {
		if (!value.isEmpty()) {
			OPENSSL_cleanse(value.data(), size_t(value.size()));
		}
	}
	QByteArray value;
};

struct SecretKey final {
	~SecretKey() {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}
	std::array<uint8_t, kKeySize> bytes{};
};

struct Context final {
	EA::DryRunPlan plan;
	QByteArray associatedData;
	std::vector<AccountId> targets;
};

template <typename Int>
void AppendInt(QByteArray &out, Int value) {
	const auto encoded = qToBigEndian(value);
	out.append(reinterpret_cast<const char*>(&encoded), sizeof(encoded));
}

template <typename Id>
void AppendId(QByteArray &out, Id id) {
	AppendInt(out, id.high);
	AppendInt(out, id.low);
}

QByteArrayView AsView(std::span<const uint8_t> bytes) {
	return { reinterpret_cast<const char*>(bytes.data()), qsizetype(bytes.size()) };
}

bool Nonzero(QByteArrayView value, qsizetype size) {
	return value.size() == size && std::ranges::any_of(value, [](char ch) {
		return ch != 0;
	});
}

QByteArray ParseOpaqueId(std::string_view input) {
	if (input.size() != 2 * kIdSize) {
		return {};
	}
	const auto bytes = QByteArray::fromHex(QByteArray(input.data(), input.size()));
	return Nonzero(bytes, kIdSize) && bytes.toHex().toStdString() == input
		? bytes : QByteArray();
}

template <typename Id>
Id ReadId(QByteArrayView raw) {
	return (raw.size() == kIdSize)
		? Id{ qFromBigEndian<quint64>(raw.data()), qFromBigEndian<quint64>(raw.data() + 8) }
		: Id();
}

bool ValidActionId(std::string_view id) {
	return !id.empty() && id.size() <= 128 && std::ranges::all_of(id, [](char ch) {
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
			|| (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == ':';
	});
}

std::optional<Context> BuildContext(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::EmergencyRuleDetails &details,
		const EA::LiveInstallation &live,
		const AccountGateTable &gates) {
	const auto installation = ParseOpaqueId(epoch.installationId.value);
	const auto epochBytes = ParseOpaqueId(epoch.transactionId);
	if (installation.isEmpty() || epochBytes.isEmpty()
		|| gates.installationId() != installation || details.rule.installationId != epoch.installationId
		|| details.capsuleVersion != EA::EmergencyExecutionCapsuleVersion::Rebindable
		|| live.id != epoch.installationId || !ValidActionId(details.actionId.value) || !details.revision) {
		return std::nullopt;
	}
	auto plan = EA::BuildDryRunPlan(details.operationId, details.rule, live);
	if (plan.accounts.size() > EA::kMaxEmergencyExecutionAccounts
		|| plan.safeProfileAccountIds.size() > kMaxSafeAccounts
		|| !plan.issues.empty() || !plan.selectedAccountIdsNotLive.empty()
		|| (plan.action == EA::EmergencyAction::ResetAccountData && plan.accounts.empty())
		|| (details.rule.safeProfileId.valid() && plan.safeDestination != EA::SafeDestinationKind::Profile)) {
		return std::nullopt;
	}
	const auto journal = EA::MakeJournal(plan);
	const auto encoded = journal ? EA::EncodeJournal(*journal) : std::vector<std::byte>();
	if (encoded.empty()) {
		return std::nullopt;
	}
	auto result = Context{ .plan = std::move(plan) };
	result.targets.reserve(result.plan.accounts.size());
	for (const auto &target : result.plan.accounts) {
		const auto id = ReadId<AccountId>(ParseOpaqueId(target.accountId.value));
		if (!id || !target.wouldClearLocalData || !target.selectedSessionIdsNotLive.empty()
			|| (target.remoteTarget == EA::RemoteSessionTargetKind::SelectedSessions
				&& target.sessionIdsForRevokeRequest.empty())) {
			return std::nullopt;
		}
		result.targets.push_back(id);
	}
	auto &aad = result.associatedData;
	aad.append(AsView(kMagic)).append(installation).append(epochBytes);
	AppendInt(aad, quint64(details.revision));
	AppendInt(aad, quint16(details.actionId.value.size()));
	aad.append(details.actionId.value.data(), details.actionId.value.size());
	AppendInt(aad, quint32(encoded.size()));
	aad.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
	AppendInt(aad, quint16(result.plan.safeProfileAccountIds.size()));
	for (const auto &member : result.plan.safeProfileAccountIds) {
		const auto id = ParseOpaqueId(member.value);
		if (id.isEmpty()) {
			return std::nullopt;
		}
		aad.append(id);
	}
	if (result.plan.safeDestination == EA::SafeDestinationKind::Profile
		&& ParseOpaqueId(result.plan.safeProfileId.value).isEmpty()) {
		return std::nullopt;
	}
	return result;
}

bool ValidSafeSet(
		const EA::DryRunPlan &plan,
		const RevocableEmergencySafeSetView &safeSet,
		EA::EmergencyExecutionCapsuleKey capsuleKey) {
	auto safeCapsuleKey = SecretKey();
	return plan.safeDestination == EA::SafeDestinationKind::Profile
		&& safeSet.id == ReadId<SetId>(ParseOpaqueId(plan.safeProfileId.value))
		&& Nonzero(safeSet.verifier, kKeySize) && Nonzero(safeSet.key, kKeySize)
		&& CRYPTO_memcmp(safeSet.key.data(), safeSet.verifier.data(), kKeySize) != 0
		&& EA::details::DeriveRebindableEmergencyCapsuleKey({
			reinterpret_cast<const uint8_t*>(safeSet.key.data()), size_t(safeSet.key.size()),
		}, safeCapsuleKey.bytes)
		&& CRYPTO_memcmp(safeCapsuleKey.bytes.data(), capsuleKey.data(), kKeySize) != 0;
}

bool ValidPackageDigest(
		const EA::DryRunPlan &plan,
		const std::optional<EA::EmergencyExecutionCapsuleDigest> &digest) {
	return (plan.action == EA::EmergencyAction::RemoveInstallation)
		? (digest && Nonzero(AsView(*digest), kKeySize))
		: !digest;
}

std::optional<std::vector<AccountId>> VerifyAccounts(
		const Context &context,
		const AccountGateTable &gates,
		std::span<const RevocableEmergencyAccount *const> accounts) {
	if (accounts.size() != context.targets.size()) {
		return std::nullopt;
	}
	auto locators = std::set<QByteArray>();
	auto identities = std::set<std::pair<EA::EmergencyScopedEnvironment, uint64_t>>();
	auto revoked = std::vector<AccountId>();
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto account = accounts[i];
		const auto &identity = account->remoteIdentity;
		const auto &binding = account->handle.binding();
		if (binding.id != context.targets[i] || !account->handle.matches(account->permit)
			|| !locators.insert(binding.locator).second
			|| (!identity && context.plan.accounts[i].remoteTarget != EA::RemoteSessionTargetKind::None)) {
			return std::nullopt;
		}
		if (identity && (!identity->userId || identity->userId > 0xFFFFFFFFFFFFULL
			|| (identity->environment != EA::EmergencyScopedEnvironment::Production
				&& identity->environment != EA::EmergencyScopedEnvironment::Test))) {
			return std::nullopt;
		}
		const auto status = InspectAccountGate(gates, account->handle);
		if (status == AccountGateStatus::Unavailable) {
			return std::nullopt;
		} else if (status == AccountGateStatus::Revoked) {
			revoked.push_back(binding.id);
		} else if (identity && !identities.emplace(identity->environment, identity->userId).second) {
			return std::nullopt;
		}
	}
	return revoked;
}

std::optional<EA::DryRunPlan> BuildActivePlan(
		const EA::EmergencyRuleDetails &details,
		const EA::LiveInstallation &reviewed,
		const EA::DryRunPlan &reviewedPlan,
		std::span<const AccountId> revoked) {
	const auto isRevoked = [&](const EA::AccountId &id) {
		return std::ranges::find(revoked, ReadId<AccountId>(ParseOpaqueId(id.value)))
			!= revoked.end();
	};
	auto live = reviewed;
	std::erase_if(live.accounts, [&](const auto &account) { return isRevoked(account.id); });
	auto rule = details.rule;
	std::erase_if(rule.selectedAccountIds, isRevoked);
	std::erase_if(rule.remoteSessionPolicies, [&](const auto &policy) {
		return isRevoked(policy.accountId);
	});
	auto allowed = reviewedPlan.accounts;
	std::erase_if(allowed, [&](const auto &account) { return isRevoked(account.accountId); });
	auto plan = EA::BuildDryRunPlan(details.operationId, rule, live);
	if (plan.status != EA::DryRunStatus::Ready || plan.accounts != allowed
		|| plan.safeDestination != reviewedPlan.safeDestination
		|| plan.safeProfileId != reviewedPlan.safeProfileId
		|| plan.safeProfileAccountIds != reviewedPlan.safeProfileAccountIds) {
		return std::nullopt;
	}
	return plan;
}

bool DeriveCipherKey(EA::EmergencyExecutionCapsuleKey input, SecretBytes &output) {
	output.value.resize(kKeySize);
	return Nonzero(AsView(input), kKeySize) && Storage::HkdfSha256(
		bytes::make_span(input.data(), input.size()),
		{},
		bytes::make_span(kKeyDomain),
		bytes::make_span(output.value.data(), output.value.size()));
}

bool Hash(std::span<const uint8_t> bytes, EA::EmergencyExecutionCapsuleDigest &result) {
	auto size = 0U;
	return EVP_Digest(bytes.data(), bytes.size(), result.data(), &size,
		EVP_sha256(), nullptr) == 1 && size == result.size();
}

bool Cipher(
		bool encrypt,
		QByteArrayView key,
		std::span<const uint8_t> nonce,
		QByteArrayView aad,
		std::span<const uint8_t> input,
		std::span<uint8_t> output,
		std::span<uint8_t, kTagSize> tag) {
	auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
		EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	auto size = 0;
	if (!context || EVP_CipherInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
			reinterpret_cast<const uint8_t*>(key.data()), nonce.data(), encrypt ? 1 : 0) != 1
		|| EVP_CipherUpdate(context.get(), nullptr, &size,
			reinterpret_cast<const uint8_t*>(aad.data()), int(aad.size())) != 1
		|| EVP_CipherUpdate(context.get(), output.data(), &size, input.data(), int(input.size())) != 1
		|| size != int(input.size()) || (!encrypt && EVP_CIPHER_CTX_ctrl(context.get(),
			EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data()) != 1)) {
		return false;
	}
	auto tail = std::array<uint8_t, EVP_MAX_BLOCK_LENGTH>();
	const auto final = EVP_CipherFinal_ex(context.get(), tail.data(), &size);
	OPENSSL_cleanse(tail.data(), tail.size());
	return final == 1 && !size && (!encrypt || EVP_CIPHER_CTX_ctrl(context.get(),
		EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data()) == 1);
}

QByteArrayView Take(QByteArrayView &remaining, qsizetype count) {
	if (remaining.size() < count) {
		return {};
	}
	const auto result = remaining.first(count);
	remaining = remaining.sliced(count);
	return result;
}

} // namespace

struct OpenedRevocableEmergencyCapability::Data final {
	SecretBytes plaintext;
	EA::DryRunPlan plan;
	std::vector<RevocableEmergencyAccount> accounts;
	std::optional<RevocableEmergencySafeSetView> safeSet;
	std::optional<EA::EmergencyExecutionCapsuleDigest> packageDigest;
};

OpenedRevocableEmergencyCapability::OpenedRevocableEmergencyCapability(std::unique_ptr<Data> data)
: _data(std::move(data)) {
}

OpenedRevocableEmergencyCapability::OpenedRevocableEmergencyCapability(
	OpenedRevocableEmergencyCapability&&) noexcept = default;

OpenedRevocableEmergencyCapability::~OpenedRevocableEmergencyCapability() = default;

const EA::DryRunPlan &OpenedRevocableEmergencyCapability::plan() const {
	return _data->plan;
}

const std::vector<RevocableEmergencyAccount> &OpenedRevocableEmergencyCapability::accounts() const {
	return _data->accounts;
}

std::vector<RevocableEmergencyAccount> OpenedRevocableEmergencyCapability::takeAccounts() && {
	return std::move(_data->accounts);
}

auto OpenedRevocableEmergencyCapability::safeSet() const
-> const std::optional<RevocableEmergencySafeSetView>& {
	return _data->safeSet;
}

auto OpenedRevocableEmergencyCapability::packageDigest() const
-> const std::optional<EA::EmergencyExecutionCapsuleDigest>& {
	return _data->packageDigest;
}

std::optional<EA::SealedEmergencyExecutionCapsule> SealRevocableEmergencyCapability(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::EmergencyRuleDetails &details,
		const EA::LiveInstallation &reviewedLive,
		const AccountGateTable &gates,
		std::span<const RevocableEmergencyAccount> accounts,
		const std::optional<RevocableEmergencySafeSetView> &safeSet,
		const std::optional<EA::EmergencyExecutionCapsuleDigest> &packageDigest,
		std::span<const uint8_t> emergencyDerivedKey) {
	auto key = SecretKey();
	if (!EA::details::DeriveRebindableEmergencyCapsuleKey(emergencyDerivedKey, key.bytes)) {
		return std::nullopt;
	}
	return SealRevocableEmergencyCapabilityForRebind(epoch, details, reviewedLive,
		gates, accounts, safeSet, packageDigest, key.bytes);
}

std::optional<EA::SealedEmergencyExecutionCapsule> SealRevocableEmergencyCapabilityForRebind(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::EmergencyRuleDetails &details,
		const EA::LiveInstallation &reviewedLive,
		const AccountGateTable &gates,
		std::span<const RevocableEmergencyAccount> accounts,
		const std::optional<RevocableEmergencySafeSetView> &safeSet,
		const std::optional<EA::EmergencyExecutionCapsuleDigest> &packageDigest,
		EA::EmergencyExecutionCapsuleKey capsuleKey,
		RevocableEmergencyTargets targets) {
	const auto context = BuildContext(epoch, details, reviewedLive, gates);
	if (!context || accounts.size() != context->targets.size()
		|| !ValidPackageDigest(context->plan, packageDigest)
		|| (safeSet && !ValidSafeSet(context->plan, *safeSet, capsuleKey))) {
		return std::nullopt;
	}
	auto ordered = std::vector<const RevocableEmergencyAccount*>();
	ordered.reserve(accounts.size());
	for (const auto id : context->targets) {
		const auto account = std::ranges::find_if(accounts, [&](const auto &value) {
			return value.handle.binding().id == id;
		});
		if (account == accounts.end()) {
			return std::nullopt;
		}
		ordered.push_back(&*account);
	}
	const auto revoked = VerifyAccounts(*context, gates, ordered);
	auto key = SecretBytes();
	if (!revoked || (!revoked->empty() && targets != RevocableEmergencyTargets::Reviewed)
		|| !DeriveCipherKey(capsuleKey, key)) {
		return std::nullopt;
	}
	auto plaintext = SecretBytes();
	auto &payload = plaintext.value;
	payload.reserve(kMinimumPayloadSize + kAccountSize * accounts.size() + (safeSet ? kSafeSize : 0));
	AppendInt(payload, quint16(accounts.size()));
	for (const auto account : ordered) {
		const auto handle = SecretBytes{ account->handle.serialize() };
		const auto permit = SecretBytes{ account->permit.serialize() };
		payload.append(handle.value).append(permit.value);
		const auto &identity = account->remoteIdentity;
		payload.append(identity ? char(identity->environment) : char(0));
		AppendInt(payload, quint64(identity ? identity->userId : 0));
	}
	payload.append(char(safeSet.has_value()));
	if (safeSet) {
		AppendId(payload, safeSet->id);
		payload.append(safeSet->verifier).append(safeSet->key);
	}
	const auto encodedDigest = packageDigest.value_or(EA::EmergencyExecutionCapsuleDigest());
	payload.append(AsView(encodedDigest));
	auto result = EA::SealedEmergencyExecutionCapsule();
	result.bytes.resize(kOverhead + payload.size());
	const auto buffer = std::span(result.bytes);
	std::ranges::copy(kMagic, buffer.begin());
	const auto nonce = buffer.subspan(kMagic.size(), kNonceSize);
	return (RAND_bytes(nonce.data(), int(nonce.size())) == 1
		&& Cipher(true, key.value, nonce, context->associatedData,
			{ reinterpret_cast<const uint8_t*>(payload.constData()), size_t(payload.size()) },
			buffer.subspan(kHeaderSize, payload.size()), buffer.last<kTagSize>())
		&& Hash(buffer, result.digest)) ? std::optional(std::move(result)) : std::nullopt;
}

RevocableEmergencyCapabilityOpenResult OpenRevocableEmergencyCapability(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::EmergencyRuleTicket &ticket,
		const AccountGateTable &gates,
		std::span<const uint8_t> sealed,
		const std::optional<EA::EmergencyExecutionCapsuleDigest> &expectedPackageDigest,
		std::span<const uint8_t> emergencyDerivedKey) {
	auto key = SecretKey();
	if (!EA::details::DeriveRebindableEmergencyCapsuleKey(emergencyDerivedKey, key.bytes)) {
		return InvalidRevocableEmergencyCapability();
	}
	return OpenRevocableEmergencyCapabilityForRebind(epoch, ticket, gates,
		sealed, expectedPackageDigest, key.bytes);
}

RevocableEmergencyCapabilityOpenResult OpenRevocableEmergencyCapabilityForRebind(
		const EA::EmergencyRuleGeneration &epoch,
		const EA::EmergencyRuleTicket &ticket,
		const AccountGateTable &gates,
		std::span<const uint8_t> sealed,
		const std::optional<EA::EmergencyExecutionCapsuleDigest> &expectedPackageDigest,
		EA::EmergencyExecutionCapsuleKey capsuleKey,
		RevocableEmergencyTargets targets) {
	constexpr auto invalid = InvalidRevocableEmergencyCapability();
	const auto &details = ticket.details();
	const auto live = ticket.reviewedLive();
	auto digest = EA::EmergencyExecutionCapsuleDigest();
	if (ticket.authority().generation != epoch || !live || !details.executionCapsuleDigest
		|| sealed.size() < kOverhead + kMinimumPayloadSize
		|| sealed.size() > kOverhead + kMaximumPayloadSize
		|| !std::ranges::equal(kMagic, sealed.first(kMagic.size()))
		|| !Hash(sealed, digest) || digest != *details.executionCapsuleDigest) {
		return invalid;
	}
	auto context = BuildContext(epoch, details, *live, gates);
	auto key = SecretBytes();
	if (!context || !ValidPackageDigest(context->plan, expectedPackageDigest)
		|| !DeriveCipherKey(capsuleKey, key)) {
		return invalid;
	}
	auto data = std::make_unique<OpenedRevocableEmergencyCapability::Data>();
	const auto size = sealed.size() - kOverhead;
	data->plaintext.value.resize(size);
	const auto plaintext = data->plaintext.value.data();
	auto tag = std::array<uint8_t, kTagSize>();
	std::ranges::copy(sealed.last(kTagSize), tag.begin());
	if (!Cipher(false, key.value, sealed.subspan(kMagic.size(), kNonceSize), context->associatedData,
			sealed.subspan(kHeaderSize, size),
			{ reinterpret_cast<uint8_t*>(plaintext), size }, tag)) {
		return invalid;
	}
	auto reader = QByteArrayView(data->plaintext.value);
	const auto count = qFromBigEndian<quint16>(Take(reader, sizeof(quint16)).data());
	if (count != context->targets.size()) {
		return invalid;
	}
	data->accounts.reserve(count);
	for (auto i = 0; i != count; ++i) {
		if (reader.size() < kAccountSize) {
			return invalid;
		}
		auto handle = AccountGateHandle::Parse(Take(reader, AccountGateHandle::kSerializedSize));
		auto permit = AccountGateRevocationPermit::Parse(Take(reader, AccountGateRevocationPermit::kSerializedSize));
		const auto environment = uchar(Take(reader, 1).front());
		const auto user = qFromBigEndian<quint64>(Take(reader, sizeof(quint64)).data());
		if (!handle || !permit || ((environment == 0) != (user == 0))) {
			return invalid;
		}
		data->accounts.push_back({ std::move(*handle), std::move(*permit), environment
			? std::optional(EA::EmergencyScopedRemoteIdentity{ user, EA::EmergencyScopedEnvironment(environment) })
			: std::nullopt });
	}
	const auto flag = Take(reader, 1);
	if (flag.empty() || uchar(flag.front()) > 1) {
		return invalid;
	}
	if (flag.front()) {
		const auto id = ReadId<SetId>(Take(reader, kIdSize));
		const auto verifier = Take(reader, kKeySize);
		const auto credential = Take(reader, kKeySize);
		data->safeSet = RevocableEmergencySafeSetView{ id, verifier, credential };
		if (!ValidSafeSet(context->plan, *data->safeSet, capsuleKey)) {
			return invalid;
		}
	}
	const auto storedDigest = Take(reader, kKeySize);
	const auto expectedDigest = expectedPackageDigest.value_or(EA::EmergencyExecutionCapsuleDigest());
	if (!reader.empty() || storedDigest != AsView(expectedDigest)) {
		return invalid;
	}
	OPENSSL_cleanse(plaintext + sizeof(quint16), count * kAccountSize);
	auto accounts = std::vector<const RevocableEmergencyAccount*>();
	accounts.reserve(count);
	for (const auto &account : data->accounts) {
		accounts.push_back(&account);
	}
	auto revoked = VerifyAccounts(*context, gates, accounts);
	if (!revoked) {
		return invalid;
	}
	const auto restrictToActive = (targets != RevocableEmergencyTargets::Reviewed) && !revoked->empty();
	if (restrictToActive && revoked->size() == accounts.size()
		&& context->plan.action == EA::EmergencyAction::ResetAccountData) {
		return RevokedRevocableEmergencyTargets{ std::move(*revoked) };
	}
	if (restrictToActive) {
		auto effective = BuildActivePlan(details, *live, context->plan, *revoked);
		if (!effective) {
			return invalid;
		}
		auto retained = std::vector<RevocableEmergencyAccount>();
		retained.reserve(effective->accounts.size());
		for (auto &account : data->accounts) {
			if (std::ranges::find(*revoked, account.handle.binding().id) == revoked->end()) {
				retained.push_back(std::move(account));
			}
		}
		data->accounts = std::move(retained);
		context->plan = std::move(*effective);
	}
	data->plan = std::move(context->plan);
	data->packageDigest = expectedPackageDigest;
	return OpenedRevocableEmergencyCapability(std::move(data));
}

} // namespace Ayu::ProfileSets
