// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_vault.h"

#include <QtCore/QtEndian>

#include <openssl/crypto.h>

#include <algorithm>
#include <set>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kMasterPayload = QByteArrayView("SGA3");
constexpr auto kSetPayload = QByteArrayView("SGS3");
constexpr auto kMasterHeaderSize = qsizetype(4 + kVerifierSize + 4);
constexpr auto kSetHeaderSize = qsizetype(4 + 16 + kProfileVaultKeySize + 2);
constexpr auto kMasterAccountSize = AccountGateHandle::kSerializedSize
	+ AccountGateRevocationPermit::kSerializedSize;
constexpr auto kMaximumCiphertextBytes = qsizetype(80 * 1024 * 1024);

using AccountCatalog = std::map<AccountId, const RevocableAccountGrant*>;

struct MasterPayload final {
	MasterPayload() = default;
	MasterPayload(MasterPayload&&) noexcept = default;
	~MasterPayload();

	RevocableAdminVaultAccess access;
	std::map<SetId, QByteArray> grantKeys;
};

void SetError(ProfileVaultError *error, ProfileVaultError value) {
	if (error) {
		*error = value;
	}
}

void Wipe(QByteArray &bytes) {
	if (!bytes.isEmpty()) {
		OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
	}
}

MasterPayload::~MasterPayload() {
	for (auto &[id, key] : grantKeys) {
		Wipe(key);
	}
}

bool ValidBytes(QByteArrayView bytes, qsizetype size) {
	return bytes.size() == size && std::ranges::any_of(bytes, [](char ch) {
		return ch != 0;
	});
}

bool Equal(QByteArrayView a, QByteArrayView b) {
	return a.size() == b.size()
		&& CRYPTO_memcmp(a.data(), b.data(), size_t(a.size())) == 0;
}

template <typename Int>
void AppendInt(QByteArray &bytes, Int value) {
	const auto encoded = qToBigEndian(value);
	bytes.append(reinterpret_cast<const char*>(&encoded), sizeof(encoded));
}

void AppendSecret(QByteArray &bytes, QByteArray secret) {
	const auto wipe = gsl::finally([&] { Wipe(secret); });
	bytes.append(secret);
}

bool MatchMetadata(const ProfileVault &envelope, const Metadata &metadata) {
	if (metadata.verifierSalt != envelope.salt
		|| metadata.verifierKdf != envelope.kdf
		|| !Equal(metadata.masterVerifier, envelope.adminVerifier)
		|| metadata.sets.size() != envelope.grants.size()) {
		return false;
	}
	auto sets = std::map<SetId, QByteArrayView>();
	for (const auto &set : metadata.sets) {
		sets.emplace(set.id, set.verifier);
	}
	return std::ranges::all_of(envelope.grants, [&](const SealedSetGrant &grant) {
		const auto set = sets.find(grant.id);
		return set != end(sets) && Equal(set->second, grant.verifier);
	});
}

std::optional<AccountCatalog> IndexAccounts(
		QByteArrayView installation,
		std::span<const RevocableAccountGrant> accounts,
		const Metadata &metadata) {
	if (accounts.size() > kMaximumAccountGateRows) {
		return std::nullopt;
	}
	auto result = AccountCatalog();
	auto locators = std::set<QByteArray>();
	for (const auto &account : accounts) {
		const auto &binding = account.handle.binding();
		if (binding.installationId != installation
			|| !account.handle.matches(account.permit)
			|| !locators.insert(binding.locator).second
			|| !result.emplace(binding.id, &account).second) {
			return std::nullopt;
		}
	}
	for (const auto &set : metadata.sets) {
		if (!std::ranges::all_of(set.accounts, [&](AccountId id) {
			return result.contains(id);
		})) {
			return std::nullopt;
		}
	}
	return result;
}

QByteArray ReadGrant(
		const ProfileVault &envelope,
		const SealedSetGrant &grant,
		const DerivedCredential &credential) {
	auto wrap = details::RevocableProfileEnvelopeKey(envelope, grant.id, credential);
	const auto wipe = gsl::finally([&] { Wipe(wrap); });
	return ValidBytes(wrap, kProfileVaultKeySize)
		? details::OpenRevocableProfileGrant(envelope, grant, wrap)
		: QByteArray();
}

std::optional<MasterPayload> ReadMaster(
		const ProfileVault &envelope,
		const DerivedCredential &admin,
		ProfileVaultError *error) {
	SetError(error, ProfileVaultError::WrongPassword);
	if (!Equal(admin.verifier, envelope.adminVerifier)) {
		return std::nullopt;
	}
	auto plaintext = ReadGrant(envelope, SealedSetGrant{
		.verifier = envelope.adminVerifier,
		.nonce = envelope.adminNonce,
		.ciphertext = envelope.adminCiphertext,
	}, admin);
	const auto wipe = gsl::finally([&] { Wipe(plaintext); });
	auto bytes = QByteArrayView(plaintext);
	SetError(error, ProfileVaultError::AuthenticationFailed);
	if (bytes.size() < kMasterHeaderSize + 2
		|| !bytes.startsWith(kMasterPayload)
		|| !Equal(bytes.sliced(4, kVerifierSize), details::RevocableProfileGrantManifest(envelope))) {
		return std::nullopt;
	}
	const auto metadataSize = qFromBigEndian<quint32>(bytes.data() + 4 + kVerifierSize);
	bytes = bytes.sliced(kMasterHeaderSize);
	if (!metadataSize || metadataSize > bytes.size() - 2) {
		return std::nullopt;
	}
	auto metadata = ParseMetadataPayload(bytes.first(metadataSize).toByteArray());
	if (!metadata || !MatchMetadata(envelope, *metadata)) {
		return std::nullopt;
	}
	bytes = bytes.sliced(metadataSize);
	const auto count = qFromBigEndian<quint16>(bytes.data());
	bytes = bytes.sliced(2);
	if (count > kMaximumAccountGateRows
		|| bytes.size() != count * kMasterAccountSize
			+ qsizetype(envelope.grants.size()) * kProfileVaultKeySize) {
		return std::nullopt;
	}
	auto result = MasterPayload();
	result.access.metadata = std::move(*metadata);
	result.access.accounts.reserve(count);
	auto previous = AccountId();
	for (auto i = 0; i != count; ++i) {
		auto handle = AccountGateHandle::Parse(bytes.first(AccountGateHandle::kSerializedSize));
		auto permit = AccountGateRevocationPermit::Parse(bytes.sliced(
			AccountGateHandle::kSerializedSize,
			AccountGateRevocationPermit::kSerializedSize));
		if (!handle || !permit || handle->binding().id <= previous) {
			return std::nullopt;
		}
		previous = handle->binding().id;
		result.access.accounts.push_back({ std::move(*handle), std::move(*permit) });
		bytes = bytes.sliced(kMasterAccountSize);
	}
	if (!IndexAccounts(envelope.id, result.access.accounts, result.access.metadata)) {
		return std::nullopt;
	}
	for (const auto &grant : envelope.grants) {
		const auto key = bytes.first(kProfileVaultKeySize);
		if (!ValidBytes(key, kProfileVaultKeySize)) {
			return std::nullopt;
		}
		result.grantKeys.emplace(grant.id, key.toByteArray());
		bytes = bytes.sliced(kProfileVaultKeySize);
	}
	SetError(error, ProfileVaultError::None);
	return result;
}

std::optional<std::vector<AccountGateHandle>> ReadSetHandles(
		const ProfileVault &envelope,
		SetId id,
		QByteArrayView bytes) {
	if (bytes.size() < kSetHeaderSize
		|| !bytes.startsWith(kSetPayload)
		|| qFromBigEndian<quint64>(bytes.data() + 4) != id.high
		|| qFromBigEndian<quint64>(bytes.data() + 12) != id.low
		|| !ValidBytes(bytes.sliced(20, kProfileVaultKeySize), kProfileVaultKeySize)) {
		return std::nullopt;
	}
	const auto count = qFromBigEndian<quint16>(bytes.data() + kSetHeaderSize - 2);
	bytes = bytes.sliced(kSetHeaderSize);
	if (count > kMaximumAccountGateRows
		|| bytes.size() != count * AccountGateHandle::kSerializedSize) {
		return std::nullopt;
	}
	auto handles = std::vector<AccountGateHandle>();
	handles.reserve(count);
	auto previous = AccountId();
	auto locators = std::set<QByteArray>();
	for (auto i = 0; i != count; ++i) {
		auto handle = AccountGateHandle::Parse(bytes.first(AccountGateHandle::kSerializedSize));
		if (!handle || handle->binding().id <= previous
			|| handle->binding().installationId != envelope.id
			|| !locators.insert(handle->binding().locator).second) {
			return std::nullopt;
		}
		previous = handle->binding().id;
		handles.push_back(std::move(*handle));
		bytes = bytes.sliced(AccountGateHandle::kSerializedSize);
	}
	return handles;
}

std::optional<SealedSetGrant> WriteSet(
		const ProfileVault &envelope,
		const AccountSet &set,
		const AccountCatalog &accounts,
		const DerivedCredential &admin,
		const QByteArray &key) {
	auto settings = details::RevocableProfileSettingsKey(envelope, set.id, admin);
	const auto wipeSettings = gsl::finally([&] { Wipe(settings); });
	if (!ValidBytes(settings, kProfileVaultKeySize)) {
		return std::nullopt;
	}
	auto plaintext = QByteArray();
	const auto wipe = gsl::finally([&] { Wipe(plaintext); });
	plaintext.reserve(kSetHeaderSize
		+ qsizetype(set.accounts.size()) * AccountGateHandle::kSerializedSize);
	plaintext.append(kSetPayload);
	AppendInt(plaintext, set.id.high);
	AppendInt(plaintext, set.id.low);
	plaintext.append(settings);
	AppendInt(plaintext, quint16(set.accounts.size()));
	auto ordered = set.accounts;
	std::ranges::sort(ordered);
	for (const auto id : ordered) {
		AppendSecret(plaintext, accounts.at(id)->handle.serialize());
	}
	return details::SealRevocableProfileGrant(envelope, set.id, set.verifier, key, plaintext);
}

bool WriteMaster(
		ProfileVault &envelope,
		const Metadata &metadata,
		const AccountCatalog &accounts,
		const DerivedCredential &admin,
		const MasterPayload &secrets) {
	const auto metadataBytes = SerializeMetadataPayload(metadata);
	if (metadataBytes.isEmpty()) {
		return false;
	}
	const auto manifest = details::RevocableProfileGrantManifest(envelope);
	auto plaintext = QByteArray();
	const auto wipe = gsl::finally([&] { Wipe(plaintext); });
	plaintext.reserve(kMasterHeaderSize + metadataBytes.size() + 2
		+ qsizetype(accounts.size()) * kMasterAccountSize
		+ qsizetype(envelope.grants.size()) * kProfileVaultKeySize);
	plaintext.append(kMasterPayload);
	plaintext.append(manifest);
	AppendInt(plaintext, quint32(metadataBytes.size()));
	plaintext.append(metadataBytes);
	AppendInt(plaintext, quint16(accounts.size()));
	for (const auto &[id, account] : accounts) {
		AppendSecret(plaintext, account->handle.serialize());
		AppendSecret(plaintext, account->permit.serialize());
	}
	for (const auto &grant : envelope.grants) {
		plaintext.append(secrets.grantKeys.at(grant.id));
	}
	auto wrap = details::RevocableProfileEnvelopeKey(envelope, {}, admin);
	const auto wipeWrap = gsl::finally([&] { Wipe(wrap); });
	if (!ValidBytes(wrap, kProfileVaultKeySize)) {
		return false;
	}
	auto sealed = details::SealRevocableProfileGrant(
		envelope,
		{},
		admin.verifier,
		wrap,
		plaintext);
	if (!sealed) {
		return false;
	}
	envelope.adminNonce = std::move(sealed->nonce);
	envelope.adminCiphertext = std::move(sealed->ciphertext);
	return true;
}

std::optional<ProfileVault> Rewrite(
		QByteArrayView installationId,
		const Metadata &metadata,
		std::span<const RevocableAccountGrant> entries,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &replacements,
		const ProfileVault *previous,
		const MasterPayload *oldMaster,
		ProfileVaultError *error) {
	SetError(error, ProfileVaultError::InvalidVaultId);
	if (!ValidBytes(installationId, kProfileVaultIdSize)) {
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::InvalidKdf);
	if (!ValidProfileVaultKdf(metadata.verifierKdf)
		|| !details::ValidProfileVaultSalt(metadata.verifierSalt)
		|| (previous && (metadata.verifierSalt != previous->salt
			|| metadata.verifierKdf != previous->kdf))) {
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::MetadataMismatch);
	if (Validate(metadata) != ValidationError::None
		|| !Equal(metadata.masterVerifier, admin.verifier)) {
		return std::nullopt;
	}
	const auto accounts = IndexAccounts(installationId, entries, metadata);
	if (!accounts) {
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::InvalidGrant);
	auto supplied = std::map<SetId, const DerivedCredential*>();
	for (const auto &entry : replacements) {
		if (!entry.id || !details::ValidRevocableProfileCredential(entry.credential)
			|| !supplied.emplace(entry.id, &entry.credential).second) {
			return std::nullopt;
		}
	}
	auto oldSets = std::map<SetId, const AccountSet*>();
	auto oldGrants = std::map<SetId, const SealedSetGrant*>();
	if (previous) {
		for (const auto &set : oldMaster->access.metadata.sets) {
			oldSets.emplace(set.id, &set);
		}
		for (const auto &grant : previous->grants) {
			oldGrants.emplace(grant.id, &grant);
		}
	}
	auto ordered = std::map<SetId, const AccountSet*>();
	for (const auto &set : metadata.sets) {
		ordered.emplace(set.id, &set);
	}
	auto envelope = ProfileVault{
		.version = kRevocableProfileVaultVersion,
		.id = installationId.toByteArray(),
		.salt = metadata.verifierSalt,
		.kdf = metadata.verifierKdf,
		.adminVerifier = admin.verifier,
	};
	auto secrets = MasterPayload();
	auto size = qsizetype(0);
	for (const auto &[id, set] : ordered) {
		const auto old = oldSets.find(id);
		const auto suppliedKey = supplied.find(id);
		const auto retainsPassword = old != end(oldSets)
			&& Equal(old->second->verifier, set->verifier);
		auto &key = secrets.grantKeys[id];
		if (retainsPassword && suppliedKey == end(supplied)) {
			const auto &oldKey = oldMaster->grantKeys.at(id);
			key = QByteArray(oldKey.constData(), oldKey.size());
		} else if (!retainsPassword && suppliedKey != end(supplied)
			&& Equal(suppliedKey->second->verifier, set->verifier)) {
			key = details::RevocableProfileEnvelopeKey(envelope, id, *suppliedKey->second);
			supplied.erase(suppliedKey);
		} else {
			return std::nullopt;
		}
		if (!ValidBytes(key, kProfileVaultKeySize)) {
			return std::nullopt;
		}
		if (retainsPassword && old->second->accounts == set->accounts) {
			envelope.grants.push_back(*oldGrants.at(id));
		} else {
			auto grant = WriteSet(envelope, *set, *accounts, admin, key);
			if (!grant) {
				return std::nullopt;
			}
			envelope.grants.push_back(std::move(*grant));
		}
		size += envelope.grants.back().ciphertext.size();
		if (size > kMaximumCiphertextBytes) {
			SetError(error, ProfileVaultError::TooLarge);
			return std::nullopt;
		}
	}
	if (!supplied.empty() || !WriteMaster(envelope, metadata, *accounts, admin, secrets)) {
		return std::nullopt;
	}
	const auto validation = details::ValidateRevocableProfileEnvelope(envelope);
	SetError(error, validation);
	return (validation == ProfileVaultError::None)
		? std::optional(std::move(envelope))
		: std::nullopt;
}

} // namespace

RevocableSetVaultAccess::RevocableSetVaultAccess(
	SetId id,
	std::vector<AccountGateHandle> handles,
	QByteArray settingsKey)
: _id(id)
, _handles(std::move(handles))
, _settingsKey(std::move(settingsKey)) {
}

RevocableSetVaultAccess::RevocableSetVaultAccess(RevocableSetVaultAccess &&other) noexcept = default;

RevocableSetVaultAccess::~RevocableSetVaultAccess() {
	Wipe(_settingsKey);
}

SetId RevocableSetVaultAccess::id() const {
	return _id;
}

const std::vector<AccountGateHandle> &RevocableSetVaultAccess::handles() const {
	return _handles;
}

QByteArrayView RevocableSetVaultAccess::settingsKey() const {
	return _settingsKey;
}

RevocableProfileVault::RevocableProfileVault(ProfileVault envelope)
: _envelope(std::move(envelope)) {
}

std::optional<RevocableProfileVault> RevocableProfileVault::Seal(
		QByteArrayView installationId,
		const Metadata &metadata,
		std::span<const RevocableAccountGrant> accounts,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &credentials,
		ProfileVaultError *error) {
	if (!details::ValidRevocableProfileCredential(admin)) {
		SetError(error, ProfileVaultError::InvalidCredential);
		return std::nullopt;
	}
	auto envelope = Rewrite(
		installationId,
		metadata,
		accounts,
		admin,
		credentials,
		nullptr,
		nullptr,
		error);
	return envelope ? std::optional(RevocableProfileVault(std::move(*envelope))) : std::nullopt;
}

std::optional<RevocableProfileVault> RevocableProfileVault::Parse(
		const QByteArray &bytes,
		ProfileVaultError *error) {
	auto envelope = details::ParseRevocableProfileEnvelope(bytes, error);
	if (!envelope) {
		return std::nullopt;
	}
	if (!std::ranges::is_sorted(envelope->grants, {}, &SealedSetGrant::id)) {
		SetError(error, ProfileVaultError::Malformed);
		return std::nullopt;
	}
	return RevocableProfileVault(std::move(*envelope));
}

const QByteArray &RevocableProfileVault::installationId() const {
	return _envelope.id;
}

const QByteArray &RevocableProfileVault::salt() const {
	return _envelope.salt;
}

KdfParameters RevocableProfileVault::kdf() const {
	return _envelope.kdf;
}

QByteArray RevocableProfileVault::serialize(ProfileVaultError *error) const {
	return details::SerializeRevocableProfileEnvelope(_envelope, error);
}

RevocableProfileVaultAccess RevocableProfileVault::open(
		const DerivedCredential &credential,
		ProfileVaultError *error) const {
	if (!details::ValidRevocableProfileCredential(credential)) {
		SetError(error, ProfileVaultError::InvalidCredential);
		return WrongPassword();
	}
	if (Equal(credential.verifier, _envelope.adminVerifier)) {
		auto master = openMaster(credential, error);
		return master
			? RevocableProfileVaultAccess(std::move(*master))
			: RevocableProfileVaultAccess(WrongPassword());
	}
	const auto grant = std::ranges::find_if(_envelope.grants, [&](const SealedSetGrant &entry) {
		return Equal(credential.verifier, entry.verifier);
	});
	if (grant == end(_envelope.grants)) {
		SetError(error, ProfileVaultError::WrongPassword);
		return WrongPassword();
	}
	auto plaintext = ReadGrant(_envelope, *grant, credential);
	const auto wipe = gsl::finally([&] { Wipe(plaintext); });
	auto handles = ReadSetHandles(_envelope, grant->id, plaintext);
	if (!handles) {
		SetError(error, ProfileVaultError::AuthenticationFailed);
		return WrongPassword();
	}
	SetError(error, ProfileVaultError::None);
	return RevocableSetVaultAccess(
		grant->id,
		std::move(*handles),
		QByteArray(plaintext.constData() + 20, kProfileVaultKeySize));
}

std::optional<RevocableAdminVaultAccess> RevocableProfileVault::openMaster(
		const DerivedCredential &credential,
		ProfileVaultError *error) const {
	if (!details::ValidRevocableProfileCredential(credential)) {
		SetError(error, ProfileVaultError::InvalidCredential);
		return std::nullopt;
	}
	auto master = ReadMaster(_envelope, credential, error);
	return master ? std::optional(std::move(master->access)) : std::nullopt;
}

std::optional<RevocableProfileVault> RevocableProfileVault::updated(
		const DerivedCredential &admin,
		const Metadata &metadata,
		const std::vector<SetGrantCredential> &replacements,
		ProfileVaultError *error) const {
	if (!details::ValidRevocableProfileCredential(admin)) {
		SetError(error, ProfileVaultError::InvalidCredential);
		return std::nullopt;
	}
	auto master = ReadMaster(_envelope, admin, error);
	if (!master) {
		return std::nullopt;
	}
	auto envelope = Rewrite(
		_envelope.id,
		metadata,
		master->access.accounts,
		admin,
		replacements,
		&_envelope,
		&*master,
		error);
	return envelope ? std::optional(RevocableProfileVault(std::move(*envelope))) : std::nullopt;
}

std::optional<RevocableProfileVault> RevocableProfileVault::enrolled(
		const DerivedCredential &admin,
		SetId target,
		const DerivedCredential &setCredential,
		const AccountGateTable &currentGates,
		RevocableAccountGrant account,
		QString newSetName,
		ProfileVaultError *error) const {
	SetError(error, ProfileVaultError::InvalidAccountEnrollment);
	if (!target || currentGates.installationId() != _envelope.id
		|| !details::ValidRevocableProfileCredential(admin)
		|| !details::ValidRevocableProfileCredential(setCredential)
		|| !account.handle.matches(account.permit)) {
		return std::nullopt;
	}
	auto master = ReadMaster(_envelope, admin, error);
	if (!master) {
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::InvalidAccountEnrollment);
	auto metadata = master->access.metadata;
	const auto previous = std::ranges::find(metadata.sets, target, &AccountSet::id);
	const auto id = account.handle.binding().id;
	auto replacements = std::vector<SetGrantCredential>();
	const auto wipe = gsl::finally([&] {
		for (auto &replacement : replacements) {
			Wipe(replacement.credential.key);
			Wipe(replacement.credential.verifier);
		}
	});
	if (!newSetName.isEmpty()) {
		if (previous != end(metadata.sets) || !std::holds_alternative<WrongPassword>(
				RoutePasswordVerifier(metadata, setCredential.verifier))) {
			return std::nullopt;
		}
		metadata.sets.push_back(AccountSet{
			.id = target,
			.name = std::move(newSetName),
			.verifier = setCredential.verifier,
			.accounts = { id },
		});
		replacements.push_back({ target, setCredential });
	} else {
		const auto opened = open(setCredential);
		const auto scoped = std::get_if<RevocableSetVaultAccess>(&opened);
		if (previous == end(metadata.sets) || !scoped || scoped->id() != target
			|| scoped->handles().size() != previous->accounts.size()
			|| !std::ranges::all_of(scoped->handles(), [&](const AccountGateHandle &handle) {
				return std::ranges::find(previous->accounts, handle.binding().id) != end(previous->accounts)
					&& InspectAccountGate(currentGates, handle) == AccountGateStatus::Revoked;
			})) {
			return std::nullopt;
		}
		previous->accounts = { id };
	}
	master->access.accounts.push_back(std::move(account));
	auto envelope = Rewrite(
		_envelope.id,
		metadata,
		master->access.accounts,
		admin,
		replacements,
		&_envelope,
		&*master,
		error);
	return envelope ? std::optional(RevocableProfileVault(std::move(*envelope))) : std::nullopt;
}

} // namespace Ayu::ProfileSets
