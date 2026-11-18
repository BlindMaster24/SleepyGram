/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_vault.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <QtCore/QCryptographicHash>

#include <algorithm>
#include <map>
#include <set>
#include <utility>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kMagic = quint32(0x53504756);
constexpr auto kNonceSize = 12;
constexpr auto kTagSize = 16;
constexpr auto kMaximumVaultSize = 80 * 1024 * 1024;
constexpr auto kMinimumSerializedGrantSize = 80;
constexpr auto kMaximumGrantCount = quint32(
	kMaximumVaultSize / kMinimumSerializedGrantSize);
constexpr auto kMinimumArgonMemoryKiB = quint32(8'192);
constexpr auto kMaximumArgonMemoryKiB = quint32(65'536);
constexpr auto kMinimumArgonTime = quint32(1);
constexpr auto kMaximumArgonTime = quint32(8);
constexpr auto kMinimumScryptN = quint32(16'384);
constexpr auto kMaximumScryptN = quint32(131'072);
constexpr auto kMaximumScryptR = quint32(8);
constexpr auto kMaximumScryptP = quint32(1);
constexpr auto kArgon2id = quint32(1);
constexpr auto kScrypt = quint32(2);

constexpr char kVaultEnvelopeContext[]
	= "SleepyGram profile-vault envelope v1";
constexpr char kVerifierContext[] = "SleepyGram account-set verifier v2";
constexpr char kCredentialContext[] = "SleepyGram account-set credential v2";
constexpr char kEncryptionContext[] = "SleepyGram profile-vault grant key v2";
constexpr char kAdminContext[] = "SleepyGram profile-vault admin keyring v2";
constexpr char kSetKeyringContext[] = "SleepyGram profile-vault set keyring v2";
// v1 truncated the derivation context using the 64-bit pointer size.
constexpr auto kLegacyContextSize = 7;
constexpr auto kAdminPayloadContext = quint32(1);
constexpr auto kSetPayloadContext = quint32(2);
constexpr auto kLocatorRecordSize = 16 + kAccountVaultLocatorSize;
constexpr auto kGrantKeyRecordSize = 16 + kProfileVaultKeySize;

using AccountKeysById = std::map<AccountId, const AccountKey*>;
using LocatorsById = std::map<AccountId, const AccountVaultLocator*>;
using CredentialsById = std::map<SetId, const DerivedCredential*>;
using GrantKeys = std::map<SetId, QByteArray>;

struct SealedBlob final {
	QByteArray nonce;
	QByteArray ciphertext;
};

void SetError(ProfileVaultError *error, ProfileVaultError value) {
	if (error) {
		*error = value;
	}
}

void AppendUint32(QByteArray &data, quint32 value) {
	for (auto shift = 24; shift >= 0; shift -= 8) {
		data.append(char(value >> shift));
	}
}

void AppendUint64(QByteArray &data, quint64 value) {
	for (auto shift = 56; shift >= 0; shift -= 8) {
		data.append(char(value >> shift));
	}
}

quint32 ReadUint32(const char *data) {
	auto result = quint32(0);
	for (auto i = 0; i != 4; ++i) {
		result = (result << 8) | uchar(data[i]);
	}
	return result;
}

quint64 ReadUint64(const char *data) {
	auto result = quint64(0);
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | uchar(data[i]);
	}
	return result;
}

bool TakeBytes(
		const QByteArray &data,
		qsizetype *offset,
		quint32 maximum,
		QByteArray *result) {
	if (*offset > data.size() - 4) {
		return false;
	}
	const auto size = ReadUint32(data.constData() + *offset);
	*offset += 4;
	if (size > maximum || qsizetype(size) > data.size() - *offset) {
		return false;
	}
	*result = data.mid(*offset, size);
	*offset += size;
	return true;
}

void AppendBytes(QByteArray &data, const QByteArray &value) {
	AppendUint32(data, quint32(value.size()));
	data.append(value);
}

bool EqualSecret(const QByteArray &a, const QByteArray &b) {
	return (a.size() == b.size())
		&& !CRYPTO_memcmp(a.constData(), b.constData(), a.size());
}

bool AllZero(const QByteArray &bytes) {
	return std::all_of(bytes.cbegin(), bytes.cend(), [](char value) {
		return value == 0;
	});
}

bool ValidLocator(const AccountVaultLocator &locator) {
	return locator.id && locator.value.size() == kAccountVaultLocatorSize
		&& !AllZero(locator.value);
}

QByteArray RandomBytes(int size) {
	auto result = QByteArray(size, Qt::Uninitialized);
	if (RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), size)
		!= 1 || AllZero(result)) {
		OPENSSL_cleanse(result.data(), result.size());
		result.clear();
	}
	return result;
}

bool ValidCredential(const DerivedCredential &credential) {
	return credential.valid()
		&& !AllZero(credential.verifier)
		&& !AllZero(credential.key)
		&& !EqualSecret(credential.verifier, credential.key);
}

QByteArray Digest(QByteArrayView context, QByteArrayView data) {
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	hash.addData(context);
	hash.addData(data);
	return hash.result();
}

QByteArray HmacSha256(const QByteArray &key, const QByteArray &data) {
	auto result = QByteArray(32, Qt::Uninitialized);
	auto size = 0U;
	const auto ok = HMAC(
		EVP_sha256(),
		key.constData(),
		int(key.size()),
		reinterpret_cast<const unsigned char*>(data.constData()),
		size_t(data.size()),
		reinterpret_cast<unsigned char*>(result.data()),
		&size);
	return (ok && size == uint(result.size())) ? result : QByteArray();
}

QByteArray GrantKey(
		const DerivedCredential &credential,
		const ProfileVault &vault,
		quint32 role,
		SetId setId) {
	auto input = QByteArray();
	const auto legacy = (vault.version == kLegacyProfileVaultVersion);
	input.append(kEncryptionContext, legacy
		? kLegacyContextSize
		: int(sizeof(kEncryptionContext) - 1));
	input.append(vault.id);
	AppendUint32(input, role);
	AppendUint64(input, setId.high);
	AppendUint64(input, setId.low);
	return HmacSha256(credential.key, input);
}

QByteArray AssociatedData(
		const ProfileVault &vault,
		quint32 role,
		SetId setId,
		const QByteArray &verifier) {
	auto result = QByteArray();
	result.append(
		kVaultEnvelopeContext,
		int(sizeof(kVaultEnvelopeContext) - 1));
	AppendUint32(result, vault.version);
	result.append(vault.id);
	AppendBytes(result, vault.salt);
	AppendUint32(result, vault.kdf.kind);
	AppendUint32(result, vault.kdf.memory);
	AppendUint32(result, vault.kdf.time);
	AppendUint32(result, vault.kdf.parallel);
	AppendUint32(result, role);
	AppendUint64(result, setId.high);
	AppendUint64(result, setId.low);
	result.append(verifier);
	return result;
}

QByteArray SealAesGcm(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &aad,
		const QByteArray &plaintext) {
	if (key.size() != kProfileVaultKeySize || nonce.size() != kNonceSize) {
		return {};
	}
	auto result = QByteArray(plaintext.size() + kTagSize, Qt::Uninitialized);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return {};
	}
	const auto cleanup = gsl::finally([&] { EVP_CIPHER_CTX_free(context); });
	auto outLength = 0;
	auto total = 0;
	auto ok = (EVP_EncryptInit_ex(
		context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1)
		&& (EVP_CIPHER_CTX_ctrl(
			context, EVP_CTRL_GCM_SET_IVLEN, int(nonce.size()), nullptr) == 1)
		&& (EVP_EncryptInit_ex(
			context,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) == 1)
		&& (EVP_EncryptUpdate(
			context,
			nullptr,
			&outLength,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			int(aad.size())) == 1);
	if (ok && !plaintext.isEmpty()) {
		ok = EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data()),
			&outLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			int(plaintext.size())) == 1;
		total = outLength;
	}
	if (ok) {
		ok = EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<unsigned char*>(result.data()) + total,
			&outLength) == 1;
		total += outLength;
	}
	if (ok) {
		ok = EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_GET_TAG,
			kTagSize,
			reinterpret_cast<unsigned char*>(result.data()) + plaintext.size()) == 1;
	}
	return ok && total == plaintext.size() ? result : QByteArray();
}

QByteArray OpenAesGcm(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &aad,
		const QByteArray &ciphertext) {
	if (key.size() != kProfileVaultKeySize
		|| nonce.size() != kNonceSize
		|| ciphertext.size() < kTagSize) {
		return {};
	}
	const auto length = ciphertext.size() - kTagSize;
	auto result = QByteArray(length, Qt::Uninitialized);
	const auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return {};
	}
	const auto cleanup = gsl::finally([&] { EVP_CIPHER_CTX_free(context); });
	auto outLength = 0;
	auto total = 0;
	auto ok = (EVP_DecryptInit_ex(
		context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1)
		&& (EVP_CIPHER_CTX_ctrl(
			context, EVP_CTRL_GCM_SET_IVLEN, int(nonce.size()), nullptr) == 1)
		&& (EVP_DecryptInit_ex(
			context,
			nullptr,
			nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) == 1)
		&& (EVP_DecryptUpdate(
			context,
			nullptr,
			&outLength,
			reinterpret_cast<const unsigned char*>(aad.constData()),
			int(aad.size())) == 1);
	if (ok && length) {
		ok = EVP_DecryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data()),
			&outLength,
			reinterpret_cast<const unsigned char*>(ciphertext.constData()),
			int(length)) == 1;
		total = outLength;
	}
	auto tag = ciphertext.mid(int(length), kTagSize);
	if (ok) {
		ok = (EVP_CIPHER_CTX_ctrl(
			context,
			EVP_CTRL_GCM_SET_TAG,
			kTagSize,
			reinterpret_cast<unsigned char*>(tag.data())) == 1)
			&& (EVP_DecryptFinal_ex(
				context,
				reinterpret_cast<unsigned char*>(result.data()) + total,
				&outLength) == 1);
		total += outLength;
	}
	if (!ok || total != length) {
		if (!result.isEmpty()) {
			OPENSSL_cleanse(result.data(), result.size());
		}
		return {};
	}
	return result;
}

bool Seal(
		const QByteArray &key,
		const QByteArray &aad,
		const QByteArray &plaintext,
		SealedBlob *blob) {
	blob->nonce = QByteArray(kNonceSize, Qt::Uninitialized);
	if (RAND_bytes(
		reinterpret_cast<unsigned char*>(blob->nonce.data()),
		int(blob->nonce.size())) != 1) {
		OPENSSL_cleanse(blob->nonce.data(), blob->nonce.size());
		blob->nonce.clear();
		return false;
	}
	blob->ciphertext = SealAesGcm(key, blob->nonce, aad, plaintext);
	return !blob->ciphertext.isEmpty();
}

QByteArray SerializeAdminPayload(
		const Metadata &metadata,
		const QByteArray &keyring,
		const QByteArray &manifest,
		const std::vector<AccountVaultLocator> &locators,
		const GrantKeys &grantKeys) {
	const auto metadataBytes = SerializeMetadataPayload(metadata);
	if (metadataBytes.isEmpty() || manifest.size() != kVerifierSize) {
		return {};
	}
	auto result = QByteArray();
	result.reserve(
		5 * 4 + metadataBytes.size() + keyring.size() + manifest.size()
		+ qsizetype(locators.size()) * kLocatorRecordSize
		+ qsizetype(grantKeys.size()) * kGrantKeyRecordSize);
	AppendUint32(result, kAdminPayloadContext);
	AppendBytes(result, metadataBytes);
	AppendBytes(result, keyring);
	AppendBytes(result, manifest);
	AppendUint32(result, quint32(locators.size() * kLocatorRecordSize));
	for (const auto &locator : locators) {
		AppendUint64(result, locator.id.high);
		AppendUint64(result, locator.id.low);
		result.append(locator.value);
	}
	AppendUint32(result, quint32(grantKeys.size() * kGrantKeyRecordSize));
	for (const auto &[id, key] : grantKeys) {
		AppendUint64(result, id.high);
		AppendUint64(result, id.low);
		result.append(key);
	}
	return result;
}

QByteArray GrantManifest(const std::vector<SealedSetGrant> &grants) {
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	for (const auto &grant : grants) {
		auto header = QByteArray();
		AppendUint64(header, grant.id.high);
		AppendUint64(header, grant.id.low);
		header.append(grant.verifier);
		header.append(grant.nonce);
		AppendUint32(header, quint32(grant.ciphertext.size()));
		hash.addData(header);
		hash.addData(grant.ciphertext);
	}
	return hash.result();
}

struct ParsedAdminPayload final {
	Metadata metadata;
	QByteArray keyring;
	QByteArray manifest;
	QByteArray locators;
	QByteArray grantKeys;
};

std::optional<ParsedAdminPayload> ParseAdminPayload(
		const QByteArray &payload,
		bool legacy) {
	if (payload.size() < 12
		|| payload.size() > kMaximumVaultSize
		|| ReadUint32(payload.constData()) != kAdminPayloadContext) {
		return std::nullopt;
	}
	auto offset = qsizetype(4);
	auto metadataBytes = QByteArray();
	auto result = ParsedAdminPayload();
	if (!TakeBytes(payload, &offset, kMaximumVaultSize, &metadataBytes)
		|| !TakeBytes(payload, &offset, kMaximumVaultSize, &result.keyring)
		|| !TakeBytes(payload, &offset, kVerifierSize, &result.manifest)
		|| (!legacy
			&& (!TakeBytes(payload, &offset, kMaximumVaultSize, &result.locators)
				|| !TakeBytes(
					payload,
					&offset,
					kMaximumVaultSize,
					&result.grantKeys)))
		|| offset != payload.size() || result.keyring.isEmpty()) {
		OPENSSL_cleanse(result.grantKeys.data(), result.grantKeys.size());
		return std::nullopt;
	}
	auto error = ValidationError::Malformed;
	auto metadata = ParseMetadataPayload(metadataBytes, &error);
	if (!metadata) {
		OPENSSL_cleanse(result.grantKeys.data(), result.grantKeys.size());
		return std::nullopt;
	}
	result.metadata = std::move(*metadata);
	return result;
}

QByteArray SerializeSetPayload(
		SetId id,
		const QByteArray &keyring,
		const std::vector<AccountVaultLocator> &locators) {
	auto result = QByteArray();
	AppendUint32(result, kSetPayloadContext);
	AppendUint64(result, id.high);
	AppendUint64(result, id.low);
	AppendBytes(result, keyring);
	for (const auto &locator : locators) {
		AppendUint64(result, locator.id.high);
		AppendUint64(result, locator.id.low);
		result.append(locator.value);
	}
	return result;
}

struct ParsedSetPayload final {
	SetId id;
	QByteArray keyring;
	QByteArray locators;
};

std::optional<ParsedSetPayload> ParseSetPayload(
		const QByteArray &payload,
		bool legacy) {
	if (payload.size() < 24
		|| payload.size() > kMaximumVaultSize
		|| ReadUint32(payload.constData()) != kSetPayloadContext) {
		return std::nullopt;
	}
	const auto id = SetId{
		.high = ReadUint64(payload.constData() + 4),
		.low = ReadUint64(payload.constData() + 12),
	};
	auto offset = qsizetype(20);
	auto keyring = QByteArray();
	if (!id || !TakeBytes(payload, &offset, kMaximumVaultSize, &keyring)
		|| (legacy && offset != payload.size())
		|| keyring.isEmpty()) {
		return std::nullopt;
	}
	return ParsedSetPayload{
		id,
		std::move(keyring),
		payload.mid(offset),
	};
}

QByteArray SetAad(
		const ProfileVault &vault,
		const SealedSetGrant &grant) {
	return AssociatedData(vault, kSetPayloadContext, grant.id, grant.verifier);
}

QByteArray AdminAad(const ProfileVault &vault) {
	return AssociatedData(
		vault,
		kAdminPayloadContext,
		SetId(),
		vault.adminVerifier);
}

ProfileVaultError ValidateVault(const ProfileVault &vault) {
	if (vault.version != kProfileVaultVersion
		&& vault.version != kLegacyProfileVaultVersion) {
		return ProfileVaultError::UnsupportedVersion;
	} else if (vault.id.size() != kProfileVaultIdSize || AllZero(vault.id)) {
		return ProfileVaultError::InvalidVaultId;
	} else if (!details::ValidProfileVaultSalt(vault.salt)
		|| !ValidProfileVaultKdf(vault.kdf)) {
		return ProfileVaultError::InvalidKdf;
	} else if (vault.adminVerifier.size() != kVerifierSize
		|| vault.adminNonce.size() != kNonceSize
		|| vault.adminCiphertext.size() < kTagSize) {
		return ProfileVaultError::InvalidGrant;
	} else if (vault.grants.size() > kMaximumGrantCount) {
		return ProfileVaultError::TooLarge;
	}
	auto estimatedSize = qsizetype(
		8 + kProfileVaultIdSize + 4 + 16 + kVerifierSize + kNonceSize + 4 + 4);
	estimatedSize += vault.salt.size() + vault.adminCiphertext.size();
	if (estimatedSize > kMaximumVaultSize) {
		return ProfileVaultError::TooLarge;
	}
	for (const auto &grant : vault.grants) {
		estimatedSize += kMinimumSerializedGrantSize
			+ grant.ciphertext.size() - kTagSize;
		if (estimatedSize > kMaximumVaultSize) {
			return ProfileVaultError::TooLarge;
		}
	}
	auto ids = std::set<SetId>();
	auto verifiers = std::set<QByteArray>{ vault.adminVerifier };
	for (const auto &grant : vault.grants) {
		if (!grant.id || !ids.insert(grant.id).second
			|| grant.verifier.size() != kVerifierSize
			|| !verifiers.insert(grant.verifier).second
			|| grant.nonce.size() != kNonceSize
			|| grant.ciphertext.size() < kTagSize) {
			return ProfileVaultError::InvalidGrant;
		}
	}
	return ProfileVaultError::None;
}

bool MetadataMatchesVault(
		const Metadata &metadata,
		const ProfileVault &vault) {
	if (metadata.verifierSalt != vault.salt
		|| metadata.verifierKdf != vault.kdf
		|| !EqualSecret(metadata.masterVerifier, vault.adminVerifier)
		|| metadata.sets.size() != vault.grants.size()) {
		return false;
	}
	auto expected = std::map<SetId, QByteArray>();
	for (const auto &set : metadata.sets) {
		expected.emplace(set.id, set.verifier);
	}
	for (const auto &grant : vault.grants) {
		const auto i = expected.find(grant.id);
		if (i == end(expected) || !EqualSecret(i->second, grant.verifier)) {
			return false;
		}
	}
	return true;
}

bool AccountMembershipsExist(
		const Metadata &metadata,
		const std::vector<AccountKey> &accounts) {
	auto ids = std::set<AccountId>();
	for (const auto &account : accounts) {
		ids.insert(account.id);
	}
	for (const auto &set : metadata.sets) {
		for (const auto id : set.accounts) {
			if (!ids.contains(id)) {
				return false;
			}
		}
	}
	return true;
}

std::optional<SealedSetGrant> FindGrant(
		const ProfileVault &vault,
		const QByteArray &verifier) {
	for (const auto &grant : vault.grants) {
		if (EqualSecret(grant.verifier, verifier)) {
			return grant;
		}
	}
	return std::nullopt;
}

QByteArray CredentialKeyringKey(
		const DerivedCredential &credential,
		const ProfileVault &vault,
		SetId setId) {
	const auto legacy = (vault.version == kLegacyProfileVaultVersion);
	auto input = QByteArray(kAdminContext, legacy
		? kLegacyContextSize
		: int(sizeof(kAdminContext) - 1));
	input.append(vault.id);
	AppendUint64(input, setId.high);
	AppendUint64(input, setId.low);
	return HmacSha256(credential.key, input);
}

QByteArray SetKeyringKey(const QByteArray &grantKey) {
	return HmacSha256(
		grantKey,
		QByteArray(kSetKeyringContext, int(sizeof(kSetKeyringContext) - 1)));
}

void CleanseAccountKeys(std::vector<AccountKey> &accounts) {
	for (auto &account : accounts) {
		if (!account.key.isEmpty()) {
			OPENSSL_cleanse(account.key.data(), account.key.size());
		}
	}
}

void CleanseGrantKeys(GrantKeys &keys) {
	for (auto &entry : keys) {
		auto &key = entry.second;
		OPENSSL_cleanse(key.data(), key.size());
	}
}

LocatorsById IndexLocators(
		const std::vector<AccountVaultLocator> &locators) {
	auto result = LocatorsById();
	auto values = std::set<QByteArray>();
	for (const auto &locator : locators) {
		if (!ValidLocator(locator)
			|| !values.insert(locator.value).second
			|| !result.emplace(locator.id, &locator).second) {
			return {};
		}
	}
	return result;
}

bool AccountLocatorsMatch(
		const std::vector<AccountKey> &accounts,
		const LocatorsById &locators) {
	return accounts.size() == locators.size()
		&& std::all_of(
			accounts.cbegin(),
			accounts.cend(),
			[&](const AccountKey &account) {
				return locators.contains(account.id);
			});
}

std::optional<std::vector<AccountVaultLocator>> ParseLocators(
		const QByteArray &serialized,
		const std::vector<AccountKey> &accounts) {
	if (serialized.size() != qsizetype(accounts.size()) * kLocatorRecordSize) {
		return std::nullopt;
	}
	auto result = std::vector<AccountVaultLocator>();
	result.reserve(accounts.size());
	for (auto offset = qsizetype(0); offset < serialized.size();
			offset += kLocatorRecordSize) {
		const auto data = serialized.constData() + offset;
		result.push_back({
			.id = { ReadUint64(data), ReadUint64(data + 8) },
			.value = serialized.mid(offset + 16, kAccountVaultLocatorSize),
		});
	}
	return AccountLocatorsMatch(accounts, IndexLocators(result))
		? std::optional(std::move(result))
		: std::nullopt;
}

bool ParseGrantKeys(
		const QByteArray &serialized,
		const Metadata &metadata,
		GrantKeys &result) {
	if (serialized.size() != qsizetype(metadata.sets.size())
		* kGrantKeyRecordSize) {
		return false;
	}
	for (auto offset = qsizetype(0); offset < serialized.size();
			offset += kGrantKeyRecordSize) {
		const auto data = serialized.constData() + offset;
		const auto id = SetId{ ReadUint64(data), ReadUint64(data + 8) };
		if (!id || result.contains(id)) {
			return false;
		}
		auto key = serialized.mid(offset + 16, kProfileVaultKeySize);
		if (AllZero(key)) {
			OPENSSL_cleanse(key.data(), key.size());
			return false;
		}
		result.emplace(id, std::move(key));
	}
	return std::all_of(
		metadata.sets.cbegin(),
		metadata.sets.cend(),
		[&](const AccountSet &set) { return result.contains(set.id); });
}

std::optional<AdminVaultAccess> OpenAdminVault(
		const ProfileVault &vault,
		const DerivedCredential &credential,
		GrantKeys &grantKeys,
		ProfileVaultError *error) {
	SetError(error, ProfileVaultError::WrongPassword);
	if (!EqualSecret(credential.verifier, vault.adminVerifier)) {
		return std::nullopt;
	}
	auto wrapKey = GrantKey(credential, vault, kAdminPayloadContext, {});
	auto plaintext = OpenAesGcm(
		wrapKey,
		vault.adminNonce,
		AdminAad(vault),
		vault.adminCiphertext);
	OPENSSL_cleanse(wrapKey.data(), wrapKey.size());
	SetError(error, ProfileVaultError::AuthenticationFailed);
	if (plaintext.isEmpty()) {
		return std::nullopt;
	}
	const auto wipePlaintext = gsl::finally([&] {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
	});
	const auto legacy = (vault.version == kLegacyProfileVaultVersion);
	auto parsed = ParseAdminPayload(plaintext, legacy);
	SetError(error, ProfileVaultError::MetadataMismatch);
	if (!parsed) {
		return std::nullopt;
	}
	const auto wipeGrantKeys = gsl::finally([&] {
		OPENSSL_cleanse(parsed->grantKeys.data(), parsed->grantKeys.size());
	});
	if (!MetadataMatchesVault(parsed->metadata, vault)
		|| !EqualSecret(parsed->manifest, GrantManifest(vault.grants))
		|| (!legacy && !ParseGrantKeys(
			parsed->grantKeys,
			parsed->metadata,
			grantKeys))) {
		return std::nullopt;
	}
	auto keyringKey = CredentialKeyringKey(credential, vault, {});
	auto accounts = OpenAccountKeyring(parsed->keyring, keyringKey);
	OPENSSL_cleanse(keyringKey.data(), keyringKey.size());
	if (!accounts) {
		return std::nullopt;
	}
	auto locators = legacy
		? std::optional(std::vector<AccountVaultLocator>())
		: ParseLocators(parsed->locators, *accounts);
	if (!locators || !AccountMembershipsExist(parsed->metadata, *accounts)) {
		CleanseAccountKeys(*accounts);
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::None);
	return AdminVaultAccess{
		.metadata = std::move(parsed->metadata),
		.accounts = std::move(*accounts),
		.locators = std::move(*locators),
		.version = vault.version,
	};
}

std::optional<SealedSetGrant> SealSetGrant(
		const ProfileVault &vault,
		const AccountSet &set,
		const AccountKeysById &accounts,
		const LocatorsById &locators,
		const QByteArray &grantKey) {
	auto subset = std::vector<AccountKey>();
	auto scopedLocators = std::vector<AccountVaultLocator>();
	subset.reserve(set.accounts.size());
	scopedLocators.reserve(set.accounts.size());
	for (const auto id : set.accounts) {
		subset.push_back(*accounts.at(id));
		scopedLocators.push_back(*locators.at(id));
	}
	auto keyringKey = SetKeyringKey(grantKey);
	const auto keyring = SealAccountKeyring(subset, keyringKey);
	OPENSSL_cleanse(keyringKey.data(), keyringKey.size());
	CleanseAccountKeys(subset);
	if (keyring.isEmpty()) {
		return std::nullopt;
	}
	auto plaintext = SerializeSetPayload(set.id, keyring, scopedLocators);
	auto sealed = SealedBlob();
	auto grant = SealedSetGrant{ .id = set.id, .verifier = set.verifier };
	const auto ok = Seal(grantKey, SetAad(vault, grant), plaintext, &sealed);
	OPENSSL_cleanse(plaintext.data(), plaintext.size());
	if (!ok) {
		return std::nullopt;
	}
	grant.nonce = std::move(sealed.nonce);
	grant.ciphertext = std::move(sealed.ciphertext);
	return grant;
}

bool SealAdminGrant(
		ProfileVault &vault,
		const Metadata &metadata,
		const DerivedCredential &admin,
		const std::vector<AccountKey> &accounts,
		const std::vector<AccountVaultLocator> &locators,
		const GrantKeys &grantKeys) {
	auto keyringKey = CredentialKeyringKey(admin, vault, {});
	const auto keyring = SealAccountKeyring(accounts, keyringKey);
	OPENSSL_cleanse(keyringKey.data(), keyringKey.size());
	if (keyring.isEmpty()) {
		return false;
	}
	auto plaintext = SerializeAdminPayload(
		metadata,
		keyring,
		GrantManifest(vault.grants),
		locators,
		grantKeys);
	auto wrapKey = GrantKey(admin, vault, kAdminPayloadContext, {});
	auto sealed = SealedBlob();
	const auto ok = !plaintext.isEmpty()
		&& Seal(wrapKey, AdminAad(vault), plaintext, &sealed);
	OPENSSL_cleanse(plaintext.data(), plaintext.size());
	OPENSSL_cleanse(wrapKey.data(), wrapKey.size());
	if (ok) {
		vault.adminNonce = std::move(sealed.nonce);
		vault.adminCiphertext = std::move(sealed.ciphertext);
	}
	return ok;
}

std::optional<ProfileVault> RewriteVault(
		const Metadata &metadata,
		const std::vector<AccountKey> &accounts,
		const std::vector<AccountVaultLocator> &locators,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &replacements,
		const ProfileVault *previous,
		const Metadata *previousMetadata,
		const GrantKeys &previousKeys,
		ProfileVaultError *error) {
	SetError(error, ProfileVaultError::InvalidKdf);
	if (!ValidProfileVaultKdf(metadata.verifierKdf)) {
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::MetadataMismatch);
	const auto locatorsById = IndexLocators(locators);
	if (Validate(metadata) != ValidationError::None
		|| !details::ValidProfileVaultSalt(metadata.verifierSalt)
		|| !ValidCredential(admin)
		|| !EqualSecret(admin.verifier, metadata.masterVerifier)
		|| (previous && (metadata.verifierSalt != previous->salt
			|| metadata.verifierKdf != previous->kdf))
		|| ValidateAccountKeys(accounts) != KeyringError::None
		|| !AccountMembershipsExist(metadata, accounts)
		|| locatorsById.size() != locators.size()
		|| !AccountLocatorsMatch(accounts, locatorsById)) {
		return std::nullopt;
	}
	auto supplied = CredentialsById();
	for (const auto &grant : replacements) {
		if (!grant.id || !ValidCredential(grant.credential)
			|| !supplied.emplace(grant.id, &grant.credential).second) {
			SetError(error, ProfileVaultError::InvalidGrant);
			return std::nullopt;
		}
	}
	auto vault = ProfileVault{
		.id = previous ? previous->id : RandomBytes(kProfileVaultIdSize),
		.salt = metadata.verifierSalt,
		.kdf = metadata.verifierKdf,
		.adminVerifier = admin.verifier,
	};
	if (vault.id.isEmpty()) {
		SetError(error, ProfileVaultError::RandomFailure);
		return std::nullopt;
	}
	auto accountKeys = AccountKeysById();
	for (const auto &account : accounts) {
		accountKeys.emplace(account.id, &account);
	}
	auto previousSets = std::map<SetId, const AccountSet*>();
	auto previousGrants = std::map<SetId, const SealedSetGrant*>();
	if (previous) {
		for (const auto &set : previousMetadata->sets) {
			previousSets.emplace(set.id, &set);
		}
		for (const auto &grant : previous->grants) {
			previousGrants.emplace(grant.id, &grant);
		}
	}
	auto grantKeys = GrantKeys();
	const auto wipe = gsl::finally([&] { CleanseGrantKeys(grantKeys); });
	auto bytes = qsizetype(0);
	for (const auto &set : metadata.sets) {
		const auto old = previousSets.find(set.id);
		const auto retain = (old != end(previousSets))
			&& EqualSecret(old->second->verifier, set.verifier);
		const auto it = supplied.find(set.id);
		const auto replacementMatches = it != end(supplied)
			&& EqualSecret(it->second->verifier, set.verifier);
		if ((retain && it != end(supplied)) || (!retain && !replacementMatches)) {
			SetError(error, ProfileVaultError::MetadataMismatch);
			return std::nullopt;
		}
		auto &key = grantKeys[set.id];
		if (retain) {
			key = previousKeys.at(set.id);
		} else {
			key = GrantKey(*it->second, vault, kSetPayloadContext, set.id);
			supplied.erase(it);
		}
		if (key.size() != kProfileVaultKeySize || AllZero(key)) {
			SetError(error, ProfileVaultError::InvalidGrant);
			return std::nullopt;
		}
		if (retain && old->second->accounts == set.accounts) {
			vault.grants.push_back(*previousGrants.at(set.id));
		} else {
			auto grant = SealSetGrant(vault, set, accountKeys, locatorsById, key);
			if (!grant) {
				SetError(error, ProfileVaultError::InvalidGrant);
				return std::nullopt;
			}
			vault.grants.push_back(std::move(*grant));
		}
		bytes += kMinimumSerializedGrantSize
			+ vault.grants.back().ciphertext.size() - kTagSize;
		if (bytes > kMaximumVaultSize) {
			SetError(error, ProfileVaultError::TooLarge);
			return std::nullopt;
		}
	}
	if (!supplied.empty()) {
		SetError(error, ProfileVaultError::InvalidGrant);
		return std::nullopt;
	}
	if (!SealAdminGrant(vault, metadata, admin, accounts, locators, grantKeys)) {
		SetError(error, ProfileVaultError::InvalidGrant);
		return std::nullopt;
	}
	const auto validation = ValidateVault(vault);
	SetError(error, validation);
	return (validation == ProfileVaultError::None)
		? std::optional(std::move(vault))
		: std::nullopt;
}

} // namespace

bool ValidProfileVaultKdf(KdfParameters parameters) {
	if (parameters.kind == kArgon2id) {
		return parameters.memory >= kMinimumArgonMemoryKiB
			&& parameters.memory <= kMaximumArgonMemoryKiB
			&& parameters.time >= kMinimumArgonTime
			&& parameters.time <= kMaximumArgonTime
			&& parameters.parallel == 1;
	} else if (parameters.kind == kScrypt) {
		return parameters.memory >= kMinimumScryptN
			&& parameters.memory <= kMaximumScryptN
			&& !(parameters.memory & (parameters.memory - 1))
			&& parameters.time >= 1
			&& parameters.time <= kMaximumScryptR
			&& parameters.parallel == kMaximumScryptP;
	}
	return false;
}

std::optional<AccountVaultLocator> NewAccountVaultLocator(AccountId id) {
	auto value = id ? RandomBytes(kAccountVaultLocatorSize) : QByteArray();
	return value.isEmpty()
		? std::nullopt
		: std::optional(AccountVaultLocator{ id, std::move(value) });
}

QString AccountVaultDataName(const AccountVaultLocator &locator) {
	return ValidLocator(locator)
		? QString::fromLatin1(locator.value.toHex())
		: QString();
}

bool details::ValidProfileVaultSalt(const QByteArray &salt) {
	return salt.size() >= 8 && salt.size() <= 64;
}

DerivedCredential details::ProfileVaultCredentialFromKdfOutput(
		QByteArrayView material) {
	if (material.isEmpty()) {
		return {};
	}
	return {
		.verifier = Digest(kVerifierContext, material),
		.key = Digest(kCredentialContext, material),
	};
}

std::optional<ProfileVault> SealProfileVault(
		const Metadata &metadata,
		const std::vector<AccountKey> &accounts,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &grants,
		ProfileVaultError *error) {
	auto locators = std::vector<AccountVaultLocator>();
	locators.reserve(accounts.size());
	for (const auto &account : accounts) {
		auto locator = NewAccountVaultLocator(account.id);
		if (!locator) {
			SetError(error, ProfileVaultError::RandomFailure);
			return std::nullopt;
		}
		locators.push_back(std::move(*locator));
	}
	return SealProfileVault(metadata, accounts, locators, admin, grants, error);
}

std::optional<ProfileVault> SealProfileVault(
		const Metadata &metadata,
		const std::vector<AccountKey> &accounts,
		const std::vector<AccountVaultLocator> &locators,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &grants,
		ProfileVaultError *error) {
	return RewriteVault(
		metadata,
		accounts,
		locators,
		admin,
		grants,
		nullptr,
		nullptr,
		{},
		error);
}

std::optional<ProfileVault> UpdateProfileVault(
		const ProfileVault &vault,
		const DerivedCredential &admin,
		const Metadata &metadata,
		const std::vector<SetGrantCredential> &replacementCredentials,
		ProfileVaultError *error) {
	const auto validation = ValidateVault(vault);
	if (validation != ProfileVaultError::None) {
		SetError(error, validation);
		return std::nullopt;
	} else if (vault.version != kProfileVaultVersion) {
		SetError(error, ProfileVaultError::UnsupportedVersion);
		return std::nullopt;
	} else if (!ValidCredential(admin)) {
		SetError(error, ProfileVaultError::InvalidCredential);
		return std::nullopt;
	}
	auto keys = GrantKeys();
	const auto wipe = gsl::finally([&] { CleanseGrantKeys(keys); });
	auto opened = OpenAdminVault(vault, admin, keys, error);
	if (!opened) {
		return std::nullopt;
	}
	const auto wipeAccounts = gsl::finally([&] {
		CleanseAccountKeys(opened->accounts);
	});
	return RewriteVault(
		metadata,
		opened->accounts,
		opened->locators,
		admin,
		replacementCredentials,
		&vault,
		&opened->metadata,
		keys,
		error);
}

ProfileVaultAccess OpenProfileVault(
		const ProfileVault &vault,
		const DerivedCredential &credential,
		ProfileVaultError *error) {
	SetError(error, ProfileVaultError::InvalidCredential);
	const auto vaultError = ValidateVault(vault);
	if (vaultError != ProfileVaultError::None) {
		SetError(error, vaultError);
		return WrongPassword();
	} else if (!ValidCredential(credential)) {
		SetError(error, ProfileVaultError::InvalidCredential);
		return WrongPassword();
	}
	if (EqualSecret(credential.verifier, vault.adminVerifier)) {
		auto keys = GrantKeys();
		const auto wipe = gsl::finally([&] { CleanseGrantKeys(keys); });
		auto opened = OpenAdminVault(vault, credential, keys, error);
		return opened
			? ProfileVaultAccess(std::move(*opened))
			: ProfileVaultAccess(WrongPassword());
	}
	const auto grant = FindGrant(vault, credential.verifier);
	if (!grant) {
		SetError(error, ProfileVaultError::WrongPassword);
		return WrongPassword();
	}
	auto grantKey = GrantKey(credential, vault, kSetPayloadContext, grant->id);
	const auto wipeGrantKey = gsl::finally([&] {
		OPENSSL_cleanse(grantKey.data(), grantKey.size());
	});
	auto plaintext = OpenAesGcm(
		grantKey,
		grant->nonce,
		SetAad(vault, *grant),
		grant->ciphertext);
	if (plaintext.isEmpty()) {
		SetError(error, ProfileVaultError::AuthenticationFailed);
		return WrongPassword();
	}
	const auto cleanse = gsl::finally([&] {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
	});
	const auto legacy = (vault.version == kLegacyProfileVaultVersion);
	const auto parsed = ParseSetPayload(plaintext, legacy);
	if (!parsed || parsed->id != grant->id) {
		SetError(error, ProfileVaultError::AuthenticationFailed);
		return WrongPassword();
	}
	auto keyringKey = legacy
		? CredentialKeyringKey(credential, vault, grant->id)
		: SetKeyringKey(grantKey);
	auto accounts = OpenAccountKeyring(parsed->keyring, keyringKey);
	OPENSSL_cleanse(keyringKey.data(), keyringKey.size());
	if (!accounts) {
		SetError(error, ProfileVaultError::AuthenticationFailed);
		return WrongPassword();
	}
	auto locators = legacy
		? std::optional(std::vector<AccountVaultLocator>())
		: ParseLocators(parsed->locators, *accounts);
	if (!locators) {
		CleanseAccountKeys(*accounts);
		SetError(error, ProfileVaultError::AuthenticationFailed);
		return WrongPassword();
	}
	SetError(error, ProfileVaultError::None);
	return SetVaultAccess{
		.id = grant->id,
		.accounts = std::move(*accounts),
		.locators = std::move(*locators),
		.version = vault.version,
	};
}

QByteArray SerializeProfileVault(
		const ProfileVault &vault,
		ProfileVaultError *error) {
	const auto validation = ValidateVault(vault);
	SetError(error, validation);
	if (validation != ProfileVaultError::None) {
		return {};
	}
	auto result = QByteArray();
	AppendUint32(result, kMagic);
	AppendUint32(result, vault.version);
	result.append(vault.id);
	AppendBytes(result, vault.salt);
	AppendUint32(result, vault.kdf.kind);
	AppendUint32(result, vault.kdf.memory);
	AppendUint32(result, vault.kdf.time);
	AppendUint32(result, vault.kdf.parallel);
	result.append(vault.adminVerifier);
	result.append(vault.adminNonce);
	AppendBytes(result, vault.adminCiphertext);
	if (result.size() > kMaximumVaultSize) {
		SetError(error, ProfileVaultError::TooLarge);
		return {};
	}
	AppendUint32(result, quint32(vault.grants.size()));
	for (const auto &grant : vault.grants) {
		AppendUint64(result, grant.id.high);
		AppendUint64(result, grant.id.low);
		result.append(grant.verifier);
		result.append(grant.nonce);
		AppendBytes(result, grant.ciphertext);
		if (result.size() > kMaximumVaultSize) {
			SetError(error, ProfileVaultError::TooLarge);
			return {};
		}
	}
	SetError(error, ProfileVaultError::None);
	return result;
}

std::optional<ProfileVault> ParseProfileVault(
		const QByteArray &serialized,
		ProfileVaultError *error) {
	SetError(error, ProfileVaultError::Malformed);
	if (serialized.size() < 8 + kProfileVaultIdSize + 4 + 16 + 32 + 12 + 4 + 16 + 4
		|| serialized.size() > kMaximumVaultSize) {
		SetError(error, ProfileVaultError::TooLarge);
		return std::nullopt;
	}
	const auto data = serialized.constData();
	if (ReadUint32(data) != kMagic) {
		return std::nullopt;
	}
	auto vault = ProfileVault();
	vault.version = ReadUint32(data + 4);
	if (vault.version != kProfileVaultVersion
		&& vault.version != kLegacyProfileVaultVersion) {
		SetError(error, ProfileVaultError::UnsupportedVersion);
		return std::nullopt;
	}
	auto offset = qsizetype(8);
	vault.id = serialized.mid(offset, kProfileVaultIdSize);
	offset += kProfileVaultIdSize;
	if (!TakeBytes(serialized, &offset, 64, &vault.salt)
		|| serialized.size() - offset < 4 * 4 + kVerifierSize + kNonceSize + 4) {
		return std::nullopt;
	}
	vault.kdf = {
		.kind = ReadUint32(data + offset),
		.memory = ReadUint32(data + offset + 4),
		.time = ReadUint32(data + offset + 8),
		.parallel = ReadUint32(data + offset + 12),
	};
	offset += 16;
	vault.adminVerifier = serialized.mid(offset, kVerifierSize);
	offset += kVerifierSize;
	vault.adminNonce = serialized.mid(offset, kNonceSize);
	offset += kNonceSize;
	if (!TakeBytes(serialized, &offset, kMaximumVaultSize, &vault.adminCiphertext)
		|| serialized.size() - offset < 4) {
		return std::nullopt;
	}
	const auto count = ReadUint32(data + offset);
	offset += 4;
	if (count > kMaximumGrantCount
		|| count > quint32((serialized.size() - offset)
			/ kMinimumSerializedGrantSize)) {
		SetError(error, ProfileVaultError::TooLarge);
		return std::nullopt;
	}
	vault.grants.reserve(count);
	for (auto i = quint32(0); i != count; ++i) {
		if (serialized.size() - offset < 16 + kVerifierSize + kNonceSize + 4) {
			return std::nullopt;
		}
		auto grant = SealedSetGrant();
		grant.id = {
			.high = ReadUint64(data + offset),
			.low = ReadUint64(data + offset + 8),
		};
		offset += 16;
		grant.verifier = serialized.mid(offset, kVerifierSize);
		offset += kVerifierSize;
		grant.nonce = serialized.mid(offset, kNonceSize);
		offset += kNonceSize;
		if (!TakeBytes(
				serialized,
				&offset,
				kMaximumVaultSize,
				&grant.ciphertext)) {
			return std::nullopt;
		}
		vault.grants.push_back(std::move(grant));
	}
	if (offset != serialized.size()) {
		return std::nullopt;
	}
	const auto validation = ValidateVault(vault);
	if (validation != ProfileVaultError::None) {
		SetError(error, validation);
		return std::nullopt;
	}
	SetError(error, ProfileVaultError::None);
	return vault;
}

} // namespace Ayu::ProfileSets
