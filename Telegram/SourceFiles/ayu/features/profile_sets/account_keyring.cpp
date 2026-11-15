/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/account_keyring.h"

#include "base/openssl_help.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QtCore/QByteArray>

#include <algorithm>
#include <set>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kMagic = quint32(0x5347414B);
constexpr auto kNonceSize = 12;
constexpr auto kTagSize = 16;
constexpr auto kHeaderSize = 4 + 4 + kNonceSize + 4;
constexpr auto kRecordSize = 16 + kAccountKeySize;
constexpr auto kMaximumAccountCount = quint32(65'536);
constexpr auto kMaximumPayloadSize = int(4 + kRecordSize * kMaximumAccountCount);

bool AllZero(const QByteArray &bytes) {
	return std::all_of(bytes.cbegin(), bytes.cend(), [](char value) {
		return value == 0;
	});
}

void SetError(KeyringError *error, KeyringError value) {
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

QByteArray Serialize(const std::vector<AccountKey> &accounts) {
	auto result = QByteArray();
	result.reserve(4 + int(accounts.size()) * kRecordSize);
	AppendUint32(result, quint32(accounts.size()));
	for (const auto &account : accounts) {
		AppendUint64(result, account.id.high);
		AppendUint64(result, account.id.low);
		result.append(account.key);
	}
	return result;
}

void CleanseKeys(std::vector<AccountKey> &accounts) {
	for (auto &account : accounts) {
		if (!account.key.isEmpty()) {
			OPENSSL_cleanse(account.key.data(), account.key.size());
		}
	}
}

QByteArray Seal(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &aad,
		const QByteArray &plaintext) {
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
			context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1)
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
			aad.size()) == 1);
	if (ok && !plaintext.isEmpty()) {
		ok = EVP_EncryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data()),
			&outLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()),
			plaintext.size()) == 1;
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

QByteArray Open(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &aad,
		const QByteArray &ciphertext) {
	if (ciphertext.size() < kTagSize) {
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
			context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1)
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
			aad.size()) == 1);
	if (ok && length) {
		ok = EVP_DecryptUpdate(
			context,
			reinterpret_cast<unsigned char*>(result.data()),
			&outLength,
			reinterpret_cast<const unsigned char*>(ciphertext.constData()),
			length) == 1;
		total = outLength;
	}
	auto tag = ciphertext.mid(length, kTagSize);
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

} // namespace

std::optional<AccountKey> NewAccountKey(
		AccountId id,
		KeyringError *error) {
	SetError(error, KeyringError::InvalidAccountId);
	if (!id) {
		return std::nullopt;
	}
	auto key = QByteArray(kAccountKeySize, Qt::Uninitialized);
	if (RAND_bytes(
		reinterpret_cast<unsigned char*>(key.data()),
		key.size()) != 1) {
		OPENSSL_cleanse(key.data(), key.size());
		SetError(error, KeyringError::RandomFailure);
		return std::nullopt;
	}
	SetError(error, KeyringError::None);
	return AccountKey{ id, std::move(key) };
}

KeyringError ValidateAccountKeys(const std::vector<AccountKey> &accounts) {
	if (accounts.size() > kMaximumAccountCount) {
		return KeyringError::TooManyAccounts;
	}
	auto ids = std::set<AccountId>();
	auto keys = std::set<QByteArray>();
	for (const auto &account : accounts) {
		if (!account.id) {
			return KeyringError::InvalidAccountId;
		} else if (!ids.insert(account.id).second) {
			return KeyringError::DuplicateAccountId;
		} else if (account.key.size() != kAccountKeySize) {
			return KeyringError::InvalidAccountKey;
		} else if (AllZero(account.key)) {
			return KeyringError::InvalidAccountKey;
		} else if (!keys.insert(account.key).second) {
			return KeyringError::DuplicateAccountKey;
		}
	}
	return KeyringError::None;
}

QByteArray SealAccountKeyring(
		const std::vector<AccountKey> &accounts,
		const QByteArray &wrappingKey,
		KeyringError *error) {
	SetError(error, KeyringError::Malformed);
	if (wrappingKey.size() != kAccountKeyringWrappingKeySize
		|| AllZero(wrappingKey)) {
		SetError(error, KeyringError::InvalidWrappingKey);
		return {};
	}
	const auto validation = ValidateAccountKeys(accounts);
	if (validation != KeyringError::None) {
		SetError(error, validation);
		return {};
	}
	auto plaintext = Serialize(accounts);
	if (plaintext.size() > kMaximumPayloadSize) {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
		SetError(error, KeyringError::TooManyAccounts);
		return {};
	}
	auto nonce = QByteArray(kNonceSize, Qt::Uninitialized);
	if (RAND_bytes(
		reinterpret_cast<unsigned char*>(nonce.data()),
		nonce.size()) != 1) {
		OPENSSL_cleanse(nonce.data(), nonce.size());
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
		SetError(error, KeyringError::RandomFailure);
		return {};
	}
	auto header = QByteArray();
	header.reserve(kHeaderSize);
	AppendUint32(header, kMagic);
	AppendUint32(header, kAccountKeyringVersion);
	header.append(nonce);
	AppendUint32(header, quint32(plaintext.size() + kTagSize));
	const auto ciphertext = Seal(wrappingKey, nonce, header, plaintext);
	OPENSSL_cleanse(plaintext.data(), plaintext.size());
	if (ciphertext.isEmpty()) {
		return {};
	}
	SetError(error, KeyringError::None);
	return header + ciphertext;
}

std::optional<std::vector<AccountKey>> OpenAccountKeyring(
		const QByteArray &sealed,
		const QByteArray &wrappingKey,
		KeyringError *error) {
	SetError(error, KeyringError::Malformed);
	if (wrappingKey.size() != kAccountKeyringWrappingKeySize
		|| AllZero(wrappingKey)) {
		SetError(error, KeyringError::InvalidWrappingKey);
		return std::nullopt;
	}
	if (sealed.size() < kHeaderSize + kTagSize + 4
		|| sealed.size() > kHeaderSize + kMaximumPayloadSize + kTagSize) {
		return std::nullopt;
	}
	const auto data = sealed.constData();
	if (ReadUint32(data) != kMagic) {
		return std::nullopt;
	} else if (ReadUint32(data + 4) != kAccountKeyringVersion) {
		SetError(error, KeyringError::UnsupportedVersion);
		return std::nullopt;
	}
	const auto nonce = sealed.mid(8, kNonceSize);
	const auto declaredSize = ReadUint32(data + 8 + kNonceSize);
	if (declaredSize != quint32(sealed.size() - kHeaderSize)
		|| declaredSize < kTagSize + 4) {
		return std::nullopt;
	}
	const auto header = sealed.first(kHeaderSize);
	const auto ciphertext = sealed.mid(kHeaderSize);
	auto plaintext = Open(wrappingKey, nonce, header, ciphertext);
	if (plaintext.isEmpty()) {
		SetError(error, KeyringError::AuthenticationFailed);
		return std::nullopt;
	}
	const auto cleanse = gsl::finally([&] {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
	});
	const auto count = ReadUint32(plaintext.constData());
	if (count > kMaximumAccountCount
		|| plaintext.size() != 4 + int(count) * kRecordSize) {
		return std::nullopt;
	}
	auto accounts = std::vector<AccountKey>();
	accounts.reserve(count);
	auto offset = 4;
	for (auto i = quint32(0); i != count; ++i) {
		auto key = QByteArray(kAccountKeySize, Qt::Uninitialized);
		const auto record = plaintext.constData() + offset;
		const auto id = AccountId{
			.high = ReadUint64(record),
			.low = ReadUint64(record + 8),
		};
		std::copy_n(record + 16, kAccountKeySize, key.data());
		accounts.push_back({ id, std::move(key) });
		offset += kRecordSize;
	}
	const auto validation = ValidateAccountKeys(accounts);
	if (validation != KeyringError::None) {
		CleanseKeys(accounts);
		SetError(error, validation);
		return std::nullopt;
	}
	SetError(error, KeyringError::None);
	return accounts;
}

} // namespace Ayu::ProfileSets
