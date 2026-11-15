// This is the source code of AyuGram for Desktop.
#include "ayu/data/archive_snapshot_vault.h"

#include "ayu/data/entities.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <ranges>

namespace Ayu::ArchiveSnapshotVault {
namespace {

constexpr auto kMagic = "AYUSNP01";
constexpr auto kHeaderSize = 8 + 4 + 16 + 8 + 12;
constexpr auto kTagSize = 16;
constexpr auto kMaxArtifactSize = 64 * 1024 * 1024;
constexpr auto kMaxRows = 100000;
constexpr auto kMaxTextBytes = 1024 * 1024;
constexpr auto kFormat = "sleepygram-text-archive";
constexpr auto kVersion = 1;

struct ClearOnExit final {
	QByteArray &value;
	~ClearOnExit() {
		if (!value.isEmpty()) {
			OPENSSL_cleanse(value.data(), size_t(value.size()));
		}
	}
};

void SetError(Error *error, Error value) {
	if (error) *error = value;
}

void Put32(char *out, quint32 value) {
	for (auto i = 0; i != 4; ++i) {
		out[i] = char(value >> ((3 - i) * 8));
	}
}

void Put64(char *out, quint64 value) {
	for (auto i = 0; i != 8; ++i) {
		out[i] = char(value >> ((7 - i) * 8));
	}
}

quint32 Get32(const char *in) {
	auto result = quint32(0);
	for (auto i = 0; i != 4; ++i) {
		result = (result << 8) | quint8(in[i]);
	}
	return result;
}

quint64 Get64(const char *in) {
	auto result = quint64(0);
	for (auto i = 0; i != 8; ++i) {
		result = (result << 8) | quint8(in[i]);
	}
	return result;
}

bool ValidKey(const ProfileSets::AccountKey &accountKey) {
	if (!accountKey.id || accountKey.key.size() != ProfileSets::kAccountKeySize) {
		return false;
	}
	auto nonzero = uint8_t(0);
	for (const auto byte : accountKey.key) {
		nonzero |= uint8_t(byte);
	}
	return nonzero != 0;
}

QByteArray DeriveKey(
		const ProfileSets::AccountKey &accountKey,
		ID archiveAccountId) {
	constexpr auto kContext = "SleepyGram archive snapshot encryption key v1";
	auto info = QByteArray(kContext, int(sizeof(kContext) - 1));
	auto accountIds = QByteArray(24, Qt::Uninitialized);
	Put64(accountIds.data(), accountKey.id.high);
	Put64(accountIds.data() + 8, accountKey.id.low);
	Put64(accountIds.data() + 16, quint64(archiveAccountId));
	info.append(accountIds);
	auto result = QByteArray(32, Qt::Uninitialized);
	auto size = 0u;
	if (!HMAC(
			EVP_sha256(),
			reinterpret_cast<const unsigned char*>(accountKey.key.constData()),
			accountKey.key.size(),
		reinterpret_cast<const unsigned char*>(info.constData()),
		size_t(info.size()),
		reinterpret_cast<unsigned char*>(result.data()),
		&size)
		|| size != size_t(result.size())) {
		OPENSSL_cleanse(info.data(), size_t(info.size()));
		OPENSSL_cleanse(result.data(), size_t(result.size()));
		return {};
	}
	OPENSSL_cleanse(info.data(), size_t(info.size()));
	return result;
}

QJsonObject Encode(const AyuMessageBase &row) {
	return {
		{ "dialog", QString::number(row.dialogId) },
		{ "peer", QString::number(row.peerId) },
		{ "peerType", row.peerType },
		{ "sender", QString::number(row.fromId) },
		{ "topic", QString::number(row.topicId) },
		{ "message", row.messageId },
		{ "date", row.date },
		{ "editDate", row.editDate },
		{ "flags", row.flags },
		{ "text", QString::fromUtf8(row.text.data(), int(row.text.size())) },
	};
}

bool ReadId(const QJsonValue &value, ID *result) {
	if (!value.isString()) return false;
	const auto bytes = value.toString().toLatin1();
	if (bytes.isEmpty()) return false;
	auto ok = false;
	const auto parsed = bytes.toLongLong(&ok);
	if (!ok) return false;
	*result = parsed;
	return true;
}

bool ReadInt(const QJsonValue &value, int *result) {
	if (!value.isDouble()) return false;
	const auto number = value.toDouble();
	if (number < std::numeric_limits<int>::min()
		|| number > std::numeric_limits<int>::max()
		|| number != double(int(number))) {
		return false;
	}
	*result = int(number);
	return true;
}

bool Decode(const QJsonValue &value, ID accountId, AyuMessageBase *row) {
	if (!value.isObject()) return false;
	const auto object = value.toObject();
	if (object.size() != 10) return false;
	row->userId = accountId;
	if (!ReadId(object.value("dialog"), &row->dialogId)
		|| !ReadId(object.value("peer"), &row->peerId)
		|| !ReadId(object.value("sender"), &row->fromId)
		|| !ReadId(object.value("topic"), &row->topicId)
		|| !ReadInt(object.value("peerType"), &row->peerType)
		|| !ReadInt(object.value("message"), &row->messageId)
		|| !ReadInt(object.value("date"), &row->date)
		|| !ReadInt(object.value("editDate"), &row->editDate)
		|| !ReadInt(object.value("flags"), &row->flags)
		|| row->peerType < 0 || row->peerType > 3
		|| !object.value("text").isString()) {
		return false;
	}
	const auto text = object.value("text").toString().toUtf8();
	if (text.size() > kMaxTextBytes) return false;
	row->text.assign(text.constData(), size_t(text.size()));
	return true;
}

QByteArray Serialize(
		ID accountId,
		const AyuDatabase::ArchiveBackupSnapshot &snapshot) {
	// Keep the password and account-key formats on the same archive record
	// schema so either staging path can reuse the existing import validator.
	auto edited = QJsonArray();
	for (const auto &row : snapshot.edited) edited.push_back(Encode(row));
	auto deleted = QJsonArray();
	for (const auto &row : snapshot.deleted) deleted.push_back(Encode(row));
	return QJsonDocument(QJsonObject{
		{ "format", kFormat },
		{ "version", kVersion },
		{ "account", QString::number(accountId) },
		{ "edited", edited },
		{ "deleted", deleted },
	}).toJson(QJsonDocument::Compact);
}

std::optional<AyuDatabase::ArchiveBackupSnapshot> Parse(
		const QByteArray &plaintext,
		ID accountId) {
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(plaintext, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		return std::nullopt;
	}
	const auto root = document.object();
	if (root.size() != 5
		|| root.value("format").toString() != QString::fromLatin1(kFormat)
		|| root.value("version").toDouble() != double(kVersion)
		|| root.value("account").toString() != QString::number(accountId)
		|| !root.value("edited").isArray()
		|| !root.value("deleted").isArray()) {
		return std::nullopt;
	}
	const auto edited = root.value("edited").toArray();
	const auto deleted = root.value("deleted").toArray();
	if (edited.size() + deleted.size() > kMaxRows) return std::nullopt;
	auto result = AyuDatabase::ArchiveBackupSnapshot();
	for (const auto &value : edited) {
		auto row = EditedMessage();
		if (!Decode(value, accountId, &row)) return std::nullopt;
		result.edited.push_back(std::move(row));
	}
	for (const auto &value : deleted) {
		auto row = DeletedMessage();
		if (!Decode(value, accountId, &row)) return std::nullopt;
		result.deleted.push_back(std::move(row));
	}
	return result;
}

QByteArray Crypt(
		bool encrypt,
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &header,
		const QByteArray &input) {
	if (!encrypt && input.size() < kTagSize) return {};
	const auto textSize = encrypt ? input.size() : input.size() - kTagSize;
	auto output = QByteArray(textSize + (encrypt ? kTagSize : 0), Qt::Uninitialized);
	auto context = EVP_CIPHER_CTX_new();
	if (!context) return {};
	auto outLength = 0;
	auto total = 0;
	auto ok = encrypt
		? EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
		: EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	ok = ok == 1
		&& EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1;
	if (ok) {
		ok = encrypt
			? EVP_EncryptInit_ex(context, nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(key.constData()),
				reinterpret_cast<const unsigned char*>(nonce.constData()))
			: EVP_DecryptInit_ex(context, nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(key.constData()),
				reinterpret_cast<const unsigned char*>(nonce.constData()));
	}
	if (ok == 1) {
		ok = encrypt
			? EVP_EncryptUpdate(context, nullptr, &outLength,
				reinterpret_cast<const unsigned char*>(header.constData()), header.size())
			: EVP_DecryptUpdate(context, nullptr, &outLength,
				reinterpret_cast<const unsigned char*>(header.constData()), header.size());
	}
	if (ok == 1 && textSize) {
		ok = encrypt
			? EVP_EncryptUpdate(context,
				reinterpret_cast<unsigned char*>(output.data()), &outLength,
				reinterpret_cast<const unsigned char*>(input.constData()), textSize)
			: EVP_DecryptUpdate(context,
				reinterpret_cast<unsigned char*>(output.data()), &outLength,
				reinterpret_cast<const unsigned char*>(input.constData()), textSize);
		total = outLength;
	}
	if (!encrypt && ok == 1) {
		auto tag = input.mid(textSize, kTagSize);
		ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, kTagSize,
			reinterpret_cast<unsigned char*>(tag.data()));
	}
	if (ok == 1) {
		ok = encrypt
			? EVP_EncryptFinal_ex(context,
				reinterpret_cast<unsigned char*>(output.data()) + total, &outLength)
			: EVP_DecryptFinal_ex(context,
				reinterpret_cast<unsigned char*>(output.data()) + total, &outLength);
	}
	total += outLength;
	if (encrypt && ok == 1) {
		ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, kTagSize,
			reinterpret_cast<unsigned char*>(output.data()) + textSize);
	}
	EVP_CIPHER_CTX_free(context);
	if (ok != 1 || total != textSize) {
		if (!output.isEmpty()) OPENSSL_cleanse(output.data(), size_t(output.size()));
		return {};
	}
	return output;
}

} // namespace

QByteArray Seal(
		const ProfileSets::AccountKey &accountKey,
		ID archiveAccountId,
		const AyuDatabase::ArchiveBackupSnapshot &snapshot,
		Error *error) {
	SetError(error, Error::InvalidAccountKey);
	if (!ValidKey(accountKey)) return {};
	SetError(error, Error::InvalidArchiveAccount);
	if (archiveAccountId <= 0) return {};
	SetError(error, Error::OutsideAccountScope);
	if (snapshot.edited.size() + snapshot.deleted.size() > kMaxRows
		|| std::ranges::any_of(snapshot.edited, [&](const auto &row) {
			return row.text.size() > kMaxTextBytes;
		})
		|| std::ranges::any_of(snapshot.deleted, [&](const auto &row) {
			return row.text.size() > kMaxTextBytes;
		})) {
		SetError(error, Error::TooLarge);
		return {};
	}
	if (std::ranges::any_of(snapshot.edited, [&](const auto &row) {
			return row.userId != archiveAccountId;
		})
		|| std::ranges::any_of(snapshot.deleted, [&](const auto &row) {
			return row.userId != archiveAccountId;
		})) {
		return {};
	}
	auto plain = Serialize(archiveAccountId, snapshot);
	if (plain.isEmpty() || plain.size() > kMaxArtifactSize - kHeaderSize - kTagSize) {
		OPENSSL_cleanse(plain.data(), size_t(plain.size()));
		SetError(error, Error::TooLarge);
		return {};
	}
	auto header = QByteArray(kHeaderSize, Qt::Uninitialized);
	auto cursor = header.data();
	memcpy(cursor, kMagic, 8); cursor += 8;
	Put32(cursor, 1); cursor += 4;
	Put64(cursor, accountKey.id.high); cursor += 8;
	Put64(cursor, accountKey.id.low); cursor += 8;
	Put64(cursor, quint64(archiveAccountId)); cursor += 8;
	if (RAND_bytes(reinterpret_cast<unsigned char*>(cursor), 12) != 1) {
		OPENSSL_cleanse(plain.data(), size_t(plain.size()));
		SetError(error, Error::RandomFailure);
		return {};
	}
	const auto nonce = QByteArray(cursor, 12);
	auto key = DeriveKey(accountKey, archiveAccountId);
	if (key.isEmpty()) {
		OPENSSL_cleanse(plain.data(), size_t(plain.size()));
		SetError(error, Error::RandomFailure);
		return {};
	}
	auto sealed = Crypt(true, key, nonce, header, plain);
	OPENSSL_cleanse(key.data(), size_t(key.size()));
	OPENSSL_cleanse(plain.data(), size_t(plain.size()));
	if (sealed.isEmpty()) {
		SetError(error, Error::RandomFailure);
		return {};
	}
	SetError(error, Error::None);
	return header + sealed;
}

std::optional<AyuDatabase::ArchiveBackupSnapshot> Open(
		const ProfileSets::AccountKey &accountKey,
		ID expectedArchiveAccountId,
		const QByteArray &artifact,
		Error *error) {
	SetError(error, Error::InvalidAccountKey);
	if (!ValidKey(accountKey)) return std::nullopt;
	SetError(error, Error::InvalidArchiveAccount);
	if (expectedArchiveAccountId <= 0) return std::nullopt;
	SetError(error, Error::Malformed);
	if (artifact.size() < kHeaderSize + kTagSize
		|| artifact.size() > kMaxArtifactSize
		|| memcmp(artifact.constData(), kMagic, 8) != 0
		|| Get32(artifact.constData() + 8) != 1) {
		return std::nullopt;
	}
	const auto *header = artifact.constData();
	const auto accountHigh = Get64(header + 12);
	const auto accountLow = Get64(header + 20);
	const auto archiveAccountId = Get64(header + 28);
	if (accountHigh != accountKey.id.high || accountLow != accountKey.id.low
		|| archiveAccountId != quint64(expectedArchiveAccountId)) {
		SetError(error, Error::WrongAccount);
		return std::nullopt;
	}
	const auto nonce = QByteArray(header + 36, 12);
	auto key = DeriveKey(accountKey, expectedArchiveAccountId);
	if (key.isEmpty()) {
		SetError(error, Error::RandomFailure);
		return std::nullopt;
	}
	auto plain = Crypt(false, key, nonce, artifact.left(kHeaderSize),
		artifact.mid(kHeaderSize));
	OPENSSL_cleanse(key.data(), size_t(key.size()));
	if (plain.isEmpty()) {
		SetError(error, Error::AuthenticationFailed);
		return std::nullopt;
	}
	const auto cleanPlain = ClearOnExit{ plain };
	const auto snapshot = Parse(plain, expectedArchiveAccountId);
	if (!snapshot) {
		SetError(error, Error::Malformed);
		return std::nullopt;
	}
	SetError(error, Error::None);
	return snapshot;
}

} // namespace Ayu::ArchiveSnapshotVault
