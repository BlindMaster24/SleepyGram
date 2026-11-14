// This is the source code of AyuGram for Desktop.
#include "ayu/data/archive_backup.h"

#include "ayu/data/entities.h"
#include "base/random.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <limits>
#include <cstring>

namespace AyuArchiveBackup {
namespace {

struct ClearOnExit {
	QByteArray &value;
	~ClearOnExit() {
		if (!value.isEmpty()) OPENSSL_cleanse(value.data(), size_t(value.size()));
	}
};

constexpr auto kMagic = "AYUARC01";
constexpr auto kHeaderSize = 8 + 4 + 8 + 4 + 16 + 12;
constexpr auto kTagSize = 16;
constexpr auto kKdfIterations = 310000;
constexpr auto kMaxFileSize = 64 * 1024 * 1024;
constexpr auto kMaxRows = 100000;
constexpr auto kMaxTextBytes = 1024 * 1024;

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
	bool ok = false;
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

QByteArray Plaintext(ID accountId, const AyuDatabase::ArchiveBackupSnapshot &data) {
	QJsonArray edited;
	for (const auto &row : data.edited) edited.push_back(Encode(row));
	QJsonArray deleted;
	for (const auto &row : data.deleted) deleted.push_back(Encode(row));
	return QJsonDocument(QJsonObject{
		{ "format", "sleepygram-text-archive" },
		{ "version", 1 },
		{ "account", QString::number(accountId) },
		{ "edited", edited },
		{ "deleted", deleted },
	}).toJson(QJsonDocument::Compact);
}

QByteArray DeriveKey(const QString &password, const QByteArray &salt) {
	auto passwordBytes = password.toUtf8();
	auto key = QByteArray(32, Qt::Uninitialized);
	const auto ok = PKCS5_PBKDF2_HMAC(
		passwordBytes.constData(), passwordBytes.size(),
		reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
		kKdfIterations, EVP_sha256(), key.size(),
		reinterpret_cast<unsigned char*>(key.data())) == 1;
	OPENSSL_cleanse(passwordBytes.data(), size_t(passwordBytes.size()));
	if (!ok) {
		OPENSSL_cleanse(key.data(), size_t(key.size()));
		return {};
	}
	return key;
}

QByteArray Seal(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &header,
		const QByteArray &plaintext) {
	auto cipher = QByteArray(plaintext.size() + kTagSize, Qt::Uninitialized);
	auto context = EVP_CIPHER_CTX_new();
	if (!context) return {};
	auto outLength = 0;
	auto total = 0;
	auto ok = EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1
		&& EVP_EncryptInit_ex(context, nullptr, nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) == 1;
	if (ok) ok = EVP_EncryptUpdate(context, nullptr, &outLength,
		reinterpret_cast<const unsigned char*>(header.constData()), header.size()) == 1;
	if (ok && !plaintext.isEmpty()) {
		ok = EVP_EncryptUpdate(context,
			reinterpret_cast<unsigned char*>(cipher.data()), &outLength,
			reinterpret_cast<const unsigned char*>(plaintext.constData()), plaintext.size()) == 1;
		total = outLength;
	}
	if (ok) ok = EVP_EncryptFinal_ex(context,
		reinterpret_cast<unsigned char*>(cipher.data()) + total, &outLength) == 1;
	total += outLength;
	if (ok) ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, kTagSize,
		reinterpret_cast<unsigned char*>(cipher.data()) + plaintext.size()) == 1;
	EVP_CIPHER_CTX_free(context);
	if (!ok || total != plaintext.size()) return {};
	return cipher;
}

QByteArray Open(
		const QByteArray &key,
		const QByteArray &nonce,
		const QByteArray &header,
		const QByteArray &ciphertext) {
	if (ciphertext.size() < kTagSize) return {};
	const auto length = ciphertext.size() - kTagSize;
	auto plain = QByteArray(length, Qt::Uninitialized);
	auto context = EVP_CIPHER_CTX_new();
	if (!context) return {};
	auto outLength = 0;
	auto total = 0;
	auto ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1
		&& EVP_DecryptInit_ex(context, nullptr, nullptr,
			reinterpret_cast<const unsigned char*>(key.constData()),
			reinterpret_cast<const unsigned char*>(nonce.constData())) == 1;
	if (ok) ok = EVP_DecryptUpdate(context, nullptr, &outLength,
		reinterpret_cast<const unsigned char*>(header.constData()), header.size()) == 1;
	if (ok && length) {
		ok = EVP_DecryptUpdate(context,
			reinterpret_cast<unsigned char*>(plain.data()), &outLength,
			reinterpret_cast<const unsigned char*>(ciphertext.constData()), length) == 1;
		total = outLength;
	}
	if (ok) ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, kTagSize,
		reinterpret_cast<const unsigned char*>(ciphertext.constData()) + length) == 1;
	if (ok) ok = EVP_DecryptFinal_ex(context,
		reinterpret_cast<unsigned char*>(plain.data()) + total, &outLength) == 1;
	total += outLength;
	EVP_CIPHER_CTX_free(context);
	if (!ok || total != length) return {};
	return plain;
}

} // namespace

QByteArray Create(ID accountId, const QString &password) {
	if (accountId <= 0 || password.toUtf8().size() < 8
		|| password.toUtf8().size() > 1024) return {};
	const auto counts = AyuDatabase::archiveBackupCounts(accountId);
	if (counts.edited + counts.deleted > kMaxRows) return {};
	const auto snapshot = AyuDatabase::archiveBackupSnapshot(accountId, kMaxRows);
	if (!snapshot) return {};
	for (const auto &row : snapshot->edited) {
		if (row.text.size() > kMaxTextBytes) return {};
	}
	for (const auto &row : snapshot->deleted) {
		if (row.text.size() > kMaxTextBytes) return {};
	}
	const auto plain = Plaintext(accountId, *snapshot);
	if (plain.isEmpty() || plain.size() > kMaxFileSize - kHeaderSize - kTagSize) return {};
	auto header = QByteArray(kHeaderSize, Qt::Uninitialized);
	auto cursor = header.data();
	memcpy(cursor, kMagic, 8); cursor += 8;
	Put32(cursor, 1); cursor += 4;
	Put64(cursor, quint64(accountId)); cursor += 8;
	Put32(cursor, kKdfIterations); cursor += 4;
	base::RandomFill(cursor, 16); const auto salt = QByteArray(cursor, 16); cursor += 16;
	base::RandomFill(cursor, 12); const auto nonce = QByteArray(cursor, 12);
	auto key = DeriveKey(password, salt);
	if (key.isEmpty()) return {};
	auto sealed = Seal(key, nonce, header, plain);
	OPENSSL_cleanse(key.data(), size_t(key.size()));
	return sealed.isEmpty() ? QByteArray() : header + sealed;
}

std::optional<Preview> Read(QByteArray bytes, ID expectedAccountId, const QString &password) {
	if (bytes.size() < kHeaderSize + kTagSize || bytes.size() > kMaxFileSize
		|| password.toUtf8().size() < 8 || password.toUtf8().size() > 1024
		|| memcmp(bytes.constData(), kMagic, 8) != 0) return std::nullopt;
	const auto *header = bytes.constData();
	if (Get32(header + 8) != 1
		|| Get64(header + 12) != quint64(expectedAccountId)
		|| Get32(header + 20) != kKdfIterations) return std::nullopt;
	const auto salt = QByteArray(header + 24, 16);
	const auto nonce = QByteArray(header + 40, 12);
	auto key = DeriveKey(password, salt);
	if (key.isEmpty()) return std::nullopt;
	const auto encrypted = bytes.mid(kHeaderSize);
	auto plain = Open(key, nonce, bytes.left(kHeaderSize), encrypted);
	const auto clearPlain = ClearOnExit{ plain };
	OPENSSL_cleanse(key.data(), size_t(key.size()));
	if (plain.isEmpty()) return std::nullopt;
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(plain, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) return std::nullopt;
	const auto root = document.object();
	if (root.size() != 5 || root.value("format").toString() != QStringLiteral("sleepygram-text-archive")
		|| root.value("version").toDouble() != 1.0
		|| root.value("account").toString() != QString::number(expectedAccountId)
		|| !root.value("edited").isArray() || !root.value("deleted").isArray()) return std::nullopt;
	const auto edited = root.value("edited").toArray();
	const auto deleted = root.value("deleted").toArray();
	if (edited.size() + deleted.size() > kMaxRows) return std::nullopt;
	Preview result;
	for (const auto &value : edited) {
		auto row = EditedMessage{};
		if (!Decode(value, expectedAccountId, &row)) return std::nullopt;
		result.snapshot.edited.push_back(std::move(row));
	}
	for (const auto &value : deleted) {
		auto row = DeletedMessage{};
		if (!Decode(value, expectedAccountId, &row)) return std::nullopt;
		result.snapshot.deleted.push_back(std::move(row));
	}
	QString sample;
	if (!result.snapshot.edited.empty()) sample = QString::fromStdString(result.snapshot.edited.front().text).simplified();
	else if (!result.snapshot.deleted.empty()) sample = QString::fromStdString(result.snapshot.deleted.front().text).simplified();
	if (sample.size() > 160) sample = sample.left(160) + u"…"_q;
	result.summary = QString("%1 edited, %2 deleted\n%3")
		.arg(edited.size()).arg(deleted.size()).arg(sample);
	return result;
}

AyuDatabase::ArchiveImportCounts Import(ID accountId, const Preview &preview) {
	return AyuDatabase::importArchiveSnapshot(accountId, preview.snapshot);
}

} // namespace AyuArchiveBackup
