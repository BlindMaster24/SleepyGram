// This is the source code of AyuGram for Desktop.
#include "ayu/features/offline_history/offline_history_scoped.h"

#include "mtproto/mtproto_auth_key.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMessageAuthenticationCode>
#include <QtCore/QSaveFile>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>

#if !defined Q_OS_WIN
#include <fcntl.h>
#include <unistd.h>
#endif

namespace Ayu::OfflineHistory {
namespace {

using Kind = LegacyOfflinePathKind;
using details::Decimal;
using details::KnownPeer;
using details::LegacyAttachmentName;
static_assert(PeerId::kChatTypeMask == details::kLegacyAccountMask);
constexpr auto kMagic = "SGOH\x01";
constexpr auto kMagicBytes = 5;
constexpr auto kNonceBytes = 12;
constexpr auto kTagBytes = 16;
constexpr auto kEnvelopeBytes = kMagicBytes + kNonceBytes + kTagBytes;
constexpr auto kMaxSnapshot = 64 * 1024 * 1024;
constexpr auto kMaxManifest = 8 * 1024 * 1024;
constexpr auto kMaxAttachment = 25 * 1024 * 1024;
constexpr auto kMaxEntries = 60'000;
constexpr auto kQuota = qint64(1024) * 1024 * 1024;
constexpr auto kEntries = QDir::AllEntries | QDir::NoDotAndDotDot
	| QDir::Hidden | QDir::System;

const auto kRoot = u"offline-history"_q;

struct Record final {
	const ScopedOfflineAccount *scope = nullptr;
	QString from;
	QString to;
	QByteArray sha256;
	int limit = 0;
	qint64 bytes = 0;
};

bool Present(const QFileInfo &info) {
	return info.exists() || info.isSymLink() || info.isJunction();
}

bool CanonicalDirectory(const QFileInfo &info) {
	return info.isDir() && !info.isSymLink() && !info.isJunction()
		&& info.canonicalFilePath() == info.absoluteFilePath()
		&& QDir(info.absoluteFilePath()).isReadable();
}

bool CanonicalFile(const QFileInfo &info) {
	auto error = std::error_code();
	return info.isFile() && !info.isSymLink() && !info.isJunction()
		&& info.canonicalFilePath() == info.absoluteFilePath()
		&& std::filesystem::hard_link_count(info.filesystemFilePath(), error) == 1
		&& !error;
}

bool SyncDirectory(const QString &path) {
	if (!CanonicalDirectory(QFileInfo(path))) {
		return false;
	}
#if defined Q_OS_WIN
	return true;
#else
	const auto native = QFile::encodeName(path);
	const auto fd = open(native.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	const auto synced = fsync(fd) == 0;
	close(fd);
	return synced;
#endif
}

bool LowerHex(QStringView text, qsizetype size) {
	return text.size() == size && std::ranges::all_of(text, [](QChar ch) {
		return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
	});
}

bool ValidAccount(const ScopedOfflineAccount &account) {
	const auto info = QFileInfo(account.accountRoot);
	return account.userId && account.userId <= PeerId::kChatTypeMask && account.key
		&& info.absoluteFilePath() == account.accountRoot
		&& LowerHex(info.fileName(), 32)
		&& CanonicalDirectory(info);
}

QByteArray Mac(const ScopedOfflineAccount &account, QByteArray label) {
	const auto material = account.key->data();
	label.append('/');
	label.append(QByteArray::number(account.userId));
	return QMessageAuthenticationCode::hash(
		label,
		QByteArrayView(reinterpret_cast<const char*>(material.data()), material.size()),
		QCryptographicHash::Sha256);
}

QString ScopedRoot(const ScopedOfflineAccount &account) {
	return account.accountRoot + '/' + kRoot;
}

int RecordLimit(QStringView scopedRelative) {
	const auto parts = scopedRelative.split('/');
	if (parts.size() < 2 || !LowerHex(parts.front(), 64)) {
		return 0;
	} else if (parts.size() == 2) {
		return (parts.back() == u"history" || parts.back() == u"partial")
			? kMaxSnapshot
			: (parts.back() == u"manifest") ? kMaxManifest : 0;
	}
	return (parts.size() == 3 && parts[1] == u"attachments" && LowerHex(parts[2], 64))
		? kMaxAttachment
		: 0;
}

std::optional<QString> ScopedRelative(
		const ScopedOfflineAccount &account,
		const QString &path) {
	const auto prefix = ScopedRoot(account) + '/';
	if (!ValidAccount(account) || !path.startsWith(prefix)) {
		return std::nullopt;
	}
	const auto relative = path.mid(prefix.size());
	return RecordLimit(relative) ? std::optional(relative) : std::nullopt;
}

bool ScopedDirectories(
		const ScopedOfflineAccount &account,
		const QString &relative,
		bool create) {
	auto path = account.accountRoot;
	const auto parent = relative.left(relative.lastIndexOf('/'));
	const auto nodes = (kRoot + '/' + parent).split('/');
	for (const auto &node : nodes) {
		path += '/' + node;
		const auto info = QFileInfo(path);
		if (!Present(info)) {
			if (!create || !QDir().mkdir(path)) {
				return false;
			}
		}
		if (!CanonicalDirectory(QFileInfo(path))) {
			return false;
		}
	}
	return true;
}

std::optional<QByteArray> ReadExact(const QString &path, qint64 limit) {
	const auto info = QFileInfo(path);
	auto file = QFile(path);
	if (!CanonicalFile(info) || info.size() <= 0 || info.size() > limit
		|| !file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	auto data = file.read(limit + 1);
	return (data.size() == info.size() && file.atEnd())
		? std::optional(std::move(data))
		: std::nullopt;
}

std::optional<QByteArray> Crypt(
		const ScopedOfflineAccount &account,
		const QString &relative,
		const QByteArray &data,
		bool encrypt) {
	if (!encrypt && (data.size() <= kEnvelopeBytes
		|| !data.startsWith(QByteArrayView(kMagic, kMagicBytes)))) {
		return std::nullopt;
	}
	auto key = Mac(account, QByteArray("SleepyGram offline history encryption v1"));
	const auto wipe = gsl::finally([&] { OPENSSL_cleanse(key.data(), key.size()); });
	auto nonce = encrypt ? QByteArray(kNonceBytes, Qt::Uninitialized)
		: data.mid(kMagicBytes, kNonceBytes);
	const auto aad = QByteArray(kMagic, kMagicBytes)
		+ QByteArray::number(account.userId) + '/' + relative.toUtf8();
	const auto view = encrypt ? QByteArrayView(data) : QByteArrayView(data)
		.sliced(kMagicBytes + kNonceBytes, data.size() - kEnvelopeBytes);
	const auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
		EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	const auto ptr = [](const char *p) { return reinterpret_cast<const unsigned char*>(p); };
	auto tag = encrypt ? QByteArray(kTagBytes, Qt::Uninitialized) : data.last(kTagBytes);
	auto plain = QByteArray(view.size() + EVP_MAX_BLOCK_LENGTH, Qt::Uninitialized);
	auto count = 0;
	auto last = 0;
	const auto ok = context
		&& (!encrypt || RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), kNonceBytes) == 1)
		&& EVP_CipherInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, ptr(key.constData()),
			ptr(nonce.constData()), encrypt ? 1 : 0) == 1
		&& EVP_CipherUpdate(context.get(), nullptr, &count, ptr(aad.constData()), int(aad.size())) == 1
		&& EVP_CipherUpdate(context.get(), reinterpret_cast<unsigned char*>(plain.data()),
			&count, ptr(view.data()), int(view.size())) == 1
		&& (encrypt || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, kTagBytes, tag.data()) == 1)
		&& EVP_CipherFinal_ex(context.get(), reinterpret_cast<unsigned char*>(plain.data()) + count,
			&last) == 1
		&& (!encrypt || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, kTagBytes, tag.data()) == 1);
	if (!ok || count + last != view.size()) {
		OPENSSL_cleanse(plain.data(), plain.size());
		return std::nullopt;
	}
	plain.resize(count + last);
	return encrypt
		? (QByteArray(kMagic, kMagicBytes) + nonce + plain + tag)
		: std::move(plain);
}

QByteArray Digest(const QByteArray &bytes) {
	return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
}

bool SaveScopedRecord(
		const ScopedOfflineAccount &account,
		const QString &path,
		const QString &relative,
		const QByteArray &bytes) {
	if (!ScopedDirectories(account, relative, true)) {
		return false;
	}
	const auto info = QFileInfo(path);
	if (Present(info) && (!CanonicalFile(info)
		|| !Storage::ReadScopedFile(account, path))) {
		return false;
	}
	const auto sealed = Crypt(account, relative, bytes, true);
	auto output = QSaveFile(path);
	output.setDirectWriteFallback(false);
	return sealed && output.open(QIODevice::WriteOnly)
		&& output.write(*sealed) == sealed->size() && output.commit()
		&& Storage::ReadScopedFile(account, path) == bytes;
}

bool AppendRecord(
		const ScopedOfflineAccount &scope,
		const QString &root,
		const QString &relative,
		const QString &target,
		const QByteArray &bytes,
		int limit,
		OfflineRetirementInventory &inventory,
		std::vector<Record> &records) {
	if (inventory.size() >= kMaxEntries || target.isEmpty()) {
		return false;
	}
	const auto hash = Digest(bytes);
	inventory.push_back({ relative, hash });
	records.push_back({ &scope, root + '/' + relative, target, hash, limit, bytes.size() });
	return true;
}

bool CollectPeer(
		const ScopedOfflineAccount &scope,
		PeerId peer,
		const QString &root,
		const QString &relative,
		OfflineRetirementInventory &inventory,
		std::vector<Record> &records) {
	using namespace Storage;
	const auto base = root + '/' + relative;
	const auto paths = ScopedPathsFor(scope, peer);
	if (!CanonicalDirectory(QFileInfo(base)) || paths.root.isEmpty()
		|| inventory.size() >= kMaxEntries) {
		return false;
	}
	inventory.push_back({ relative });
	const auto entries = QDir(base).entryInfoList(kEntries);
	auto attachments = std::vector<Attachment>();
	for (const auto &entry : entries) {
		const auto name = entry.fileName();
		const auto item = relative + '/' + name;
		const auto kind = ClassifyLegacyOfflinePath(item);
		if (kind == Kind::Directory && CanonicalDirectory(entry)) {
			continue;
		} else if (kind == Kind::Snapshot) {
			const auto data = ReadExact(entry.absoluteFilePath(), kMaxSnapshot);
			auto parsed = Snapshot();
			const auto target = (name == u"history.json"_q) ? paths.complete : paths.partial;
			if (!data || !DecodeSnapshot(*data, scope.userId, peer, &parsed)
				|| Serialize(parsed, scope.userId, peer) != *data
				|| !AppendRecord(scope, root, item, target, *data, kMaxSnapshot, inventory, records)) {
				return false;
			}
		} else if (kind == Kind::Manifest) {
			const auto data = ReadExact(entry.absoluteFilePath(), kMaxManifest);
			if (!data || !DecodeAttachments(*data, scope.userId, peer, &attachments)
				|| SerializeAttachments(attachments, scope.userId, peer) != *data
				|| !AppendRecord(scope, root, item, paths.attachmentManifest, *data,
					kMaxManifest, inventory, records)) {
				return false;
			}
		} else {
			return false;
		}
	}
	const auto folder = base + u"/attachments"_q;
	if (!Present(QFileInfo(folder))) {
		return attachments.empty();
	}
	if (inventory.size() >= kMaxEntries || !CanonicalDirectory(QFileInfo(folder))) {
		return false;
	}
	inventory.push_back({ relative + u"/attachments"_q });
	const auto files = QDir(folder).entryList(kEntries);
	if (files.size() != qsizetype(attachments.size())) {
		return false;
	}
	for (const auto &attachment : attachments) {
		const auto item = relative + u"/attachments/"_q + attachment.fileName;
		const auto target = ScopedAttachmentPath(scope, paths, attachment);
		const auto data = ReadExact(root + '/' + item, kMaxAttachment);
		if (!data || data->size() != attachment.size
			|| !AppendRecord(scope, root, item, target, *data, kMaxAttachment, inventory, records)) {
			return false;
		}
	}
	return true;
}

bool TargetInventory(
		const QString &path,
		const std::set<QString> &expected,
		bool complete,
		std::set<QString> &observed) {
	const auto info = QFileInfo(path);
	if (!Present(info)) {
		return !complete || expected.empty();
	} else if (!CanonicalDirectory(info)) {
		return false;
	}
	for (const auto &entry : QDir(path).entryInfoList(kEntries)) {
		const auto full = entry.absoluteFilePath();
		if (!expected.contains(full) || !observed.emplace(full).second) {
			return false;
		}
		if (entry.isDir()) {
			if (!TargetInventory(full, expected, false, observed)) {
				return false;
			}
		} else if (!CanonicalFile(entry)) {
			return false;
		}
	}
	return !complete || expected == observed;
}

} // namespace

std::optional<OfflineRetirementInventory> StageLegacyOfflineHistory(
		const QString &dataDirectory,
		std::span<const ScopedOfflineAccount> accounts) {
	if (QDir::cleanPath(dataDirectory) != dataDirectory
		|| !CanonicalDirectory(QFileInfo(dataDirectory))
		|| accounts.empty() || accounts.size() > 200) {
		return std::nullopt;
	}
	auto byId = std::map<quint64, const ScopedOfflineAccount*>();
	auto roots = std::set<QString>();
	const auto accountParent = dataDirectory + u"/profile-sets/accounts"_q;
	for (const auto &account : accounts) {
		if (!ValidAccount(account) || QFileInfo(account.accountRoot).path() != accountParent
			|| !byId.emplace(account.userId, &account).second
			|| !roots.emplace(account.accountRoot).second) {
			return std::nullopt;
		}
	}
	auto inventory = OfflineRetirementInventory();
	auto records = std::vector<Record>();
	const auto root = dataDirectory + '/' + kRoot;
	if (Present(QFileInfo(root))) {
		if (!CanonicalDirectory(QFileInfo(root))) {
			return std::nullopt;
		}
		inventory.push_back({ kRoot });
		for (const auto &legacy : QDir(root).entryInfoList(kEntries)) {
			const auto id = Decimal(legacy.fileName());
			const auto account = id ? byId.find(*id) : byId.end();
			const auto relative = kRoot + '/' + legacy.fileName();
			if (account == byId.end() || !CanonicalDirectory(legacy)
				|| inventory.size() >= kMaxEntries) {
				return std::nullopt;
			}
			inventory.push_back({ relative });
			for (const auto &peer : QDir(legacy.absoluteFilePath()).entryInfoList(kEntries)) {
				const auto peerId = Decimal(peer.fileName());
				if (!peerId || !KnownPeer(*peerId) || !CollectPeer(*account->second, PeerId(*peerId),
					dataDirectory, relative + '/' + peer.fileName(), inventory, records)) {
					return std::nullopt;
				}
			}
		}
	}
	auto expected = std::map<quint64, std::set<QString>>();
	auto totals = std::map<quint64, qint64>();
	for (const auto &record : records) {
		auto &paths = expected[record.scope->userId];
		auto &total = totals[record.scope->userId];
		total += record.bytes;
		if (total > kQuota || !paths.emplace(record.to).second) {
			return std::nullopt;
		}
		for (auto parent = QFileInfo(record.to).path(); parent != ScopedRoot(*record.scope)
			; parent = QFileInfo(parent).path()) {
			paths.emplace(parent);
		}
	}
	for (const auto &account : accounts) {
		auto observed = std::set<QString>();
		if (!TargetInventory(ScopedRoot(account), expected[account.userId], false, observed)) {
			return std::nullopt;
		}
	}
	for (const auto &record : records) {
		const auto data = ReadExact(record.from, record.limit);
		if (!data || Digest(*data) != record.sha256) {
			return std::nullopt;
		}
		using namespace Storage;
		if (Present(QFileInfo(record.to))) {
			if (ReadScopedFile(*record.scope, record.to) != *data) {
				return std::nullopt;
			}
		} else {
			const auto relative = ScopedRelative(*record.scope, record.to);
			if (!relative || !SaveScopedRecord(*record.scope, record.to, *relative, *data)) {
				return std::nullopt;
			}
		}
	}
	for (const auto &account : accounts) {
		auto observed = std::set<QString>();
		const auto scoped = ScopedRoot(account);
		if (!TargetInventory(scoped, expected[account.userId], true, observed)) {
			return std::nullopt;
		}
		for (auto i = observed.rbegin(); i != observed.rend(); ++i) {
			if (QFileInfo(*i).isDir() && !SyncDirectory(*i)) {
				return std::nullopt;
			}
		}
		if (Present(QFileInfo(scoped))
			&& (!SyncDirectory(scoped) || !SyncDirectory(account.accountRoot))) {
			return std::nullopt;
		}
	}
	std::ranges::sort(inventory, {}, &LegacyOfflineEntry::relativePath);
	return inventory;
}

namespace Storage {

Paths ScopedPathsFor(const ScopedOfflineAccount &account, PeerId peer) {
	if (!KnownPeer(peer.value) || !ValidAccount(account)) {
		return {};
	}
	const auto root = ScopedRoot(account);
	const auto name = Mac(account, QByteArray("SleepyGram offline history peer v1/")
		+ QByteArray::number(peer.value));
	const auto folder = root + '/' + QString::fromLatin1(name.toHex());
	return {
		.root = root,
		.complete = folder + u"/history"_q,
		.partial = folder + u"/partial"_q,
		.attachmentDirectory = folder + u"/attachments"_q,
		.attachmentManifest = folder + u"/manifest"_q,
	};
}

QString ScopedAttachmentPath(
		const ScopedOfflineAccount &account,
		const Paths &paths,
		const Attachment &attachment) {
	if (!account.key || paths.attachmentDirectory.isEmpty()
		|| !LegacyAttachmentName(attachment.fileName)) {
		return {};
	}
	const auto name = Mac(account, QByteArray("SleepyGram offline history attachment v1/")
		+ attachment.fileName.toUtf8());
	return paths.attachmentDirectory + '/' + QString::fromLatin1(name.toHex());
}

std::optional<QByteArray> ReadScopedFile(
		const ScopedOfflineAccount &account,
		const QString &path) {
	const auto relative = ScopedRelative(account, path);
	if (!relative || !ScopedDirectories(account, *relative, false)) {
		return std::nullopt;
	}
	const auto sealed = ReadExact(path, RecordLimit(*relative) + kEnvelopeBytes);
	return sealed ? Crypt(account, *relative, *sealed, false) : std::nullopt;
}

bool WriteScopedFile(
		const ScopedOfflineAccount &account,
		const QString &path,
		const QByteArray &bytes,
		qint64 quota,
		const QStringList &excluded) {
	const auto relative = ScopedRelative(account, path);
	if (!relative || bytes.isEmpty() || bytes.size() > RecordLimit(*relative)
		|| !ScopedDirectories(account, *relative, true)) {
		return false;
	}
	auto skip = excluded;
	skip.push_back(path);
	if (UsageBytes(ScopedRoot(account), skip) + bytes.size() + kEnvelopeBytes > quota) {
		return false;
	}
	return SaveScopedRecord(account, path, *relative, bytes);
}

bool ScopedFilePresent(
		const ScopedOfflineAccount &account,
		const QString &path,
		qint64 payloadSize) {
	const auto relative = ScopedRelative(account, path);
	const auto info = QFileInfo(path);
	return relative && payloadSize > 0 && payloadSize <= RecordLimit(*relative)
		&& ScopedDirectories(account, *relative, false)
		&& CanonicalFile(info) && info.size() == payloadSize + kEnvelopeBytes;
}

bool RemoveScopedPeer(const ScopedOfflineAccount &account, const Paths &paths) {
	const auto relative = ScopedRelative(account, paths.complete);
	if (!relative || !relative->endsWith(u"/history"_q)) {
		return false;
	}
	const auto parent = QFileInfo(paths.complete).path();
	const auto attachments = parent + u"/attachments"_q;
	if (!Present(QFileInfo(parent))) {
		return true;
	} else if (!ScopedDirectories(account, *relative, false)) {
		return false;
	}
	auto files = QStringList();
	for (const auto &entry : QDir(parent).entryInfoList(kEntries)) {
		const auto path = entry.absoluteFilePath();
		if (entry.fileName() == u"attachments"_q && CanonicalDirectory(entry)) {
			for (const auto &attachment : QDir(path).entryInfoList(kEntries)) {
				if (!LowerHex(attachment.fileName(), 64) || !CanonicalFile(attachment)) {
					return false;
				}
				files.push_back(attachment.absoluteFilePath());
			}
		} else if (!ScopedRelative(account, path) || !CanonicalFile(entry)) {
			return false;
		} else {
			files.push_back(path);
		}
	}
	return std::ranges::all_of(files, [](const QString &path) { return QFile::remove(path); })
		&& (!Present(QFileInfo(attachments)) || QDir().rmdir(attachments))
		&& QDir().rmdir(parent);
}

} // namespace Storage
} // namespace Ayu::OfflineHistory
