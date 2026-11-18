// This is the source code of AyuGram for Desktop.
#include "storage/details/storage_cache_migration.h"

#include "storage/cache/storage_cache_binlog_reader.h"
#include "storage/details/storage_cache_migration_paths.h"
#include "base/openssl_help.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <openssl/crypto.h>
#include <xxhash.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>

#if defined Q_OS_WIN
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace Storage::details {
namespace {

using Result = CacheMigrationResult;
using Kind = CacheMigrationPathKind;
using namespace Cache::details;

constexpr auto kHeaderBytes = qint64(base::FileLock::kSkipBytes
	+ kSaltSize
	+ 2 * sizeof(uint64)
	+ openssl::kSha256Size);
constexpr auto kChunkBytes = 256 * 1024;
constexpr auto kMaximumEntries = 60'000;
constexpr auto kEntries = QDir::AllEntries
	| QDir::NoDotAndDotDot
	| QDir::Hidden
	| QDir::System;

struct Tree {
	std::map<QString, Kind> entries;
	QStringList activeBinlogs;
};

bool Present(const QFileInfo &info) {
	return info.exists() || info.isSymLink() || info.isJunction();
}

bool CanonicalDirectory(const QFileInfo &info) {
	return info.isDir() && !info.isSymLink() && !info.isJunction()
		&& info.absoluteFilePath() == info.canonicalFilePath()
		&& QDir(info.absoluteFilePath()).isReadable();
}

bool CanonicalFile(const QFileInfo &info) {
	auto error = std::error_code();
	return info.isFile() && !info.isSymLink() && !info.isJunction()
		&& info.absoluteFilePath() == info.canonicalFilePath()
		&& std::filesystem::hard_link_count(info.filesystemFilePath(), error) == 1
		&& !error;
}

bool ValidRoot(const QString &path, const QString &clean) {
	return QDir::isAbsolutePath(path) && !path.startsWith(':')
		&& !path.contains(QChar(0)) && (path == clean || path == clean + '/')
		&& CanonicalDirectory(QFileInfo(QFileInfo(clean).path()));
}

bool Add(Tree &tree, QString path, Kind kind) {
	return tree.entries.size() < kMaximumEntries
		&& tree.entries.emplace(std::move(path), kind).second;
}

bool ReadGeneration(
		const QString &root,
		const QString &generation,
		Tree &tree) {
	for (const auto &item : QDir(root + '/' + generation).entryInfoList(kEntries)) {
		const auto name = item.fileName();
		const auto path = generation + '/' + name;
		const auto kind = ClassifyCacheMigrationPath(path);
		if (kind == Kind::Encrypted) {
			if (!CanonicalFile(item) || !Add(tree, path, Kind::Encrypted)) {
				return false;
			}
			continue;
		}
		if (kind != Kind::Directory
			|| !CanonicalDirectory(item)
			|| !Add(tree, path, Kind::Directory)) {
			return false;
		}
		for (const auto &payload : QDir(item.absoluteFilePath()).entryInfoList(kEntries)) {
			const auto relative = path + '/' + payload.fileName();
			if (ClassifyCacheMigrationPath(relative) != Kind::Encrypted
				|| !CanonicalFile(payload)
				|| !Add(tree, relative, Kind::Encrypted)) {
				return false;
			}
		}
	}
	return true;
}

bool ReadCache(const QString &root, const QFileInfo &cache, Tree &tree) {
	const auto name = cache.fileName();
	if (!CanonicalDirectory(cache) || !Add(tree, name, Kind::Directory)) {
		return false;
	}
	const auto entries = QDir(cache.absoluteFilePath()).entryInfoList(kEntries);
	auto active = Version(0);
	for (const auto &item : entries) {
		const auto part = item.fileName();
		const auto path = name + '/' + part;
		const auto kind = ClassifyCacheMigrationPath(path);
		if (kind == Kind::Version) {
			if (!CanonicalFile(item) || item.size() != sizeof(Version)
				|| !Add(tree, path, Kind::Version)) {
				return false;
			}
			const auto read = ReadVersionValue(cache.absoluteFilePath() + '/');
			if (!read || *read < 0) {
				return false;
			}
			active = *read;
		} else {
			if (kind != Kind::Directory
				|| !CanonicalDirectory(item) || !Add(tree, path, Kind::Directory)
				|| !ReadGeneration(root, path, tree)) {
				return false;
			}
		}
	}
	if (!entries.isEmpty()) {
		const auto path = name + '/' + QString::number(active);
		const auto ready = path + u"/binlog-ready"_q;
		const auto log = path + u"/binlog"_q;
		if (tree.entries.contains(ready)) {
			tree.activeBinlogs.push_back(ready);
		} else if (tree.entries.contains(log)) {
			tree.activeBinlogs.push_back(log);
		} else {
			return false;
		}
	}
	return true;
}

std::optional<Tree> ReadTree(const QString &root, bool scoped, bool preserveLegacyWebview = false) {
	const auto directory = QFileInfo(root);
	if (!Present(directory)) {
		return Tree();
	} else if (!CanonicalDirectory(directory)) {
		return std::nullopt;
	}
	auto tree = Tree();
	for (const auto &item : QDir(root).entryInfoList(kEntries)) {
		const auto name = item.fileName();
		if (!scoped && preserveLegacyWebview && IsLegacyWebviewDirectoryName(name)) {
			continue;
		}
		if (scoped && name == u"archive.db"_q
			&& CanonicalFile(item) && item.size() > 0) {
			continue;
		} else if ((name != u"cache"_q && name != u"media_cache"_q)
			|| !ReadCache(root, item, tree)) {
			return std::nullopt;
		}
	}
	return tree;
}

bool OpenEncrypted(File &file, const QString &path, const EncryptionKey &key) {
	const auto info = QFileInfo(path);
	if (!CanonicalFile(info) || info.size() < kHeaderBytes
		|| (info.size() - kHeaderBytes) % CtrState::kBlockSize) {
		return false;
	}
	auto raw = QFile(path);
	return raw.open(QIODevice::ReadOnly) && raw.read(4) == "TDEF"
		&& file.open(path, File::Mode::Read, key) == File::Result::Success
		&& file.size() == info.size() - kHeaderBytes;
}

QString PayloadPath(const QString &directory, const PlaceId &id) {
	const auto hex = QByteArray(
		reinterpret_cast<const char*>(id.data()),
		id.size()).toHex().toUpper();
	auto path = directory + '/';
	for (auto i = 0; i != hex.size(); i += 2) {
		path += QLatin1Char(hex[i + 1]);
		path += QLatin1Char(hex[i]);
		if (!i) {
			path += '/';
		}
	}
	return path;
}

bool CheckActiveCache(
		const QString &source,
		const QString &relative,
		const Tree &tree,
		const EncryptionKey &key) {
	auto binlog = File();
	const auto settings = Settings();
	if (!OpenEncrypted(binlog, source + '/' + relative, key)
		|| !BinlogWrapper::ReadHeader(binlog, settings)) {
		return false;
	}
	auto wrapper = BinlogWrapper(binlog, settings);
	auto reader = BinlogReader<
		StoreWithTime,
		MultiStoreWithTime,
		MultiRemove,
		MultiAccess>(wrapper);
	auto records = std::map<Cache::Key, Store>();
	const auto store = [&](const StoreWithTime &record) {
		if (!record.key.valid() || record.getSize() <= 0
			|| record.getSize() > settings.maxDataSize
			|| records.size() >= kMaximumEntries) {
			return false;
		}
		records.insert_or_assign(record.key, record);
		return true;
	};
	while (!reader.readTillEnd(
			store,
			[&](const MultiStoreWithTime &, const auto &next) {
				while (const auto part = next()) {
					if (!store(*part)) {
						return false;
					}
				}
				return true;
			},
			[&](const MultiRemove &, const auto &next) {
				while (const auto part = next()) {
					records.erase(*part);
				}
				return true;
			},
			[](const MultiAccess &, const auto &) { return true; })) {
	}
	if (wrapper.failed() || binlog.offset() != binlog.size()) {
		return false;
	}
	const auto generation = relative.left(relative.lastIndexOf('/'));
	auto used = std::set<QString>();
	for (const auto &[id, record] : records) {
		const auto path = PayloadPath(generation, record.place);
		const auto existing = tree.entries.find(path);
		if (existing == end(tree.entries) || existing->second != Kind::Encrypted
			|| !used.emplace(path).second) {
			return false;
		}
		auto payload = File();
		const auto size = record.getSize();
		const auto block = CtrState::kBlockSize;
		const auto padded = ((size + block - 1) / block) * block;
		if (!OpenEncrypted(payload, source + '/' + path, key)
			|| payload.size() != padded) {
			return false;
		}
		auto data = bytes::vector(size);
		const auto wipe = gsl::finally([&] {
			OPENSSL_cleanse(data.data(), data.size());
		});
		if (payload.readWithPadding(data) != size
			|| XXH32(data.data(), data.size(), 0) != record.checksum) {
			return false;
		}
	}
	return true;
}

bool SyncFile(const QString &path) {
	auto file = QFile(path);
#if defined Q_OS_WIN
	return file.open(QIODevice::ReadWrite) && (_commit(file.handle()) == 0);
#else
	return file.open(QIODevice::ReadOnly) && (fsync(file.handle()) == 0);
#endif
}

bool SyncDirectory(const QString &path) {
#if defined Q_OS_WIN
	return CanonicalDirectory(QFileInfo(path));
#else
	const auto fd = open(
		QFile::encodeName(path).constData(),
		O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	const auto ok = fsync(fd) == 0;
	close(fd);
	return ok;
#endif
}

Result CompareEncrypted(
		const QString &sourcePath,
		const QString &targetPath,
		const EncryptionKey &sourceKey,
		const EncryptionKey &targetKey,
		bool write) {
	auto source = File();
	if (!OpenEncrypted(source, sourcePath, sourceKey)) {
		return Result::InvalidSource;
	}
	const auto bufferSize = std::min(int64(kChunkBytes), source.size());
	auto buffer = bytes::vector(bufferSize);
	auto readback = bytes::vector(bufferSize);
	const auto wipe = gsl::finally([&] {
		if (!buffer.empty()) {
			OPENSSL_cleanse(buffer.data(), buffer.size());
			OPENSSL_cleanse(readback.data(), readback.size());
		}
	});
	const auto chunk = [&] {
		return size_type(std::min(bufferSize, source.size() - source.offset()));
	};
	if (write) {
		auto target = File();
		if (Present(QFileInfo(targetPath))
			|| target.open(targetPath, File::Mode::Write, targetKey)
				!= File::Result::Success) {
			return Result::DestinationIo;
		}
		while (const auto size = chunk()) {
			const auto span = bytes::make_span(buffer).first(size);
			if (source.read(span) != size) {
				return Result::InvalidSource;
			} else if (!target.write(span)) {
				return Result::DestinationIo;
			}
		}
		if (!target.flush()) {
			return Result::DestinationIo;
		}
		target.close();
		if (!SyncFile(targetPath) || !source.seek(0)) {
			return Result::DestinationIo;
		}
	}
	auto checked = File();
	auto wrongKey = File();
	if (!OpenEncrypted(checked, targetPath, targetKey)
		|| checked.size() != source.size()
		|| OpenEncrypted(wrongKey, targetPath, sourceKey)) {
		return Result::VerificationFailed;
	}
	while (const auto size = chunk()) {
		const auto expected = bytes::make_span(buffer).first(size);
		const auto actual = bytes::make_span(readback).first(size);
		if (source.read(expected) != size) {
			return Result::InvalidSource;
		} else if (checked.read(actual) != size || bytes::compare(expected, actual)) {
			return Result::VerificationFailed;
		}
	}
	return Result::Success;
}

Result CompareVersion(const QString &sourcePath, const QString &targetPath, bool write) {
	const auto sourceBase = QFileInfo(sourcePath).path() + '/';
	const auto targetBase = QFileInfo(targetPath).path() + '/';
	const auto version = ReadVersionValue(sourceBase);
	if (!version) {
		return Result::InvalidSource;
	} else if (write && (Present(QFileInfo(targetPath))
		|| !WriteVersionValue(targetBase, *version)
		|| !SyncFile(targetPath))) {
		return Result::DestinationIo;
	}
	return ReadVersionValue(targetBase) == version
		? Result::Success
		: Result::VerificationFailed;
}

} // namespace

CacheMigrationResult CompareAccountCachesForMigration(
		const QString &legacyDatabasePath,
		const QString &scopedDatabasePath,
		const EncryptionKey &legacyKey,
		const EncryptionKey &scopedKey,
		bool write,
		CacheMigrationInventory *inventory,
		LegacyWebviewTransfer webview) {
	if (inventory) {
		*inventory = {};
	}
	if (!legacyKey || !scopedKey || legacyKey.data() == scopedKey.data()) {
		return Result::InvalidKeys;
	}
	const auto source = QDir::cleanPath(legacyDatabasePath);
	const auto target = QDir::cleanPath(scopedDatabasePath);
	if (!ValidRoot(legacyDatabasePath, source) || !ValidRoot(scopedDatabasePath, target)
		|| source == target || source.startsWith(target + '/')
		|| target.startsWith(source + '/')) {
		return Result::InvalidPaths;
	}
	const auto oldTree = ReadTree(source, false, webview == LegacyWebviewTransfer::StartFresh);
	if (!oldTree) {
		return Result::UnsupportedSource;
	}
	const auto newTree = ReadTree(target, true);
	if (!newTree || (write ? !newTree->entries.empty() : newTree->entries != oldTree->entries)) {
		return Result::VerificationFailed;
	}
	for (const auto &binlog : oldTree->activeBinlogs) {
		if (!CheckActiveCache(source, binlog, *oldTree, legacyKey)) {
			return Result::InvalidSource;
		}
	}
	auto verified = CacheMigrationInventory();
	if (write && !oldTree->entries.empty() && !Present(QFileInfo(target))
		&& !QDir().mkdir(target)) {
		return Result::DestinationIo;
	}
	for (const auto &[relative, kind] : oldTree->entries) {
		const auto from = source + '/' + relative;
		const auto to = target + '/' + relative;
		if (kind == Kind::Directory) {
			if (write && !QDir().mkdir(to)) {
				return Result::DestinationIo;
			}
			verified.directories.push_back(relative);
			continue;
		}
		const auto compared = (kind == Kind::Version)
			? CompareVersion(from, to, write)
			: CompareEncrypted(from, to, legacyKey, scopedKey, write);
		if (compared != Result::Success) {
			return compared;
		}
		verified.files.push_back(relative);
	}
	if (write && !oldTree->entries.empty()) {
		for (auto i = verified.directories.crbegin(); i != verified.directories.crend(); ++i) {
			if (!SyncDirectory(target + '/' + *i)) {
				return Result::DestinationIo;
			}
		}
		if (!SyncDirectory(target) || !SyncDirectory(QFileInfo(target).path())) {
			return Result::DestinationIo;
		}
	}
	if (inventory) {
		*inventory = std::move(verified);
	}
	return Result::Success;
}

} // namespace Storage::details
