/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tgw/tgw_storage_disk.h"

#include "main/main_account.h"
#include "mtproto/mtproto_auth_key.h"
#include "mtproto/mtproto_dc_options.h"
#include "storage/details/storage_file_utilities.h"
#include "twidget/sdk_policy.h"

#include <QtCore/QDataStream>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <openssl/crypto.h>

#include <cmath>
#include <filesystem>
#include <set>

namespace Tgw {
namespace {

constexpr auto kIndexVersion = quint32(2);
constexpr auto kRecordVersion = quint32(1);
constexpr auto kQuota = uint64(twidget::sdk::STORAGE_QUOTA_BYTES);
// WHY: records saved under the old 16 KB quota must still parse, so
// their first read retires them instead of failing at every start.
constexpr auto kMaxStoredBytes = std::max(kQuota, uint64(16384));
constexpr auto kMaxPairs = kMaxStoredBytes + 1;
constexpr auto kPairSize = uint64(2 * sizeof(quint32));
constexpr auto kRecordHeaderSize = uint64(2 * sizeof(quint32));
constexpr auto kMaxRecordSize = kRecordHeaderSize
	+ kMaxPairs * kPairSize
	+ kMaxStoredBytes;
constexpr auto kIndexHeaderSize = uint64(
	2 * sizeof(quint32) + sizeof(quint64));
constexpr auto kIndexEntrySizeV1 = uint64(
	6 * sizeof(quint64) + 2 * sizeof(qint32));
constexpr auto kIndexEntrySize = kIndexEntrySizeV1
	+ uint64(sizeof(double) + sizeof(quint32));
constexpr auto kNullBytes = quint32(0xFFFFFFFF);
constexpr auto kFileNameSize = 16;
constexpr auto kTestSessionOwnerBit = 0x0100'0000'0000'0000ULL;
constexpr auto kMaxMigrationIndexSize = uint64(64 * 1024 * 1024);
constexpr auto kRecordEnvelopeAllowance = uint64(64);
constexpr auto kMigrationEntries = QDir::AllEntries
	| QDir::NoDotAndDotDot
	| QDir::Hidden
	| QDir::System;

const auto kIndexName = u"index"_q;
const auto kStorageFolderName = u"tgw"_q;
const auto kSuffixes = u"01s"_q;

using namespace Storage::details;
using MigrationResult = Storage::AccountMigrationResult;

[[nodiscard]] bool Storable(FullMsgId key) {
	const auto peer = key.peer;
	return IsServerMsgId(key.msg)
		&& (peerToUser(peer) || peerToChat(peer) || peerToChannel(peer));
}

[[nodiscard]] bool HasSuffix(const QString &name, qsizetype size) {
	return (name.size() == size + 1) && kSuffixes.contains(name.back());
}

[[nodiscard]] bool IndexFile(const QString &name) {
	return HasSuffix(name, kIndexName.size()) && name.startsWith(kIndexName);
}

[[nodiscard]] uint32 Reserve(uint64 size) {
	return uint32(std::min(size, kMaxRecordSize));
}

[[nodiscard]] std::optional<std::string> ReadBytes(
		QDataStream &stream,
		uint64 &left) {
	auto size = quint32();
	stream >> size;
	if (stream.status() != QDataStream::Ok) {
		return std::nullopt;
	} else if (size == kNullBytes) {
		return std::string();
	} else if (size > left) {
		return std::nullopt;
	}
	auto result = std::string(size, char());
	if (size && stream.readRawData(result.data(), size) != qint64(size)) {
		return std::nullopt;
	}
	left -= size;
	return result;
}

[[nodiscard]] std::optional<StorageDisk::Area> ReadRecord(
		QDataStream &stream) {
	auto version = quint32();
	auto count = quint32();
	stream >> version >> count;
	if (!CheckStreamStatus(stream)
		|| !version
		|| version > kRecordVersion
		|| count > kMaxPairs
		|| count * kPairSize > uint64(stream.device()->bytesAvailable())) {
		return std::nullopt;
	}
	auto result = StorageDisk::Area();
	auto left = kMaxStoredBytes;
	for (auto i = quint32(); i != count; ++i) {
		auto key = ReadBytes(stream, left);
		auto value = key ? ReadBytes(stream, left) : std::nullopt;
		const auto added = value
			&& result.emplace(std::move(*key), std::move(*value)).second;
		if (!added) {
			return std::nullopt;
		}
	}
	return result;
}

[[nodiscard]] bool ReadIndex(
		QDataStream &stream,
		uint64 expectedOwner,
		auto add) {
	auto version = quint32();
	auto owner = quint64();
	auto count = quint32();
	stream >> version >> owner >> count;
	const auto entrySize = (version > 1) ? kIndexEntrySize : kIndexEntrySizeV1;
	if (!CheckStreamStatus(stream)
		|| !version
		|| version > kIndexVersion
		|| owner != expectedOwner
		|| count * entrySize > uint64(stream.device()->bytesAvailable())) {
		return false;
	}
	auto files = std::vector<Storage::FileKey>();
	for (auto i = quint32(); i != count; ++i) {
		auto peer = quint64();
		auto msg = qint64();
		auto file = Storage::FileKey();
		auto meta = StorageMeta();
		auto height = HeightRecord();
		auto topicRootId = qint64();
		auto sublistPeerId = quint64();
		auto from = quint64();
		auto anchor = quint32();
		stream
			>> peer
			>> msg
			>> file
			>> meta.date
			>> meta.expires
			>> topicRootId
			>> sublistPeerId
			>> from;
		if (version > 1) {
			stream >> height.height >> anchor;
		}
		meta.topicRootId = topicRootId;
		meta.sublistPeerId = DeserializePeerId(sublistPeerId);
		meta.from = DeserializePeerId(from);
		height.bottom = (anchor == 1);
		const auto key = FullMsgId(DeserializePeerId(peer), MsgId(msg));
		if (!CheckStreamStatus(stream)
			|| !Storable(key)
			|| !std::isfinite(height.height)
			|| (height.height < 0.)
			|| (anchor > 1)
			|| (!file && height.height <= 0.)
			|| !add(key, file, meta, height)) {
			return false;
		} else if (file) {
			files.push_back(file);
		}
	}
	ranges::sort(files);
	return (ranges::adjacent_find(files) == end(files));
}

void AppendRecordPaths(
		std::vector<QString> &paths,
		const QString &folder,
		Storage::FileKey file) {
	const auto base = folder + ToFilePart(file);
	for (const auto suffix : kSuffixes) {
		paths.push_back(base + suffix);
	}
}

struct MigrationRecord {
	~MigrationRecord() {
		if (!payload.data.isEmpty()) {
			OPENSSL_cleanse(payload.data.data(), size_t(payload.data.size()));
		}
	}

	EncryptedDescriptor payload;
	int32 version = 0;
};

[[nodiscard]] bool Present(const QFileInfo &info) {
	return info.exists() || info.isSymLink() || info.isJunction();
}

[[nodiscard]] bool CanonicalDirectory(const QString &path) {
	const auto info = QFileInfo(path);
	return info.isDir()
		&& !info.isSymLink()
		&& !info.isJunction()
		&& info.canonicalFilePath() == path
		&& QDir(path).isReadable();
}

[[nodiscard]] std::optional<std::set<QString>> MigrationInventory(
		const QString &directory,
		bool staged) {
	auto stems = std::set<QString>();
	if (!Present(QFileInfo(directory))) {
		return stems;
	} else if (!CanonicalDirectory(directory)) {
		return std::nullopt;
	}
	for (const auto &info : QDir(directory).entryInfoList(kMigrationEntries)) {
		const auto name = info.fileName();
		const auto isIndex = IndexFile(name);
		const auto maximum = isIndex ? kMaxMigrationIndexSize : kMaxRecordSize;
		auto error = std::error_code();
		if ((!isIndex && !HasSuffix(name, kFileNameSize))
			|| (staged && name.back() != QChar('s'))
			|| !info.isFile()
			|| info.isSymLink()
			|| info.isJunction()
			|| info.canonicalFilePath() != info.absoluteFilePath()
			|| std::filesystem::hard_link_count(
				info.filesystemFilePath(),
				error) != 1
			|| error
			|| uint64(info.size()) > maximum + kRecordEnvelopeAllowance) {
			return std::nullopt;
		}
		stems.insert(name.chopped(1));
	}
	return stems;
}

[[nodiscard]] bool ReadMigrationRecord(
		const QString &name,
		const QString &folder,
		const MTP::AuthKeyPtr &key,
		MigrationRecord &record) {
	auto file = FileReadDescriptor();
	if (!ReadFile(file, name, folder, LegacyBackupPolicy::Preserve)
		|| file.version <= 0) {
		return false;
	}
	auto encrypted = QByteArray();
	file.stream >> encrypted;
	record.version = file.version;
	return (file.stream.status() == QDataStream::Ok)
		&& file.stream.atEnd()
		&& DecryptLocal(record.payload, encrypted, key);
}

[[nodiscard]] MigrationResult CompareMigrationRecord(
		MigrationRecord &source,
		const QString &name,
		const QString &folder,
		const MTP::AuthKeyPtr &key,
		bool write) {
	if (write) {
		auto file = FileWriteDescriptor(name, folder);
		file.writeEncrypted(source.payload, key);
		return file.finishStaged(source.version)
			? MigrationResult::Success
			: MigrationResult::DestinationIo;
	}
	auto target = MigrationRecord();
	return (ReadMigrationRecord(name, folder, key, target)
		&& (source.version == target.version)
		&& (source.payload.data == target.payload.data))
		? MigrationResult::Success
		: MigrationResult::VerificationFailed;
}

} // namespace

QString StorageFolder(not_null<Main::Account*> account) {
	return account->local().basePath() + kStorageFolderName + '/';
}

void EraseStorageFolder(const QString &folder) {
	ScheduleRemoveFolder(folder);
}

Storage::AccountMigrationResult CompareStorageForMigration(
		const QString &sourceAccountBasePath,
		const MTP::AuthKeyPtr &sourceKey,
		const QString &targetAccountBasePath,
		const MTP::AuthKeyPtr &targetKey,
		UserId expectedUser,
		MTP::Environment environment,
		bool write) {
	const auto sourceBase = QDir::cleanPath(sourceAccountBasePath);
	const auto targetBase = QDir::cleanPath(targetAccountBasePath);
	if (!sourceKey || !targetKey || sourceKey->equals(targetKey)) {
		return MigrationResult::InvalidKeys;
	} else if (!expectedUser
		|| (environment != MTP::Environment::Production
			&& environment != MTP::Environment::Test)) {
		return MigrationResult::IdentityMismatch;
	} else if (!CanonicalDirectory(sourceBase)
		|| !CanonicalDirectory(targetBase)
		|| (sourceAccountBasePath != sourceBase
			&& sourceAccountBasePath != sourceBase + '/')
		|| (targetAccountBasePath != targetBase
			&& targetAccountBasePath != targetBase + '/')
		|| sourceBase == targetBase
		|| sourceBase.startsWith(targetBase + '/')
		|| targetBase.startsWith(sourceBase + '/')) {
		return MigrationResult::InvalidPaths;
	}
	const auto sourceDirectory = sourceBase + '/' + kStorageFolderName;
	const auto targetDirectory = targetBase + '/' + kStorageFolderName;
	const auto source = MigrationInventory(sourceDirectory, false);
	const auto target = MigrationInventory(targetDirectory, true);
	if (!source) {
		return MigrationResult::UnsupportedData;
	} else if (!target
		|| (write && Present(QFileInfo(targetDirectory)))
		|| (!write && *target != *source)) {
		return MigrationResult::VerificationFailed;
	} else if (source->empty()) {
		return MigrationResult::Success;
	} else if (!source->contains(kIndexName)) {
		return MigrationResult::InvalidSource;
	}
	const auto sourceFolder = sourceDirectory + '/';
	const auto targetFolder = targetDirectory + '/';
	const auto owner = expectedUser.bare | ((environment == MTP::Environment::Test)
		? kTestSessionOwnerBit
		: 0ULL);
	auto index = MigrationRecord();
	if (!ReadMigrationRecord(kIndexName, sourceFolder, sourceKey, index)) {
		return MigrationResult::InvalidSource;
	}
	auto messages = std::set<FullMsgId>();
	auto expected = std::set<QString>{ kIndexName };
	const auto indexed = ReadIndex(
		index.payload.stream,
		owner,
		[&](FullMsgId key, Storage::FileKey file, StorageMeta, HeightRecord) {
			if (file) {
				expected.insert(ToFilePart(file));
			}
			return messages.insert(key).second;
		});
	if (!indexed || !index.payload.stream.atEnd() || *source != expected) {
		return MigrationResult::InvalidSource;
	}
	if (write && !QDir().mkdir(targetDirectory)) {
		return MigrationResult::DestinationIo;
	}
	for (const auto &name : *source) {
		if (name == kIndexName) {
			continue;
		}
		auto record = MigrationRecord();
		if (!ReadMigrationRecord(name, sourceFolder, sourceKey, record)
			|| !ReadRecord(record.payload.stream)
			|| !record.payload.stream.atEnd()) {
			return MigrationResult::InvalidSource;
		}
		const auto result = CompareMigrationRecord(
			record,
			name,
			targetFolder,
			targetKey,
			write);
		if (result != MigrationResult::Success) {
			return result;
		}
	}
	return CompareMigrationRecord(index, kIndexName, targetFolder, targetKey, write);
}

StorageDisk::StorageDisk(QString folder, MTP::AuthKeyPtr key, uint64 owner)
: _folder(std::move(folder))
, _key(std::move(key))
, _owner(owner) {
	Expects(_key != nullptr);
	Expects(_folder.endsWith(QChar('/')));

	const auto names = QDir(_folder).entryList(
		QDir::Files | QDir::Hidden | QDir::System);
	if (ranges::any_of(names, IndexFile) && !readIndex()) {
		LOG(("Tgw Error: Could not read the widget storage index."));
		ScheduleRemoveFolder(_folder);
	} else {
		cleanup(names);
	}
}

bool StorageDisk::empty() const {
	return _entries.empty();
}

std::optional<StorageMeta> StorageDisk::lookup(FullMsgId key) const {
	const auto i = _entries.find(key);
	if (i == end(_entries)) {
		return std::nullopt;
	}
	return i->second.meta;
}

std::optional<StorageDisk::Area> StorageDisk::read(FullMsgId key) {
	const auto i = _entries.find(key);
	if (i == end(_entries) || !i->second.file) {
		return std::nullopt;
	}
	auto file = FileReadDescriptor();
	auto result = ReadEncryptedFile(file, i->second.file, _folder, _key)
		? ReadRecord(file.stream)
		: std::nullopt;
	if (!result) {
		LOG(("Tgw Error: Could not read a widget storage record."));
		return Area();
	} else if (twidget::sdk::storageAreaFits(*result)) {
		return result;
	}
	auto paths = std::vector<QString>();
	AppendRecordPaths(paths, _folder, base::take(i->second.file));
	if (i->second.height.height <= 0.) {
		_entries.erase(i);
	}
	ScheduleRemoveFiles(std::move(paths));
	writeIndex();
	LOG(("Tgw dropped a widget storage record over the quota."));
	return std::nullopt;
}

std::optional<HeightRecord> StorageDisk::height(FullMsgId key) const {
	const auto i = _entries.find(key);
	return (i != end(_entries) && i->second.height.height > 0.)
		? std::make_optional(i->second.height)
		: std::nullopt;
}

TimeId StorageDisk::nextExpiry() const {
	auto result = TimeId();
	for (const auto &[key, entry] : _entries) {
		const auto expires = entry.meta.expires;
		if (expires > 0 && (!result || expires < result)) {
			result = expires;
		}
	}
	return result;
}

bool StorageDisk::write(
		FullMsgId key,
		const StorageMeta &meta,
		const Area &local) {
	if (!Storable(key)) {
		return false;
	}
	auto i = _entries.find(key);
	if (i == end(_entries)) {
		if (local.empty()) {
			return false;
		}
		i = _entries.emplace(key, Entry()).first;
	}
	auto &entry = i->second;
	const auto attach = !entry.file && !local.empty();
	const auto changed = attach || (entry.meta != meta);
	if (attach) {
		entry.file = generateFile();
	}
	if (changed) {
		entry.meta = meta;
		writeIndex();
	}
	if (entry.file) {
		writeRecord(entry.file, local);
	}
	return changed;
}

bool StorageDisk::setHeight(
		FullMsgId key,
		const StorageMeta &meta,
		HeightRecord height) {
	if (!Storable(key)
		|| !std::isfinite(height.height)
		|| (height.height <= 0.)) {
		return false;
	}
	auto &entry = _entries[key];
	if (entry.meta == meta && entry.height == height) {
		return false;
	}
	entry.meta = meta;
	entry.height = height;
	_indexDirty = true;
	return true;
}

bool StorageDisk::refresh(FullMsgId key, const StorageMeta &meta) {
	const auto i = _entries.find(key);
	if (i == end(_entries) || i->second.meta == meta) {
		return false;
	}
	i->second.meta = meta;
	writeIndex();
	return true;
}

bool StorageDisk::refresh(
		Fn<std::optional<StorageMeta>(FullMsgId)> current) {
	auto changed = false;
	for (auto &[key, entry] : _entries) {
		const auto meta = current(key);
		if (meta && entry.meta != *meta) {
			entry.meta = *meta;
			changed = true;
		}
	}
	if (changed) {
		writeIndex();
	}
	return changed;
}

bool StorageDisk::remove(Fn<bool(FullMsgId, const StorageMeta &)> matches) {
	auto paths = std::vector<QString>();
	const auto was = _entries.size();
	_entries.erase(
		ranges::remove_if(_entries, [&](const auto &entry) {
			if (!matches(entry.first, entry.second.meta)) {
				return false;
			} else if (entry.second.file) {
				AppendRecordPaths(paths, _folder, entry.second.file);
			}
			return true;
		}),
		end(_entries));
	if (_entries.size() == was) {
		return false;
	}
	ScheduleRemoveFiles(std::move(paths));
	writeIndex();
	return true;
}

void StorageDisk::flush() {
	if (_indexDirty) {
		writeIndex();
	}
}

void StorageDisk::erase() {
	_entries.clear();
	_indexDirty = false;
	EraseStorageFolder(_folder);
}

bool StorageDisk::readIndex() {
	auto file = FileReadDescriptor();
	if (!ReadEncryptedFile(file, kIndexName, _folder, _key)) {
		return false;
	}
	auto entries = base::flat_map<FullMsgId, Entry>();
	const auto add = [&](
			FullMsgId key,
			Storage::FileKey storageFile,
			StorageMeta meta,
			HeightRecord height) {
		return entries.emplace(key, Entry{ storageFile, meta, height }).second;
	};
	if (!ReadIndex(file.stream, _owner, add)) {
		return false;
	}
	_entries = std::move(entries);
	return true;
}

void StorageDisk::cleanup(const QStringList &names) {
	auto list = std::vector<QString>();
	list.reserve(_entries.size());
	for (const auto &[key, entry] : _entries) {
		if (entry.file) {
			list.push_back(ToFilePart(entry.file));
		}
	}
	const auto files = base::flat_set<QString>(begin(list), end(list));
	auto present = std::vector<QString>();
	auto orphans = std::vector<QString>();
	for (const auto &name : names) {
		if (IndexFile(name)) {
			continue;
		}
		const auto stem = name.left(kFileNameSize);
		if (HasSuffix(name, kFileNameSize) && files.contains(stem)) {
			present.push_back(stem);
		} else {
			orphans.push_back(_folder + name);
		}
	}
	ScheduleRemoveFiles(std::move(orphans));
	const auto kept = base::flat_set<QString>(begin(present), end(present));
	const auto was = _entries.size();
	_entries.erase(
		ranges::remove_if(_entries, [&](const auto &entry) {
			const auto file = entry.second.file;
			return file && !kept.contains(ToFilePart(file));
		}),
		end(_entries));
	if (_entries.size() != was) {
		writeIndex();
	}
}

void StorageDisk::writeIndex() {
	_indexDirty = false;
	auto data = EncryptedDescriptor(
		Reserve(kIndexHeaderSize + _entries.size() * kIndexEntrySize));
	data.stream
		<< quint32(kIndexVersion)
		<< quint64(_owner)
		<< quint32(_entries.size());
	for (const auto &[key, entry] : _entries) {
		const auto &meta = entry.meta;
		data.stream
			<< quint64(SerializePeerId(key.peer))
			<< qint64(key.msg.bare)
			<< quint64(entry.file)
			<< qint32(meta.date)
			<< qint32(meta.expires)
			<< qint64(meta.topicRootId.bare)
			<< quint64(SerializePeerId(meta.sublistPeerId))
			<< quint64(SerializePeerId(meta.from))
			<< double(entry.height.height)
			<< quint32(entry.height.bottom ? 1 : 0);
	}
	auto file = FileWriteDescriptor(kIndexName, _folder);
	file.writeEncrypted(data, _key);
}

void StorageDisk::writeRecord(Storage::FileKey file, const Area &local) {
	auto size = kRecordHeaderSize;
	for (const auto &[key, value] : local) {
		size += kPairSize + key.size() + value.size();
	}
	auto data = EncryptedDescriptor(Reserve(size));
	data.stream << quint32(kRecordVersion) << quint32(local.size());
	for (const auto &[key, value] : local) {
		data.stream
			<< QByteArray::fromStdString(key)
			<< QByteArray::fromStdString(value);
	}
	auto descriptor = FileWriteDescriptor(file, _folder);
	descriptor.writeEncrypted(data, _key);
}

Storage::FileKey StorageDisk::generateFile() const {
	auto result = Storage::FileKey();
	do {
		result = GenerateKey(_folder);
	} while (ranges::any_of(_entries, [&](const auto &entry) {
		return (entry.second.file == result);
	}));
	return result;
}

} // namespace Tgw
