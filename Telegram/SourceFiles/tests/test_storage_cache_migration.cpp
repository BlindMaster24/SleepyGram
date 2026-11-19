// This is the source code of AyuGram for Desktop.
#include "storage/details/storage_cache_migration.h"

#include "storage/cache/storage_cache_binlog_reader.h"
#include "storage/details/storage_native_path.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMap>
#include <QtCore/QTemporaryDir>
#include <xxhash.h>

#include <cstdio>
#include <filesystem>

namespace {

using namespace Storage;
using namespace Storage::Cache::details;
using namespace Storage::details;

using Result = CacheMigrationResult;

int Failures = 0;

void Check(bool passed, const char *name) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
	Failures += !passed;
}

EncryptionKey Key(char fill) {
	return EncryptionKey(bytes::vector(EncryptionKey::kSize, bytes::type(fill)));
}

bool Write(const QString &path, QByteArray data, const EncryptionKey &key) {
	auto output = File();
	return output.open(path, File::Mode::Write, key) == File::Result::Success
		&& output.writeWithPadding(bytes::make_detached_span(data))
		&& output.flush();
}

bool WriteRaw(const QString &path, const QByteArray &bytes) {
	auto file = QFile(path);
	return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size();
}

bool WriteCache(
		const QString &root,
		const EncryptionKey &key,
		const QByteArray &payload,
		int version,
		bool explicitVersion,
		bool compactReady) {
	const auto branch = root + '/' + QString::number(version);
	const auto blob = branch + u"/10/203040506070"_q;
	if ((explicitVersion && !WriteVersionValue(root + '/', version))
		|| !Write(blob, payload, key)) {
		return false;
	}
	auto binlog = File();
	const auto path = branch + (compactReady ? u"/binlog-ready"_q : u"/binlog"_q);
	auto header = BasicHeader();
	header.flags = header.kTrackEstimatedTime;
	header.systemTime = 200;
	auto store = StoreWithTime();
	store.key = { 1, 42 };
	store.place = { 1, 2, 3, 4, 5, 6, 7 };
	store.setSize(payload.size());
	store.checksum = XXH32(payload.constData(), payload.size(), 0);
	return binlog.open(path, File::Mode::Write, key) == File::Result::Success
		&& binlog.write(bytes::object_as_span(&header))
		&& binlog.write(bytes::object_as_span(&store))
		&& binlog.flush();
}

QByteArray ReadRaw(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

QMap<QString, QByteArray> Snapshot(const QString &directory) {
	auto result = QMap<QString, QByteArray>();
	auto iter = QDirIterator(directory, QDir::Files, QDirIterator::Subdirectories);
	while (iter.hasNext()) {
		const auto name = iter.next();
		result.insert(name.mid(directory.size()), ReadRaw(name));
	}
	return result;
}

struct Fixture {
	QTemporaryDir temporary;
	QString base = QDir(temporary.path()).canonicalPath();
	QString source = base + u"/user_legacy"_q;
	QString stage = base + u"/stage"_q;
	QString target = stage + u"/user"_q;
	EncryptionKey oldKey = Key(0x1A);
	EncryptionKey newKey = Key(0x2B);

	bool setup() {
		return temporary.isValid() && QDir().mkpath(stage);
	}

	Result run(bool write, CacheMigrationInventory *inventory = nullptr) {
		return CompareAccountCachesForMigration(
			source, target, oldKey, newKey, write, inventory);
	}
};

void CheckRoundTrip() {
	auto fixture = Fixture();
	const auto body = QByteArray(300 * 1024 + 3, 'p');
	const auto normal = fixture.source + u"/cache"_q;
	const auto media = fixture.source + u"/media_cache"_q;
	if (!fixture.setup()
		|| !WriteCache(normal, fixture.oldKey, body, 0, false, false)
		|| !WriteCache(media, fixture.oldKey, QByteArray("media"), 2, true, true)
		|| !Write(media + u"/1/binlog-temp"_q, QByteArray("inactive compaction"), fixture.oldKey)) {
		Check(false, "construct real encrypted cache fixtures");
		return;
	}
	const auto before = Snapshot(fixture.source);
	auto inventory = CacheMigrationInventory();
	const auto staged = fixture.run(true, &inventory);
	Check(staged == Result::Success
		&& inventory.files.contains(u"cache/0/binlog"_q)
		&& inventory.files.contains(u"media_cache/2/binlog-ready"_q)
		&& inventory.files.contains(u"media_cache/1/binlog-temp"_q)
		&& inventory.directories.contains(u"cache/0/10"_q),
		"ordinary and media caches preserve active and old generation inventory");
	if (staged != Result::Success) {
		return;
	}
	const auto file = fixture.target + u"/cache/0/10/203040506070"_q;
	auto current = File();
	auto stale = File();
	auto read = QByteArray(body.size(), Qt::Uninitialized);
	Check(current.open(file, File::Mode::Read, fixture.newKey) == File::Result::Success
		&& current.readWithPadding(bytes::make_detached_span(read)) == read.size()
		&& read == body
		&& stale.open(file, File::Mode::Read, fixture.oldKey) == File::Result::WrongKey,
		"scoped key reads the complete padded payload while legacy key fails");
	Check(ReadRaw(file) != before.value(u"/cache/0/10/203040506070"_q)
		&& before == Snapshot(fixture.source),
		"ciphertext changes and every legacy file remains byte-for-byte intact");
	Check(!QFileInfo::exists(fixture.target + u"/cache/version"_q)
		&& ReadVersionValue(fixture.target + u"/media_cache/"_q) == 2,
		"versionless active generation zero and explicit version both preserved");
	Check(WriteRaw(fixture.target + u"/archive.db"_q, "stand-in archive")
		&& fixture.run(false) == Result::Success
		&& ReadRaw(fixture.target + u"/archive.db"_q) == "stand-in archive",
		"readback accepts a separately handled archive without changing it");
	const auto bad = fixture.target + u"/cache/0/10/203040506070"_q;
	current.close();
	stale.close();
	Check(Write(bad, QByteArray(body.size(), 'q'), fixture.newKey)
		&& fixture.run(false) == Result::VerificationFailed,
		"readback detects a valid new-key envelope with different payload");
}

void CheckUnsafeSource() {
	auto fixture = Fixture();
	const auto root = fixture.source + u"/cache"_q;
	if (!fixture.setup()
		|| !WriteCache(root, fixture.oldKey, QByteArray("legacy payload"), 0, false, false)) {
		Check(false, "construct unsafe-source fixture");
		return;
	}
	const auto extra = root + u"/0/unexplained"_q;
	Check(WriteRaw(extra, "user data")
		&& fixture.run(true) == Result::UnsupportedSource
		&& !QFileInfo::exists(fixture.target), "unknown cache file blocks staging");
	Check(QFile::remove(extra), "remove synthetic unexpected file");
	const auto payload = root + u"/0/10/203040506070"_q;
	Check(Write(payload, "edited payload", fixture.oldKey)
		&& fixture.run(true) == Result::InvalidSource
		&& !QFileInfo::exists(fixture.target), "active binlog checksum detects corrupt blob");
	Check(QFile::remove(payload)
		&& fixture.run(true) == Result::InvalidSource
		&& !QFileInfo::exists(fixture.target), "active binlog cannot reference a missing blob");
}

void CheckEmpty() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "construct empty cache fixture");
		return;
	}
	Check(fixture.run(true) == Result::Success
		&& fixture.run(false) == Result::Success
		&& !QFileInfo::exists(fixture.target), "empty legacy cache needs no new directory");
	Check(CompareAccountCachesForMigration(
		fixture.source, fixture.target, fixture.oldKey, fixture.oldKey, true)
		== Result::InvalidKeys, "legacy key reuse is rejected even for empty cache");
}

void CheckArchivePaths() {
	auto fixture = Fixture();
	const auto root = fixture.source + u"/cache"_q;
	const auto outside = fixture.base + u"/outside"_q;
	if (!fixture.setup()
		|| !WriteRaw(outside, "unrelated file")
		|| !WriteCache(root, fixture.oldKey, "payload", 0, false, false)) {
		Check(false, "construct linked cache fixture");
		return;
	}
	const auto blob = root + u"/0/10/203040506070"_q;
	const auto outsideNative = NativeFilePath(QFileInfo(outside).filePath());
	const auto blobNative = NativeFilePath(QFileInfo(blob).filePath());
	auto error = std::error_code();
	if (!QFile::remove(blob)) {
		Check(false, "replace the synthetic cache blob");
		return;
	}
	std::filesystem::create_hard_link(outsideNative, blobNative, error);
	Check(!error && fixture.run(true) == Result::UnsupportedSource
		&& ReadRaw(outside) == "unrelated file"
		&& !QFileInfo::exists(fixture.target), "hard links cannot expand cache scope");
#if !defined Q_OS_WIN
	if (!QFile::remove(blob)) {
		Check(false, "remove synthetic hard link");
		return;
	}
	std::filesystem::create_symlink(outsideNative, blobNative, error);
	Check(!error && fixture.run(true) == Result::UnsupportedSource
		&& ReadRaw(outside) == "unrelated file"
		&& !QFileInfo::exists(fixture.target), "symlinks cannot expand cache scope");
#endif
}

} // namespace

int main(int argc, char *argv[]) {
	const auto app = QCoreApplication(argc, argv);
	CheckRoundTrip();
	CheckUnsafeSource();
	CheckEmpty();
	CheckArchivePaths();
	return Failures ? 1 : 0;
}
