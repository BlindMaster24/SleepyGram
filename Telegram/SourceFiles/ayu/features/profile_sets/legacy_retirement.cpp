// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/legacy_retirement.h"

#include "base/basic_types.h"
#include "storage/details/storage_cache_migration_paths.h"
#include "storage/details/storage_native_path.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>

#include <algorithm>
#include <array>
#include <filesystem>
#include <limits>
#include <map>
#include <set>
#include <utility>

#if defined Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu::ProfileSets {
namespace {

constexpr auto kTransactionIdSize = 16;
constexpr auto kPlanVersion = 1;
constexpr auto kPreserveWebviewPlanVersion = 2;
constexpr auto kVerifiedWalletPlanVersion = 3;
constexpr auto kVerifiedWalletPreserveWebviewPlanVersion = 4;
constexpr auto kMaximumAccounts = 200;
constexpr auto kMaximumEntries = 60'000;
constexpr auto kMaximumPlanBytes = 16 * 1024 * 1024;
constexpr auto kMaximumFileBytes = 65LL * 1024 * 1024;
constexpr auto kEntries = QDir::AllEntries
	| QDir::NoDotAndDotDot
	| QDir::Hidden
	| QDir::System;
constexpr auto kSuffixes = std::array{ 's', '0', '1' };
const auto kLegacyArchiveFiles = std::array{
	u"ayudata.db"_q,
	u"ayudata.db-wal"_q,
	u"ayudata.db-shm"_q,
};
const auto kLegacyArchiveJournal = u"ayudata.db-journal"_q;
const auto kLegacyAyuPreferences = u"ayu_settings.json"_q;
const auto kLegacyOffline = u"offline-history"_q;

using Entry = LegacyRetirementEntry;
using Plan = LegacyRetirementPlan;
using CachePathKind = Storage::details::CacheMigrationPathKind;
using Storage::details::ClassifyCacheMigrationPath;
using OfflineKind = OfflineHistory::LegacyOfflinePathKind;
using OfflineHistory::ClassifyLegacyOfflinePath;

enum class DirectoryKind : uchar {
	Account,
	Tgw,
	Database,
	Offline,
	Empty,
};

struct Layout final {
	std::map<QString, DirectoryKind> directories;
	std::set<QString> rootStems;
	QString walletStem;
};

bool CanonicalDirectory(const QString &path) {
	const auto info = QFileInfo(path);
	return info.isDir()
		&& !info.isSymLink()
		&& !info.isJunction()
		&& info.canonicalFilePath() == path
		&& QDir(path).isReadable();
}

bool Present(const QFileInfo &info) {
	return info.exists() || info.isSymLink() || info.isJunction();
}

bool ValidName(const QString &name) {
	return !name.isEmpty()
		&& name.size() <= 120
		&& !name.endsWith('.')
		&& !name.endsWith(' ')
		&& std::ranges::none_of(name, [](QChar ch) {
			return ch.unicode() < 32 || u"/\\:\"<>|?*"_q.contains(ch);
		});
}

bool ValidTransactionId(const QByteArray &id) {
	return id.size() == kTransactionIdSize
		&& std::ranges::any_of(id, [](char byte) { return byte != 0; });
}

bool LegacyArchiveFile(const QString &name) {
	return std::ranges::find(kLegacyArchiveFiles, name) != end(kLegacyArchiveFiles);
}

qint64 MaximumFileBytes(const QString &relative) {
	if (relative == kLegacyAyuPreferences) {
		return 16 * 1024 * 1024;
	}
	if (relative.startsWith(kLegacyOffline + '/')) {
		switch (ClassifyLegacyOfflinePath(relative)) {
		case OfflineKind::Snapshot: return 64 * 1024 * 1024;
		case OfflineKind::Manifest: return 8 * 1024 * 1024;
		case OfflineKind::Attachment: return 25 * 1024 * 1024;
		default: return 0;
		}
	}
	const auto slash = relative.indexOf('/');
	return (LegacyArchiveFile(relative)
		|| (slash >= 0 && relative.startsWith(u"user_"_q)
			&& ClassifyCacheMigrationPath(QStringView(relative).mid(slash + 1))
				== CachePathKind::Encrypted))
		? std::numeric_limits<qint64>::max()
		: kMaximumFileBytes;
}

bool ValidFileName(const QString &name, DirectoryKind kind) {
	if (name.isEmpty() || !std::ranges::any_of(kSuffixes, [&](char suffix) {
		return name.back() == suffix;
	})) {
		return false;
	}
	const auto stem = name.chopped(1);
	if (kind != DirectoryKind::Account && kind != DirectoryKind::Tgw) {
		return false;
	} else if (kind == DirectoryKind::Account
		&& (stem == u"map"_q || stem == u"config"_q)) {
		return true;
	} else if (kind == DirectoryKind::Tgw && stem == u"index"_q) {
		return true;
	}
	return stem.size() == 16 && std::ranges::all_of(stem, [](QChar ch) {
		return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F');
	});
}

std::optional<Layout> BuildLayout(const Plan &plan) {
	if (!ValidName(plan.dataName)
		|| !ValidTransactionId(plan.transactionId)
		|| !QDir::isAbsolutePath(plan.dataDirectory)
		|| plan.dataDirectory.startsWith(':')
		|| plan.dataDirectory.contains(QChar(0))
		|| QDir::cleanPath(plan.dataDirectory) != plan.dataDirectory
		|| QFileInfo(plan.dataDirectory).fileName().isEmpty()
		|| (plan.webview != Storage::LegacyWebviewTransfer::RequireIsolated
			&& plan.webview != Storage::LegacyWebviewTransfer::StartFresh)
		|| plan.accountIndices.empty()
		|| plan.accountIndices.size() > kMaximumAccounts) {
		return std::nullopt;
	}
	auto result = Layout();
	result.directories.emplace(kLegacyOffline, DirectoryKind::Offline);
	result.rootStems.emplace(u"key_"_q + plan.dataName);
	if (plan.walletInventoryVerified) {
		result.walletStem = u"wallet_keyring_"_q + plan.dataName;
	}
	auto current = -1;
	for (const auto index : plan.accountIndices) {
		if (index <= current || index >= kMaximumAccounts) {
			return std::nullopt;
		}
		current = index;
		const auto name = Storage::AccountDataName(plan.dataName, index);
		const auto account = Storage::AccountPathsForDataName(
			plan.dataDirectory, name);
		const auto auth = QFileInfo(account.authPath).fileName();
		if (!ValidName(name) || !result.rootStems.emplace(auth).second
			|| !result.directories.emplace(auth, DirectoryKind::Account).second
			|| !result.directories.emplace(auth + u"/tgw"_q, DirectoryKind::Tgw).second
			|| !result.directories.emplace(
				u"temp_"_q + name, DirectoryKind::Empty).second
			|| !result.directories.emplace(
				u"user_"_q + name, DirectoryKind::Database).second) {
			return std::nullopt;
		}
	}
	return result;
}

bool PreserveWebviewRoot(
		const Plan &plan,
		const Layout &layout,
		const QString &relative) {
	const auto directory = layout.directories.find(relative);
	return plan.webview == Storage::LegacyWebviewTransfer::StartFresh
		&& directory != end(layout.directories) && directory->second == DirectoryKind::Database;
}

CachePathKind DatabaseEntryKind(const Layout &layout, const QString &path) {
	const auto slash = path.indexOf('/');
	if (slash < 0) {
		return CachePathKind::Invalid;
	}
	const auto directory = layout.directories.find(path.left(slash));
	return (directory != end(layout.directories)
		&& directory->second == DirectoryKind::Database)
		? ClassifyCacheMigrationPath(QStringView(path).mid(slash + 1))
		: CachePathKind::Invalid;
}

bool ValidEntries(const Plan &plan, const Layout &layout) {
	if (plan.entries.empty() || plan.entries.size() > kMaximumEntries) {
		return false;
	}
	auto directories = std::set<QString>();
	auto stems = std::set<QString>();
	auto archiveFiles = std::set<QString>();
	auto previous = QString();
	for (const auto &entry : plan.entries) {
		const auto &path = entry.relativePath;
		if (path <= previous) {
			return false;
		}
		previous = path;
		const auto slash = path.lastIndexOf('/');
		const auto parent = (slash >= 0) ? path.left(slash) : QString();
		if (!parent.isEmpty() && !directories.contains(parent)) {
			return false;
		}
		const auto database = DatabaseEntryKind(layout, path);
		const auto offline = ClassifyLegacyOfflinePath(path);
		if (entry.sha256.isEmpty()) {
			if (!layout.directories.contains(path)
				&& database != CachePathKind::Directory
				&& offline != OfflineKind::Directory) {
				return false;
			}
			directories.emplace(path);
			continue;
		} else if (entry.sha256.size() != 32 || path.isEmpty()) {
			return false;
		}
		if (database == CachePathKind::Version
			|| database == CachePathKind::Encrypted
			|| offline == OfflineKind::Snapshot
			|| offline == OfflineKind::Manifest
			|| offline == OfflineKind::Attachment) {
			continue;
		}
		if (slash < 0) {
			if (path == kLegacyAyuPreferences) {
				continue;
			}
			if (LegacyArchiveFile(path)) {
				archiveFiles.emplace(path);
				continue;
			}
			if ((!layout.rootStems.contains(path.chopped(1))
					&& (layout.walletStem.isEmpty() || path.chopped(1) != layout.walletStem))
				|| !std::ranges::any_of(kSuffixes, [&](char suffix) {
					return path.back() == suffix;
				})) {
				return false;
			}
		} else {
			const auto kind = layout.directories.find(parent);
			if (kind == end(layout.directories)
				|| !ValidFileName(path.mid(slash + 1), kind->second)) {
				return false;
			}
		}
		stems.emplace(path.chopped(1));
	}
	return (archiveFiles.empty()
			|| archiveFiles.contains(kLegacyArchiveFiles.front()))
		&& std::ranges::all_of(layout.rootStems, [&](const QString &stem) {
			return stems.contains(stem);
		})
		&& std::ranges::all_of(layout.directories, [&](const auto &directory) {
			return directory.second != DirectoryKind::Account
				|| stems.contains(directory.first + u"/map"_q);
		});
}

bool MatchesPaths(
		const Storage::AccountPaths &actual,
		const Storage::AccountPaths &expected) {
	return actual.mode == Storage::AccountStorageMode::Legacy
		&& actual.dataNameKey == expected.dataNameKey
		&& actual.authPath == expected.authPath
		&& actual.basePath == expected.basePath
		&& actual.tempPath == expected.tempPath
		&& actual.databasePath == expected.databasePath;
}

std::optional<QStringList> ListExactDirectory(
		const QString &path,
		QStringList expected,
		bool preserveWebview) {
	std::ranges::sort(expected);
	if (std::adjacent_find(expected.cbegin(), expected.cend()) != expected.cend()) {
		return std::nullopt;
	}
	if (!Present(QFileInfo(path))) {
		return expected.isEmpty() ? std::optional(QStringList()) : std::nullopt;
	}
	if (!CanonicalDirectory(path)) {
		return std::nullopt;
	}
	auto entries = QDir(path).entryList(kEntries);
	if (preserveWebview) {
		entries.removeAll(u"wvbots"_q);
		entries.removeAll(u"wvother"_q);
	}
	std::ranges::sort(entries);
	return (entries == expected) ? std::optional(std::move(entries)) : std::nullopt;
}

std::optional<QByteArray> Fingerprint(
		const QString &path,
		const QString &relative) {
	const auto info = QFileInfo(path);
	auto error = std::error_code();
	if (!info.isFile() || info.isSymLink() || info.isJunction()
		|| info.canonicalFilePath() != path
		|| info.size() < 0 || info.size() > MaximumFileBytes(relative)
		|| std::filesystem::hard_link_count(Storage::NativeFilePath(info.filePath()), error) != 1
		|| error) {
		return std::nullopt;
	}
	auto file = QFile(path);
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	return (file.open(QIODevice::ReadOnly) && hash.addData(&file)
		&& file.pos() == info.size())
		? std::optional(hash.result())
		: std::nullopt;
}

bool AppendDirectory(
		Plan &plan,
		const QString &relative,
		QStringList expected,
		bool preserveWebview = false) {
	const auto path = plan.dataDirectory + '/' + relative;
	if (!ListExactDirectory(path, std::move(expected), preserveWebview)) {
		return false;
	}
	if (Present(QFileInfo(path))) {
		if (plan.entries.size() >= kMaximumEntries) {
			return false;
		}
		plan.entries.push_back({ .relativePath = relative });
	}
	return true;
}

bool AppendFile(Plan &plan, QString relative) {
	const auto hash = Fingerprint(plan.dataDirectory + '/' + relative, relative);
	if (!hash || plan.entries.size() >= kMaximumEntries) {
		return false;
	}
	plan.entries.push_back({ std::move(relative), *hash });
	return true;
}

bool AppendDatabase(
		Plan &plan,
		const QString &base,
		const VerifiedLegacyRetirementAccount &account) {
	auto expected = std::map<QString, QStringList>{ { QString(), {} } };
	for (const auto &directory : account.cacheDirectories) {
		if (ClassifyCacheMigrationPath(directory) != CachePathKind::Directory
			|| !expected.emplace(directory, QStringList()).second) {
			return false;
		}
	}
	const auto record = [&](const QString &relative) {
		const auto slash = relative.lastIndexOf('/');
		const auto parent = (slash < 0) ? QString() : relative.left(slash);
		const auto found = expected.find(parent);
		if (found == end(expected)) {
			return false;
		}
		found->second.push_back(relative.mid(slash + 1));
		return true;
	};
	for (const auto &directory : account.cacheDirectories) {
		if (!record(directory)) {
			return false;
		}
	}
	for (const auto &file : account.cacheFiles) {
		const auto kind = ClassifyCacheMigrationPath(file);
		if ((kind != CachePathKind::Version && kind != CachePathKind::Encrypted)
			|| !record(file)) {
			return false;
		}
	}
	for (auto &[directory, children] : expected) {
		const auto relative = directory.isEmpty() ? base : (base + '/' + directory);
		const auto preserveWebview = directory.isEmpty()
			&& plan.webview == Storage::LegacyWebviewTransfer::StartFresh;
		if ((!directory.isEmpty() && !Present(QFileInfo(plan.dataDirectory + '/' + relative)))
			|| !AppendDirectory(plan, relative, std::move(children), preserveWebview)) {
			return false;
		}
	}
	for (const auto &file : account.cacheFiles) {
		if (!AppendFile(plan, base + '/' + file)) {
			return false;
		}
	}
	return true;
}

bool AppendSuffixedFiles(Plan &plan, const QString &stem) {
	auto found = false;
	for (const auto suffix : kSuffixes) {
		const auto relative = stem + suffix;
		if (!Present(QFileInfo(plan.dataDirectory + '/' + relative))) {
			continue;
		} else if (!AppendFile(plan, relative)) {
			return false;
		}
		found = true;
	}
	return found;
}

bool AppendLegacyArchive(Plan &plan, LegacyArchiveRetirement archive) {
	const auto hasMain = Present(QFileInfo(
		plan.dataDirectory + '/' + kLegacyArchiveFiles.front()));
	const auto partitioned = archive == LegacyArchiveRetirement::VerifiedPartitioned;
	if ((!partitioned && archive != LegacyArchiveRetirement::ExpectedAbsent)
		|| hasMain != partitioned
		|| Present(QFileInfo(plan.dataDirectory + '/' + kLegacyArchiveJournal))) {
		return false;
	}
	for (const auto &file : kLegacyArchiveFiles) {
		if (Present(QFileInfo(plan.dataDirectory + '/' + file))
			&& (!partitioned || !AppendFile(plan, file))) {
			return false;
		}
	}
	return true;
}

bool AppendAyuPreferences(Plan &plan, const QByteArray &verified) {
	const auto path = plan.dataDirectory + '/' + kLegacyAyuPreferences;
	if (verified.isEmpty()) {
		return !Present(QFileInfo(path));
	}
	return verified.size() == 32
		&& AppendFile(plan, kLegacyAyuPreferences)
		&& plan.entries.back().sha256 == verified;
}

bool AppendOffline(
		Plan &plan,
		std::span<const OfflineHistory::LegacyOfflineEntry> verified) {
	const auto root = plan.dataDirectory + '/' + kLegacyOffline;
	if (verified.empty()) {
		return !Present(QFileInfo(root));
	}
	if (verified.size() > kMaximumEntries - plan.entries.size()) {
		return false;
	}
	auto entries = std::set<QString>();
	auto directories = std::map<QString, QStringList>();
	for (const auto &entry : verified) {
		const auto kind = ClassifyLegacyOfflinePath(entry.relativePath);
		const auto isDirectory = (kind == OfflineKind::Directory);
		if (kind == OfflineKind::Invalid
			|| (entry.sha256.size() != (isDirectory ? 0 : 32))
			|| !entries.emplace(entry.relativePath).second) {
			return false;
		}
		if (isDirectory) {
			directories.emplace(entry.relativePath, QStringList());
		}
	}
	if (!directories.contains(kLegacyOffline)) {
		return false;
	}
	for (const auto &entry : verified) {
		const auto &path = entry.relativePath;
		if (path == kLegacyOffline) {
			continue;
		}
		const auto slash = path.lastIndexOf('/');
		const auto parent = directories.find(path.left(slash));
		if (parent == end(directories)) {
			return false;
		}
		parent->second.push_back(path.mid(slash + 1));
	}
	for (auto &[path, children] : directories) {
		if (!CanonicalDirectory(plan.dataDirectory + '/' + path)
			|| !AppendDirectory(plan, path, std::move(children))) {
			return false;
		}
	}
	for (const auto &entry : verified) {
		if (!entry.sha256.isEmpty()
			&& (!AppendFile(plan, entry.relativePath)
				|| plan.entries.back().sha256 != entry.sha256)) {
			return false;
		}
	}
	return true;
}

bool MatchesCurrentSource(const Plan &plan, const Layout &layout) {
	if (!CanonicalDirectory(plan.dataDirectory)) {
		return false;
	}
	auto byPath = std::map<QString, const Entry*>();
	for (const auto &entry : plan.entries) {
		byPath.emplace(entry.relativePath, &entry);
	}
	if (Present(QFileInfo(plan.dataDirectory + '/' + kLegacyAyuPreferences))
		&& !byPath.contains(kLegacyAyuPreferences)) {
		return false;
	}
	if (Present(QFileInfo(plan.dataDirectory + '/' + kLegacyArchiveJournal))) {
		return false;
	}
	for (const auto &file : kLegacyArchiveFiles) {
		if (Present(QFileInfo(plan.dataDirectory + '/' + file))
			&& !byPath.contains(file)) {
			return false;
		}
	}
	for (const auto &[directory, kind] : layout.directories) {
		if (Present(QFileInfo(plan.dataDirectory + '/' + directory))
			&& !byPath.contains(directory)) {
			return false;
		}
	}
	for (const auto &entry : plan.entries) {
		if (!entry.sha256.isEmpty()) {
			continue;
		}
		const auto &directory = entry.relativePath;
		const auto path = plan.dataDirectory + '/' + directory;
		if (!Present(QFileInfo(path))) {
			continue;
		} else if (!CanonicalDirectory(path)) {
			return false;
		}
		for (const auto &name : QDir(path).entryList(kEntries)) {
			if (PreserveWebviewRoot(plan, layout, directory)
				&& Storage::IsLegacyWebviewDirectoryName(name)) {
				continue;
			}
			if (!byPath.contains(directory + '/' + name)) {
				return false;
			}
		}
	}
	for (const auto &stem : layout.rootStems) {
		for (const auto suffix : kSuffixes) {
			const auto relative = stem + suffix;
			if (Present(QFileInfo(plan.dataDirectory + '/' + relative))
				&& !byPath.contains(relative)) {
				return false;
			}
		}
	}
	if (!layout.walletStem.isEmpty()) {
		for (const auto suffix : kSuffixes) {
			const auto relative = layout.walletStem + suffix;
			if (Present(QFileInfo(plan.dataDirectory + '/' + relative))
				&& !byPath.contains(relative)) {
				return false;
			}
		}
	}
	for (const auto &entry : plan.entries) {
		const auto path = plan.dataDirectory + '/' + entry.relativePath;
		if (!entry.sha256.isEmpty() && Present(QFileInfo(path))
			&& Fingerprint(path, entry.relativePath) != entry.sha256) {
			return false;
		}
	}
	return true;
}

#if defined Q_OS_WIN

class NativeHandle final {
public:
	explicit NativeHandle(HANDLE value) : _value(value) {}
	NativeHandle(NativeHandle &&other) noexcept
	: _value(std::exchange(other._value, INVALID_HANDLE_VALUE)) {}
	~NativeHandle() {
		if (valid()) {
			CloseHandle(_value);
		}
	}
	[[nodiscard]] HANDLE get() const {
		return _value;
	}
	[[nodiscard]] bool valid() const {
		return _value != INVALID_HANDLE_VALUE;
	}

private:
	HANDLE _value = INVALID_HANDLE_VALUE;

};

NativeHandle OpenNativeEntry(const std::filesystem::path &path, DWORD access) {
	return NativeHandle(CreateFileW(
		path.c_str(),
		access,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr));
}

std::optional<BY_HANDLE_FILE_INFORMATION> NativeInfo(const NativeHandle &handle) {
	auto info = BY_HANDLE_FILE_INFORMATION{};
	return handle.valid()
		&& GetFileType(handle.get()) == FILE_TYPE_DISK
		&& GetFileInformationByHandle(handle.get(), &info)
		&& !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		? std::optional(info)
		: std::nullopt;
}

bool MatchesNativeFile(
		const NativeHandle &handle,
		const BY_HANDLE_FILE_INFORMATION &info,
		const Entry &entry) {
	const auto size = (quint64(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
	if (info.nNumberOfLinks != 1 || size > quint64(MaximumFileBytes(entry.relativePath))) {
		return false;
	}
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	auto buffer = std::array<char, 64 * 1024>();
	auto remaining = size;
	while (remaining) {
		auto read = DWORD();
		if (!ReadFile(
			handle.get(),
			buffer.data(),
			DWORD(std::min<quint64>(remaining, buffer.size())),
			&read,
			nullptr) || !read) {
			return false;
		}
		remaining -= read;
		hash.addData(QByteArrayView(buffer.data(), read));
	}
	return hash.result() == entry.sha256;
}

bool RemoveNativeEntry(const QString &root, const Entry &entry) {
	auto target = Storage::NativeFilePath(QFileInfo(root + '/' + entry.relativePath).filePath());
	target.make_preferred();
	const auto drive = target.root_name().native();
	if (drive.size() != 2 || drive[1] != L':') {
		return false;
	}
	auto current = std::filesystem::path(L"\\\\?\\" + target.root_path().native());
	auto parents = std::vector<NativeHandle>();
	const auto pin = [&] {
		auto handle = OpenNativeEntry(current, FILE_READ_ATTRIBUTES);
		const auto info = NativeInfo(handle);
		if (!info || !(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			return false;
		}
		parents.push_back(std::move(handle));
		return true;
	};
	if (!pin()) {
		return false;
	}
	const auto path = target.parent_path().relative_path();
	for (const auto &part : path) {
		current /= part;
		if (!pin()) {
			return false;
		}
	}
	current /= target.filename();
	const auto isDirectory = entry.sha256.isEmpty();
	const auto handle = OpenNativeEntry(
		current,
		DELETE | FILE_READ_ATTRIBUTES | (isDirectory ? 0 : GENERIC_READ));
	const auto info = NativeInfo(handle);
	if (!info
		|| bool(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != isDirectory
		|| (!isDirectory && !MatchesNativeFile(handle, *info, entry))) {
		return false;
	}
	auto disposition = FILE_DISPOSITION_INFO{ .DeleteFile = TRUE };
	return SetFileInformationByHandle(
		handle.get(),
		FileDispositionInfo,
		&disposition,
		sizeof(disposition));
}

bool SyncRetirementRoot(const QString &) {
	return true;
}

#else

constexpr auto kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

class NativeDescriptor final {
public:
	explicit NativeDescriptor(int fd) : _fd(fd) {}
	NativeDescriptor(const NativeDescriptor &) = delete;
	NativeDescriptor &operator=(const NativeDescriptor &) = delete;
	~NativeDescriptor() {
		reset(-1);
	}
	void reset(int fd) {
		if (_fd >= 0) {
			close(_fd);
		}
		_fd = fd;
	}
	[[nodiscard]] int get() const {
		return _fd;
	}

private:
	int _fd = -1;

};

QByteArray MountId([[maybe_unused]] int fd) {
#if defined __linux__
	auto file = QFile(u"/proc/self/fdinfo/"_q + QString::number(fd));
	if (file.open(QIODevice::ReadOnly)) {
		for (auto line = file.readLine(); !line.isEmpty(); line = file.readLine()) {
			if (line.startsWith("mnt_id:")) {
				return line;
			}
		}
	}
#endif
	return {};
}

bool SameNativeEntry(const struct stat &a, const struct stat &b) {
	return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode;
}

bool MatchesNativeFile(
		int fd,
		const struct stat &info,
		const Entry &entry) {
	if (!S_ISREG(info.st_mode)
		|| info.st_nlink != 1 || info.st_size < 0
		|| info.st_size > MaximumFileBytes(entry.relativePath)) {
		return false;
	}
	auto file = QFile();
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	return file.open(fd, QIODevice::ReadOnly)
		&& hash.addData(&file)
		&& file.pos() == info.st_size
		&& hash.result() == entry.sha256;
}

bool OpenNativeRoot(const QString &root, NativeDescriptor &rootFd) {
	rootFd.reset(open("/", kDirectoryFlags));
	const auto path = Storage::NativeFilePath(QFileInfo(root).filePath());
	for (const auto &part : path.relative_path()) {
		rootFd.reset(openat(rootFd.get(), part.c_str(), kDirectoryFlags));
		if (rootFd.get() < 0) {
			return false;
		}
	}
	return rootFd.get() >= 0;
}

bool RemoveNativeEntry(const QString &root, const Entry &entry) {
	auto rootFd = NativeDescriptor(-1);
	struct stat rootInfo = {};
	if (!OpenNativeRoot(root, rootFd) || fstat(rootFd.get(), &rootInfo) != 0) {
		return false;
	}
	const auto rootMount = MountId(rootFd.get());
#if defined __linux__
	if (rootMount.isEmpty()) {
		return false;
	}
#endif
	auto current = NativeDescriptor(dup(rootFd.get()));
	const auto relative = Storage::NativeFilePath(QFileInfo(entry.relativePath).filePath());
	for (const auto &part : relative.parent_path()) {
		current.reset(openat(current.get(), part.c_str(), kDirectoryFlags));
		struct stat directory = {};
		if (current.get() < 0 || fstat(current.get(), &directory) != 0
			|| directory.st_dev != rootInfo.st_dev
			|| MountId(current.get()) != rootMount) {
			return false;
		}
	}
	const auto name = relative.filename();
	const auto isDirectory = entry.sha256.isEmpty();
	const auto flags = isDirectory
		? kDirectoryFlags
		: (O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	const auto target = NativeDescriptor(openat(current.get(), name.c_str(), flags));
	struct stat opened = {};
	if (target.get() < 0 || fstat(target.get(), &opened) != 0
		|| opened.st_dev != rootInfo.st_dev
		|| MountId(target.get()) != rootMount
		|| (!isDirectory && !MatchesNativeFile(target.get(), opened, entry))) {
		return false;
	}
	struct stat beforeRemoval = {};
	return fstatat(current.get(), name.c_str(), &beforeRemoval, AT_SYMLINK_NOFOLLOW) == 0
		&& SameNativeEntry(opened, beforeRemoval)
		&& (isDirectory || (beforeRemoval.st_nlink == 1
			&& beforeRemoval.st_size == opened.st_size))
		&& unlinkat(current.get(), name.c_str(), isDirectory ? AT_REMOVEDIR : 0) == 0
		&& fsync(current.get()) == 0;
}

bool SyncRetirementRoot(const QString &root) {
	auto rootFd = NativeDescriptor(-1);
	return OpenNativeRoot(root, rootFd) && fsync(rootFd.get()) == 0;
}

#endif

bool RemoveIfPresent(const QString &root, const Entry &entry) {
	return !Present(QFileInfo(root + '/' + entry.relativePath))
		|| RemoveNativeEntry(root, entry);
}

} // namespace

std::optional<LegacyRetirementPlan> CaptureLegacyRetirementPlan(
		const QString &dataDirectory,
		const QString &dataName,
		const QByteArray &transactionId,
		std::span<const int> legacyAccountIndices,
		std::span<const VerifiedLegacyRetirementAccount> verifiedAccounts,
		LegacyArchiveRetirement archive,
		const QByteArray &verifiedAyuSettingsSha256,
		std::span<const OfflineHistory::LegacyOfflineEntry> verifiedOffline,
		Storage::LegacyWebviewTransfer webview,
		const std::vector<LegacyRetirementEntry> *verifiedWalletFiles) {
	if (legacyAccountIndices.size() != verifiedAccounts.size()
		|| legacyAccountIndices.size() > kMaximumAccounts
		|| !CanonicalDirectory(dataDirectory)) {
		return std::nullopt;
	}
	auto plan = Plan{
		.dataDirectory = dataDirectory,
		.dataName = dataName,
		.transactionId = transactionId,
		.accountIndices = { begin(legacyAccountIndices), end(legacyAccountIndices) },
		.webview = webview,
		.walletInventoryVerified = (verifiedWalletFiles != nullptr),
	};
	std::ranges::sort(plan.accountIndices);
	const auto layout = BuildLayout(plan);
	if (!layout
		|| !AppendSuffixedFiles(plan, u"key_"_q + dataName)
		|| !AppendLegacyArchive(plan, archive)
		|| !AppendAyuPreferences(plan, verifiedAyuSettingsSha256)
		|| !AppendOffline(plan, verifiedOffline)) {
		return std::nullopt;
	}
	auto verified = std::set<int>();
	for (const auto &account : verifiedAccounts) {
		if (!std::ranges::binary_search(plan.accountIndices, account.index)
			|| !verified.emplace(account.index).second) {
			return std::nullopt;
		}
		const auto name = Storage::AccountDataName(dataName, account.index);
		const auto paths = Storage::AccountPathsForDataName(dataDirectory, name);
		const auto auth = QFileInfo(paths.authPath).fileName();
		const auto tgw = auth + u"/tgw"_q;
		auto dataEntries = account.dataFiles;
		const auto hasTgw = Present(QFileInfo(dataDirectory + '/' + tgw));
		if (hasTgw) {
			dataEntries.push_back(u"tgw"_q);
		}
		if (!MatchesPaths(account.paths, paths)
			|| !AppendDirectory(plan, auth, std::move(dataEntries))
			|| !AppendDirectory(plan, tgw, account.tgwFiles)
			|| !AppendDirectory(plan, u"temp_"_q + name, {})
			|| !AppendDatabase(plan, u"user_"_q + name, account)
			|| !AppendSuffixedFiles(plan, auth)) {
			return std::nullopt;
		}
		for (const auto &file : account.dataFiles) {
			if (!ValidFileName(file, DirectoryKind::Account)
				|| !AppendFile(plan, auth + '/' + file)) {
				return std::nullopt;
			}
		}
		for (const auto &file : account.tgwFiles) {
			if (!ValidFileName(file, DirectoryKind::Tgw)
				|| !AppendFile(plan, tgw + '/' + file)) {
				return std::nullopt;
			}
		}
	}
	if (verifiedWalletFiles) {
		auto proofs = std::set<QString>();
		for (const auto &proof : *verifiedWalletFiles) {
			const auto &name = proof.relativePath;
			if (proof.sha256.size() != 32 || !proofs.emplace(name).second) {
				return std::nullopt;
			}
			if (name.chopped(1) == layout->walletStem && !name.isEmpty()
				&& std::ranges::any_of(kSuffixes, [&](char suffix) { return name.back() == suffix; })
				&& !AppendFile(plan, name)) {
				return std::nullopt;
			}
		}
		auto captured = std::map<QString, QByteArray>();
		for (const auto &entry : plan.entries) {
			captured.emplace(entry.relativePath, entry.sha256);
		}
		if (std::ranges::any_of(*verifiedWalletFiles, [&](const auto &proof) {
				const auto found = captured.find(proof.relativePath);
				return found == end(captured) || found->second != proof.sha256;
			}) || !MatchesCurrentSource(plan, *layout)) {
			return std::nullopt;
		}
	}
	std::ranges::sort(plan.entries, {}, &Entry::relativePath);
	return ValidEntries(plan, *layout) ? std::optional(std::move(plan)) : std::nullopt;
}

QByteArray SerializeLegacyRetirementPlan(const LegacyRetirementPlan &plan) {
	const auto layout = BuildLayout(plan);
	if (!layout || !ValidEntries(plan, *layout)) {
		return {};
	}
	auto indices = QJsonArray();
	for (const auto index : plan.accountIndices) {
		indices.append(index);
	}
	auto entries = QJsonArray();
	for (const auto &entry : plan.entries) {
		entries.append(QJsonArray{
			entry.relativePath,
			QString::fromLatin1(entry.sha256.toHex()),
		});
	}
	auto encoded = QJsonDocument(QJsonArray{
		(plan.webview == Storage::LegacyWebviewTransfer::StartFresh)
			? (plan.walletInventoryVerified ? kVerifiedWalletPreserveWebviewPlanVersion : kPreserveWebviewPlanVersion)
			: (plan.walletInventoryVerified ? kVerifiedWalletPlanVersion : kPlanVersion),
		plan.dataDirectory,
		plan.dataName,
		QString::fromLatin1(plan.transactionId.toHex()),
		indices,
		entries,
	}).toJson(QJsonDocument::Compact);
	return (encoded.size() <= kMaximumPlanBytes) ? std::move(encoded) : QByteArray();
}

std::optional<LegacyRetirementPlan> ParseLegacyRetirementPlan(
		const QByteArray &serialized) {
	if (serialized.isEmpty() || serialized.size() > kMaximumPlanBytes) {
		return std::nullopt;
	}
	const auto array = QJsonDocument::fromJson(serialized).array();
	const auto version = array.isEmpty() ? 0 : array[0].toInt();
	if (array.size() != 6 || version < kPlanVersion || version > kVerifiedWalletPreserveWebviewPlanVersion) {
		return std::nullopt;
	}
	auto result = Plan{
		.dataDirectory = array[1].toString(),
		.dataName = array[2].toString(),
		.transactionId = QByteArray::fromHex(array[3].toString().toLatin1()),
		.webview = (version == kPreserveWebviewPlanVersion
				|| version == kVerifiedWalletPreserveWebviewPlanVersion)
			? Storage::LegacyWebviewTransfer::StartFresh
			: Storage::LegacyWebviewTransfer::RequireIsolated,
		.walletInventoryVerified = (version >= kVerifiedWalletPlanVersion),
	};
	const auto indices = array[4].toArray();
	const auto entries = array[5].toArray();
	if (indices.size() > kMaximumAccounts || entries.size() > kMaximumEntries) {
		return std::nullopt;
	}
	for (const auto index : indices) {
		result.accountIndices.push_back(index.toInt(-1));
	}
	for (const auto entry : entries) {
		const auto item = entry.toArray();
		if (item.size() != 2) {
			return std::nullopt;
		}
		result.entries.push_back({
			item[0].toString(),
			QByteArray::fromHex(item[1].toString().toLatin1()),
		});
	}
	return (SerializeLegacyRetirementPlan(result) == serialized)
		? std::optional(std::move(result))
		: std::nullopt;
}

LegacyRetirementResult RetireLegacyProfileFiles(
		const QString &dataDirectory,
		const QByteArray &committedTransactionId,
		const LegacyRetirementPlan &plan) {
	using Result = LegacyRetirementResult;
	const auto layout = BuildLayout(plan);
	if (!layout || !ValidEntries(plan, *layout)
		|| dataDirectory != plan.dataDirectory
		|| committedTransactionId != plan.transactionId) {
		return Result::InvalidPlan;
	}
	if (!MatchesCurrentSource(plan, *layout)) {
		return Result::UnexpectedSource;
	}
	const auto keys = u"key_"_q + plan.dataName;
	for (const auto &entry : plan.entries) {
		if (entry.relativePath.chopped(1) == keys
			&& !RemoveIfPresent(dataDirectory, entry)) {
			return Result::FilesystemFailure;
		}
	}
	for (auto i = plan.entries.rbegin(); i != plan.entries.rend(); ++i) {
		if (i->sha256.isEmpty() && PreserveWebviewRoot(plan, *layout, i->relativePath)) {
			continue;
		}
		if (!RemoveIfPresent(dataDirectory, *i)) {
			return Result::FilesystemFailure;
		}
	}
	if (!MatchesCurrentSource(plan, *layout)
		|| std::ranges::any_of(plan.entries, [&](const Entry &entry) {
			if (entry.sha256.isEmpty() && PreserveWebviewRoot(plan, *layout, entry.relativePath)) {
				return false;
			}
			return Present(QFileInfo(dataDirectory + '/' + entry.relativePath));
		})) {
		return Result::UnexpectedSource;
	}
	return SyncRetirementRoot(dataDirectory)
		? Result::Complete
		: Result::FilesystemFailure;
}

} // namespace Ayu::ProfileSets
