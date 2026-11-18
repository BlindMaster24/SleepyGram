// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/scoped_account_clear.h"

#include <algorithm>
#include <memory>
#include <ranges>
#include <set>
#include <string_view>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu::EmergencyActions {
namespace {

using Path = std::filesystem::path;

constexpr auto kLocatorLength = size_t(32);
constexpr auto kMaximumDirectoryDepth = 64;

Path NativePath(Path path) {
	path.make_preferred();
#ifdef _WIN32
	constexpr auto prefix = std::wstring_view(L"\\\\?\\");
	if (path.native().starts_with(prefix)) {
		return Path(path.native().substr(prefix.size()));
	}
#endif
	return path;
}

bool ValidDataDirectory(const Path &path) {
	if (!path.is_absolute() || !path.has_relative_path()
		|| path.native().find(Path::value_type(0)) != Path::string_type::npos) {
		return false;
	}
	return std::ranges::none_of(path.relative_path(), [](const Path &part) {
		return part.empty() || part == "." || part == "..";
	});
}

bool ValidBindings(const std::vector<ScopedAccountLocator> &accounts) {
	auto ids = std::set<AccountId>();
	auto locators = std::set<std::string>();
	auto namedStores = std::set<ScopedWebviewStoreId>();
	for (const auto &account : accounts) {
		if (!account.accountId.valid()
			|| account.locator.size() != kLocatorLength
			|| account.locator.find_first_not_of('0') == std::string::npos
			|| !std::ranges::all_of(account.locator, [](char ch) {
				return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
			})
			|| !ids.insert(account.accountId).second
			|| !locators.insert(account.locator).second) {
			return false;
		}
		if (account.namedWebviewStores && (!ValidScopedWebviewStoreIds(*account.namedWebviewStores)
			|| std::ranges::any_of(*account.namedWebviewStores, [&](const auto &id) {
				return !namedStores.insert(id).second;
			}))) {
			return false;
		}
	}
	return true;
}

#ifdef _WIN32
class Handle final {
public:
	explicit Handle(HANDLE value) : _value(value) {
	}
	Handle(Handle &&other) noexcept
	: _value(std::exchange(other._value, INVALID_HANDLE_VALUE)) {
	}
	Handle &operator=(Handle&&) = delete;
	~Handle() {
		if (*this) {
			CloseHandle(_value);
		}
	}

	[[nodiscard]] explicit operator bool() const {
		return _value != INVALID_HANDLE_VALUE;
	}
	[[nodiscard]] HANDLE get() const {
		return _value;
	}

private:
	HANDLE _value = INVALID_HANDLE_VALUE;

};

class DirectoryListing final {
public:
	explicit DirectoryListing(HANDLE value) : _value(value) {
	}
	DirectoryListing(const DirectoryListing &) = delete;
	DirectoryListing &operator=(const DirectoryListing &) = delete;
	~DirectoryListing() {
		if (*this) {
			FindClose(_value);
		}
	}

	[[nodiscard]] explicit operator bool() const {
		return _value != INVALID_HANDLE_VALUE;
	}
	[[nodiscard]] HANDLE get() const {
		return _value;
	}

private:
	HANDLE _value = INVALID_HANDLE_VALUE;

};

Handle OpenEntry(const Path &path, DWORD access) {
	return Handle(CreateFileW(
		path.c_str(),
		access,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr));
}

std::optional<DWORD> EntryAttributes(HANDLE handle) {
	auto info = BY_HANDLE_FILE_INFORMATION{};
	return GetFileInformationByHandle(handle, &info)
		? std::optional(info.dwFileAttributes)
		: std::nullopt;
}

bool RealDirectory(DWORD attributes) {
	return (attributes & FILE_ATTRIBUTE_DIRECTORY)
		&& !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool RemoveEntry(const Path &path, int depth);

bool RemoveChildren(const Path &path, int depth) {
	if (depth >= kMaximumDirectoryDepth) {
		return false;
	}
	auto entry = WIN32_FIND_DATAW{};
	const auto listing = DirectoryListing(FindFirstFileW((path / L"*").c_str(), &entry));
	if (!listing) {
		return GetLastError() == ERROR_FILE_NOT_FOUND;
	}
	do {
		const auto name = std::wstring_view(entry.cFileName);
		if (name != L"." && name != L".." && !RemoveEntry(path / name, depth + 1)) {
			return false;
		}
	} while (FindNextFileW(listing.get(), &entry));
	return GetLastError() == ERROR_NO_MORE_FILES;
}

bool RemoveEntry(const Path &path, int depth) {
	const auto entry = OpenEntry(path, FILE_READ_ATTRIBUTES | DELETE);
	if (!entry) {
		return GetLastError() == ERROR_FILE_NOT_FOUND;
	}
	const auto attributes = EntryAttributes(entry.get());
	if (!attributes || (!depth && !RealDirectory(*attributes))) {
		return false;
	}
	if (RealDirectory(*attributes) && !RemoveChildren(path, depth)) {
		return false;
	}
	auto disposition = FILE_DISPOSITION_INFO{ .DeleteFile = TRUE };
	return SetFileInformationByHandle(
		entry.get(),
		FileDispositionInfo,
		&disposition,
		sizeof(disposition));
}

bool ClearScopedDirectory(const Path &root, const std::string &locator) {
	const auto drive = root.root_name().native();
	if (drive.size() != 2 || drive[1] != L':'
		|| !((drive[0] >= L'A' && drive[0] <= L'Z')
			|| (drive[0] >= L'a' && drive[0] <= L'z'))) {
		return false;
	}
	auto current = Path(L"\\\\?\\" + root.root_path().make_preferred().native());
	auto ancestors = std::vector<Handle>();
	const auto lockDirectory = [&] {
		auto dir = OpenEntry(current, FILE_READ_ATTRIBUTES);
		const auto attributes = dir ? EntryAttributes(dir.get()) : std::nullopt;
		if (!attributes || !RealDirectory(*attributes)) {
			return false;
		}
		ancestors.push_back(std::move(dir));
		return true;
	};
	if (!lockDirectory()) {
		return false;
	}
	for (const auto &part : root.relative_path()) {
		current /= part;
		if (!lockDirectory()) {
			return false;
		}
	}
	const auto target = current / locator;
	return RemoveEntry(target, 0)
		&& GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES
		&& GetLastError() == ERROR_FILE_NOT_FOUND;
}
#else
constexpr auto kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

class FileDescriptor final {
public:
	explicit FileDescriptor(int value) : _value(value) {
	}
	FileDescriptor(const FileDescriptor &) = delete;
	FileDescriptor &operator=(const FileDescriptor &) = delete;
	~FileDescriptor() {
		reset(-1);
	}

	void reset(int value) {
		if (_value >= 0) {
			close(_value);
		}
		_value = value;
	}
	[[nodiscard]] int get() const {
		return _value;
	}

private:
	int _value = -1;

};

struct CloseDirectory final {
	void operator()(DIR *stream) const {
		closedir(stream);
	}
};

std::unique_ptr<DIR, CloseDirectory> ListDirectory(int directory) {
	const auto copy = openat(directory, ".", kDirectoryFlags);
	if (copy < 0) {
		return nullptr;
	}
	const auto stream = fdopendir(copy);
	if (!stream) {
		close(copy);
	}
	return std::unique_ptr<DIR, CloseDirectory>(stream);
}

bool SameDirectory(const struct stat &a, const struct stat &b) {
	return S_ISDIR(a.st_mode) && S_ISDIR(b.st_mode)
		&& a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

struct VolumeIdentity final {
	dev_t device = 0;
	std::string mount;
};

std::string DirectoryMountId([[maybe_unused]] int directory) {
#if defined __linux__
	auto info = std::ifstream("/proc/self/fdinfo/" + std::to_string(directory));
	auto line = std::string();
	constexpr auto prefix = std::string_view("mnt_id:\t");
	while (std::getline(info, line)) {
		if (line.starts_with(prefix)) {
			return line.substr(prefix.size());
		}
	}
#endif
	return {};
}

bool MatchesVolume(int directory, const struct stat &info, const VolumeIdentity &volume) {
	return info.st_dev == volume.device && DirectoryMountId(directory) == volume.mount;
}

bool RemoveEntry(int parent, const char *name, const VolumeIdentity &volume, int depth) {
	struct stat entry = {};
	if (fstatat(parent, name, &entry, AT_SYMLINK_NOFOLLOW) != 0) {
		return errno == ENOENT;
	}
	if (entry.st_dev != volume.device) {
		return false;
	}
	if (!S_ISDIR(entry.st_mode)) {
		return depth && (unlinkat(parent, name, 0) == 0 || errno == ENOENT);
	}
	if (depth >= kMaximumDirectoryDepth) {
		return false;
	}
	const auto child = FileDescriptor(openat(parent, name, kDirectoryFlags));
	struct stat opened = {};
	if (child.get() < 0 || fstat(child.get(), &opened) != 0
		|| !SameDirectory(entry, opened)
		|| !MatchesVolume(child.get(), opened, volume)) {
		return false;
	}
	const auto listing = ListDirectory(child.get());
	if (!listing) {
		return false;
	}
	while (true) {
		errno = 0;
		const auto item = readdir(listing.get());
		if (!item) {
			if (errno) {
				return false;
			}
			break;
		}
		const auto childName = std::string_view(item->d_name);
		if (childName != "." && childName != ".."
			&& !RemoveEntry(child.get(), item->d_name, volume, depth + 1)) {
			return false;
		}
	}
	struct stat current = {};
	return fsync(child.get()) == 0
		&& fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0
		&& SameDirectory(opened, current)
		&& unlinkat(parent, name, AT_REMOVEDIR) == 0;
}

bool ClearScopedDirectory(const Path &root, const std::string &locator) {
	const auto installation = root.parent_path().parent_path();
	auto parent = FileDescriptor(open("/", kDirectoryFlags));
	for (const auto &part : installation.relative_path()) {
		if (parent.get() < 0) {
			return false;
		}
		parent.reset(openat(parent.get(), part.c_str(), kDirectoryFlags));
	}
	struct stat installationInfo = {};
	if (parent.get() < 0 || fstat(parent.get(), &installationInfo) != 0) {
		return false;
	}
	const auto volume = VolumeIdentity{
		.device = installationInfo.st_dev,
		.mount = DirectoryMountId(parent.get()),
	};
#if defined __linux__
	if (volume.mount.empty()) {
		return false;
	}
#endif
	for (const auto &part : root.lexically_relative(installation)) {
		parent.reset(openat(parent.get(), part.c_str(), kDirectoryFlags));
		struct stat scope = {};
		if (parent.get() < 0 || fstat(parent.get(), &scope) != 0
			|| !MatchesVolume(parent.get(), scope, volume)) {
			return false;
		}
	}
	return RemoveEntry(parent.get(), locator.c_str(), volume, 0)
		&& fsync(parent.get()) == 0;
}
#endif

} // namespace

ScopedAccountClear::ScopedAccountClear(
		const InstallationId &installationId,
		std::filesystem::path installationDataDirectory,
		ScopedAccountCleanupBinding authenticatedBinding,
		ClearScopedWebviewStores clearNamedStores)
: _accountStorageRoot(NativePath(installationDataDirectory) / "profile-sets" / "accounts")
, _accounts(std::move(authenticatedBinding.accounts))
, _clearNamedStores(std::move(clearNamedStores))
, _valid(installationId.valid()
	&& installationId == authenticatedBinding.installationId
	&& ValidDataDirectory(NativePath(std::move(installationDataDirectory)))
	&& NativePath(std::move(authenticatedBinding.accountStorageRoot)) == _accountStorageRoot
	&& ValidBindings(_accounts)) {
}

EffectResult ScopedAccountClear::clear(const AccountId &accountId) {
	if (!_valid) {
		return EffectResult::ConfirmedFailure;
	}
	const auto target = std::ranges::find(_accounts, accountId, &ScopedAccountLocator::accountId);
	if (target == _accounts.end()) {
		return EffectResult::ConfirmedFailure;
	}
	const auto &stores = target->namedWebviewStores;
	if ((!stores && _clearNamedStores) || (stores && !stores->empty() && !_clearNamedStores)) {
		return EffectResult::ConfirmedFailure;
	} else if (stores && !stores->empty() && !_confirmedNamedClears.contains(accountId)) {
		const auto result = _clearNamedStores(*stores);
		if (result != EffectResult::ConfirmedSuccess) {
			return result;
		}
		_confirmedNamedClears.insert(accountId);
	}
	return ClearScopedDirectory(_accountStorageRoot, target->locator)
		? EffectResult::ConfirmedSuccess
		: EffectResult::ConfirmedFailure;
}

} // namespace Ayu::EmergencyActions
