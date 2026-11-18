// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/installation_data_cleanup.h"

#include <openssl/evp.h>

#include <algorithm>
#include <charconv>
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
#include <aclapi.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu::EmergencyActions {
namespace {

using Path = std::filesystem::path;
using Result = InstallationDataCleanupResult;
using Phase = InstallationDataCleanupPhase;
constexpr auto kMaxSetScopes = size_t(4096);
constexpr auto kMaxRecoveryScopes = size_t(256);
constexpr auto kMaxFileBytes = uint64_t(2) * 1024 * 1024 * 1024;
constexpr auto kWorkspace = std::string_view("profile-sets/");
constexpr auto kScopedSets = std::string_view("set-settings/");
constexpr auto kGenerations = std::string_view("generations/");
constexpr auto kJournals = std::string_view("emergency-journal/");
constexpr auto kStage = std::string_view("stage/");
constexpr auto kJournalSuffix = std::string_view(".journal");
constexpr auto kJournalDigits = std::string_view("abcdefghijklmnopqrstuvwxyz234567");

constexpr auto kSettingsFiles = std::array<std::string_view, 6>{
	"settingss", "settings0", "settings1",
	"sleepy-preferencess", "sleepy-preferences0", "sleepy-preferences1",
};
constexpr auto kGlobalFiles = std::array<std::string_view, 17>{
	"config", "prefix", "update-manifest", "withdebug", "devversion", "usertag",
	"working", "experimental_options.json", "shortcuts-default.json",
	"shortcuts-custom.json", "opengl_crash_check", "angle_backend", "ayu_settings.json",
	"ayudata.db", "ayudata.db-wal", "ayudata.db-shm", "ayudata.db-journal",
};
constexpr auto kReplayControlFiles = std::array<std::string_view, 8>{
	".migration-workspace", ".cutover/phase", ".cutover/active",
	"migration.manifest.pending", "migration.manifest.committed", "migration.lock",
	"profile-setup.bin", "emergency-journal/execution.lock",
};
constexpr auto kGenerationFiles = std::array<std::string_view, 5>{
	"profile-vault.bin", "account-keyring.bin", "legacy-retirement.bin",
	"emergency-rules.bin", "emergency-recovery.bin",
};

bool ValidStableId(std::string_view id) {
	return !id.empty() && id.size() <= 128
		&& std::ranges::all_of(id, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9')
				|| ch == '-' || ch == '_' || ch == '.' || ch == ':';
		});
}

bool ValidLocator(std::string_view value) {
	return value.size() == 32 && value.find_first_not_of('0') != std::string_view::npos
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9');
		});
}

bool ValidRootPath(const Path &path) {
	if (!path.is_absolute() || path.filename() != "tdata" || path.lexically_normal() != path
		|| path.native().find(Path::value_type(0)) != Path::string_type::npos
		|| std::ranges::any_of(path.relative_path(), [](const Path &part) {
			return part.empty() || part == "." || part == "..";
		})) {
		return false;
	}
#ifdef _WIN32
	const auto drive = path.root_name().native();
	return drive.size() == 2 && drive[1] == L':'
		&& ((drive[0] >= L'A' && drive[0] <= L'Z')
			|| (drive[0] >= L'a' && drive[0] <= L'z'))
		&& std::ranges::none_of(path.relative_path(), [](const Path &part) {
			return part.native().find_first_of(L"<>:\"|?*") != std::wstring::npos
				|| part.native().back() == L'.' || part.native().back() == L' ';
		});
#else
	return true;
#endif
}

bool JournalName(std::string_view name) {
	if (!name.ends_with(kJournalSuffix)) {
		return false;
	}
	name.remove_suffix(kJournalSuffix.size());
	return !name.empty() && name.size() <= 205
		&& name.find_first_not_of(kJournalDigits) == std::string_view::npos;
}

std::string JournalFile(const OperationId &id) {
	auto label = std::string();
	auto buffer = uint32_t(0);
	auto bits = 0;
	for (const auto ch : id.value) {
		buffer = (buffer << 8) | uint8_t(ch);
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			label += kJournalDigits[(buffer >> bits) & 31];
		}
	}
	if (bits) {
		label += kJournalDigits[(buffer << (5 - bits)) & 31];
	}
	return label.append(kJournalSuffix);
}

template <size_t Size>
bool Contains(const std::array<std::string_view, Size> &values, std::string_view value) {
	return std::ranges::find(values, value) != values.end();
}

template <size_t Size>
bool ScopedLeaf(
		std::string_view relative,
		std::string_view prefix,
		const std::array<std::string_view, Size> &names) {
	if (!relative.starts_with(prefix)) {
		return false;
	}
	relative.remove_prefix(prefix.size());
	const auto separator = relative.find('/');
	return separator == 32 && ValidLocator(relative.substr(0, separator))
		&& Contains(names, relative.substr(separator + 1));
}

std::optional<Phase> FilePhase(std::string_view relative) {
	if (Contains(kGlobalFiles, relative) || Contains(kSettingsFiles, relative)) {
		return Phase::AfterExit;
	}
	if (!relative.starts_with(kWorkspace)) {
		return std::nullopt;
	}
	relative.remove_prefix(kWorkspace.size());
	if (ScopedLeaf(relative, kScopedSets, kSettingsFiles)) {
		return Phase::AfterExit;
	}
	if (Contains(kReplayControlFiles, relative)
		|| ScopedLeaf(relative, kGenerations, kGenerationFiles)
		|| (relative.starts_with(kStage) && Contains(kGenerationFiles, relative.substr(kStage.size())))
		|| (relative.starts_with(kJournals) && JournalName(relative.substr(kJournals.size())))) {
		return Phase::FinalizeRecovery;
	}
	return std::nullopt;
}

std::optional<std::set<std::string>> Candidates(const InstallationDataCleanupScope &scope) {
	if (scope.setIds.size() > kMaxSetScopes || scope.generationIds.size() > kMaxRecoveryScopes
		|| scope.journalIds.size() > kMaxRecoveryScopes) {
		return std::nullopt;
	}
	auto result = std::set<std::string>();
	const auto append = [&](std::string_view prefix, const auto &leaves) {
		for (const auto leaf : leaves) {
			result.insert(std::string(prefix).append(leaf));
		}
	};
	append("", kGlobalFiles);
	append("", kSettingsFiles);
	append(kWorkspace, kReplayControlFiles);
	append(std::string(kWorkspace).append(kStage), kGenerationFiles);
	const auto scoped = [&](const auto &ids, std::string_view prefix, const auto &leaves) {
		auto unique = std::set<std::string_view>();
		for (const auto &id : ids) {
			if (!ValidLocator(id) || !unique.insert(id).second) {
				return false;
			}
			append(std::string(kWorkspace).append(prefix).append(id).append("/"), leaves);
		}
		return true;
	};
	if (!scoped(scope.setIds, kScopedSets, kSettingsFiles)
		|| !scoped(scope.generationIds, kGenerations, kGenerationFiles)) {
		return std::nullopt;
	}
	for (const auto &id : scope.journalIds) {
		if (!ValidStableId(id.value)
			|| !result.insert(std::string(kWorkspace).append(kJournals).append(JournalFile(id))).second) {
			return std::nullopt;
		}
	}
	return result;
}

struct Snapshot final {
	InstallationDataIdentity identity;
	uint64_t size = 0;
	uint64_t modified = 0;
	uint64_t modifiedFraction = 0;
	uint64_t changed = 0;
	uint64_t changedFraction = 0;

	friend bool operator==(const Snapshot&, const Snapshot&) = default;
};

enum class EntryStatus : uint8_t {
	Present,
	Missing,
	Unsafe,
	Unavailable,
};

template <typename Read>
std::optional<InstallationArtifactDigest> Digest(size_t size, Read &&read) {
	auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
		EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
		return std::nullopt;
	}
	auto buffer = std::array<uint8_t, 32 * 1024>{};
	while (size) {
		const auto count = read(std::span(buffer).first(std::min(size, buffer.size())));
		if (!count || !*count || *count > size
			|| EVP_DigestUpdate(context.get(), buffer.data(), *count) != 1) {
			return std::nullopt;
		}
		size -= *count;
	}
	auto result = InstallationArtifactDigest{};
	auto bytes = 0U;
	return EVP_DigestFinal_ex(context.get(), result.data(), &bytes) == 1 && bytes == result.size()
		? std::optional(result) : std::nullopt;
}

#ifdef _WIN32

class NativeHandle final {
public:
	NativeHandle() = default;
	explicit NativeHandle(HANDLE value) : _value(value) {
	}
	NativeHandle(NativeHandle &&other) noexcept
	: _value(std::exchange(other._value, nullptr)) {
	}
	NativeHandle &operator=(NativeHandle&&) = delete;
	~NativeHandle() {
		close();
	}

	void close() {
		if (*this) {
			CloseHandle(_value);
		}
		_value = nullptr;
	}
	[[nodiscard]] explicit operator bool() const {
		return _value && _value != INVALID_HANDLE_VALUE;
	}
	[[nodiscard]] HANDLE get() const {
		return _value;
	}

private:
	HANDLE _value = nullptr;

};

struct NativeRoot final {
	Path path;
	InstallationDataIdentity identity;
	std::vector<NativeHandle> ancestors;
	std::vector<uint8_t> principal;
};

struct NativeLeaf final {
	EntryStatus status = EntryStatus::Unavailable;
	std::vector<NativeHandle> parents;
	NativeHandle file;
	Path path;
};

std::vector<uint8_t> CurrentPrincipal() {
	auto raw = HANDLE();
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
		return {};
	}
	const auto token = NativeHandle(raw);
	auto owner = std::vector<uint8_t>(sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE);
	auto bytes = DWORD(0);
	if (!GetTokenInformation(token.get(), TokenUser, owner.data(), DWORD(owner.size()), &bytes)) {
		return {};
	}
	const auto sid = reinterpret_cast<const TOKEN_USER*>(owner.data())->User.Sid;
	return sid && IsValidSid(sid) ? std::move(owner) : std::vector<uint8_t>();
}

bool OwnedBy(const NativeHandle &handle, const std::vector<uint8_t> &principal) {
	if (principal.empty()) {
		return false;
	}
	const auto sid = reinterpret_cast<const TOKEN_USER*>(principal.data())->User.Sid;
	auto owner = PSID();
	auto descriptor = PSECURITY_DESCRIPTOR();
	const auto checked = GetSecurityInfo(
		handle.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
		&owner, nullptr, nullptr, nullptr, &descriptor);
	const auto matches = checked == ERROR_SUCCESS && owner && EqualSid(owner, sid);
	if (descriptor) {
		LocalFree(descriptor);
	}
	return matches;
}

NativeHandle OpenNative(const Path &path, DWORD access, DWORD sharing) {
	return NativeHandle(CreateFileW(
		path.c_str(), access, sharing, nullptr, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
}

std::optional<BY_HANDLE_FILE_INFORMATION> Information(const NativeHandle &handle) {
	auto result = BY_HANDLE_FILE_INFORMATION();
	if (!handle || GetFileType(handle.get()) != FILE_TYPE_DISK
		|| !GetFileInformationByHandle(handle.get(), &result)
		|| (result.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		return std::nullopt;
	}
	return result;
}

InstallationDataIdentity Identity(const BY_HANDLE_FILE_INFORMATION &info) {
	return {
		info.dwVolumeSerialNumber,
		(uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow,
	};
}

std::optional<Snapshot> StatFile(const NativeHandle &handle) {
	const auto info = Information(handle);
	auto time = FILE_BASIC_INFO();
	if (!info || (info->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE))
		|| info->nNumberOfLinks != 1
		|| !GetFileInformationByHandleEx(handle.get(), FileBasicInfo, &time, sizeof(time))) {
		return std::nullopt;
	}
	return Snapshot{
		.identity = Identity(*info),
		.size = (uint64_t(info->nFileSizeHigh) << 32) | info->nFileSizeLow,
		.modified = uint64_t(time.LastWriteTime.QuadPart),
		.changed = uint64_t(time.ChangeTime.QuadPart),
	};
}

EntryStatus NativeFailure() {
	const auto error = GetLastError();
	return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
		? EntryStatus::Missing : EntryStatus::Unavailable;
}

std::optional<NativeRoot> OpenRoot(const Path &path) {
	auto native = path;
	native.make_preferred();
	auto result = NativeRoot{
		.path = Path(L"\\\\?\\" + native.root_path().native()),
		.principal = CurrentPrincipal(),
	};
	if (result.principal.empty()) {
		return std::nullopt;
	}
	const auto pin = [&] {
		auto directory = OpenNative(
			result.path, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE);
		const auto info = Information(directory);
		if (!info || !(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			return false;
		}
		result.identity = Identity(*info);
		result.ancestors.push_back(std::move(directory));
		return true;
	};
	if (!pin()) {
		return std::nullopt;
	}
	for (const auto &part : native.relative_path()) {
		result.path /= part;
		if (!pin()) {
			return std::nullopt;
		}
	}
	return result.identity.node && OwnedBy(result.ancestors.back(), result.principal)
		? std::optional(std::move(result))
		: std::nullopt;
}

NativeLeaf OpenLeaf(const NativeRoot &root, std::string_view relative, bool removing) {
	const auto path = Path(relative);
	auto result = NativeLeaf{ .path = root.path };
	for (const auto &part : path.parent_path()) {
		result.path /= part;
		auto directory = OpenNative(
			result.path, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE);
		if (!directory) {
			result.status = NativeFailure();
			return result;
		}
		const auto info = Information(directory);
		if (!info || !(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			|| Identity(*info).volume != root.identity.volume || !OwnedBy(directory, root.principal)) {
			result.status = EntryStatus::Unsafe;
			return result;
		}
		result.parents.push_back(std::move(directory));
	}
	result.path /= path.filename();
	auto file = OpenNative(
		result.path,
		GENERIC_READ | READ_CONTROL | (removing ? DELETE : 0),
		removing ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE));
	if (!file) {
		result.status = NativeFailure();
		return result;
	}
	const auto info = StatFile(file);
	if (!info || !info->identity.node || info->identity.volume != root.identity.volume
		|| !OwnedBy(file, root.principal)) {
		result.status = EntryStatus::Unsafe;
		return result;
	}
	return {
		.status = EntryStatus::Present,
		.parents = std::move(result.parents),
		.file = std::move(file),
		.path = std::move(result.path),
	};
}

std::optional<size_t> ReadNative(const NativeHandle &handle, std::span<uint8_t> bytes) {
	auto count = DWORD(0);
	return ReadFile(handle.get(), bytes.data(), DWORD(bytes.size()), &count, nullptr)
		? std::optional(size_t(count)) : std::nullopt;
}

bool RemoveNative(NativeLeaf &leaf, const Snapshot &expected) {
	if (StatFile(leaf.file) != expected) {
		return false;
	}
	auto disposition = FILE_DISPOSITION_INFO{ .DeleteFile = TRUE };
	if (!SetFileInformationByHandle(
			leaf.file.get(), FileDispositionInfo, &disposition, sizeof(disposition))) {
		return false;
	}
	leaf.file.close();
	return GetFileAttributesW(leaf.path.c_str()) == INVALID_FILE_ATTRIBUTES
		&& NativeFailure() == EntryStatus::Missing;
}

#else

using Stat = struct stat;
constexpr auto kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

class NativeHandle final {
public:
	NativeHandle() = default;
	explicit NativeHandle(int value) : _value(value) {
	}
	NativeHandle(NativeHandle &&other) noexcept
	: _value(std::exchange(other._value, -1)) {
	}
	NativeHandle &operator=(NativeHandle &&other) noexcept {
		std::swap(_value, other._value);
		return *this;
	}
	~NativeHandle() {
		if (*this) {
			close(_value);
		}
	}

	[[nodiscard]] explicit operator bool() const {
		return _value >= 0;
	}
	[[nodiscard]] int get() const {
		return _value;
	}

private:
	int _value = -1;

};

struct NativeRoot final {
	NativeHandle directory;
	InstallationDataIdentity identity;
	uint64_t mount = 0;
};

struct NativeLeaf final {
	EntryStatus status = EntryStatus::Unavailable;
	NativeHandle directory;
	NativeHandle file;
	std::string name;
};

InstallationDataIdentity Identity(const Stat &info) {
	return { uint64_t(info.st_dev), uint64_t(info.st_ino) };
}

Snapshot FileSnapshot(const Stat &stat) {
#ifdef __APPLE__
	const auto &modified = stat.st_mtimespec;
	const auto &changed = stat.st_ctimespec;
#else
	const auto &modified = stat.st_mtim;
	const auto &changed = stat.st_ctim;
#endif
	return {
		.identity = Identity(stat),
		.size = uint64_t(stat.st_size),
		.modified = uint64_t(modified.tv_sec),
		.modifiedFraction = uint64_t(modified.tv_nsec),
		.changed = uint64_t(changed.tv_sec),
		.changedFraction = uint64_t(changed.tv_nsec),
	};
}

bool OwnedRegular(const Stat &info) {
	return S_ISREG(info.st_mode) && info.st_uid == geteuid()
		&& !(info.st_mode & 0022) && info.st_nlink == 1 && info.st_size >= 0;
}

bool OwnedDirectory(const Stat &info) {
	return S_ISDIR(info.st_mode) && info.st_uid == geteuid() && !(info.st_mode & 0022);
}

std::optional<Snapshot> StatFile(const NativeHandle &handle) {
	auto info = Stat{};
	return handle && fstat(handle.get(), &info) == 0 && OwnedRegular(info)
		? std::optional(FileSnapshot(info)) : std::nullopt;
}

EntryStatus NativeFailure() {
	switch (errno) {
	case ENOENT: return EntryStatus::Missing;
	case ELOOP:
	case ENOTDIR: return EntryStatus::Unsafe;
	default: return EntryStatus::Unavailable;
	}
}

std::optional<uint64_t> MountIdentity(const NativeHandle &directory) {
#ifdef __linux__
	const auto path = "/proc/self/fdinfo/" + std::to_string(directory.get());
	const auto info = NativeHandle(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
	if (!info) {
		return std::nullopt;
	}
	auto data = std::array<char, 1024>{};
	auto count = ssize_t(0);
	do {
		count = read(info.get(), data.data(), data.size());
	} while (count < 0 && errno == EINTR);
	if (count <= 0) {
		return std::nullopt;
	}
	auto text = std::string_view(data.data(), size_t(count));
	constexpr auto key = std::string_view("\nmnt_id:\t");
	const auto offset = text.find(key);
	if (offset == std::string_view::npos) {
		return std::nullopt;
	}
	text.remove_prefix(offset + key.size());
	const auto line = text.substr(0, text.find('\n'));
	auto identity = uint64_t(0);
	const auto result = std::from_chars(line.data(), line.data() + line.size(), identity);
	return identity && result.ec == std::errc() && result.ptr == line.data() + line.size()
		? std::optional(identity) : std::nullopt;
#else
	auto info = Stat{};
	return fstat(directory.get(), &info) == 0
		? std::optional(uint64_t(info.st_dev)) : std::nullopt;
#endif
}

std::optional<NativeRoot> OpenRoot(const Path &path) {
	auto directory = NativeHandle(open("/", kDirectoryFlags));
	for (const auto &part : path.parent_path().relative_path()) {
		if (!directory) {
			return std::nullopt;
		}
		directory = NativeHandle(openat(directory.get(), part.c_str(), kDirectoryFlags));
	}
	if (!directory) {
		return std::nullopt;
	}
	const auto containment = MountIdentity(directory);
	directory = NativeHandle(openat(directory.get(), "tdata", kDirectoryFlags));
	auto info = Stat{};
	if (!directory || !containment || MountIdentity(directory) != containment
		|| fstat(directory.get(), &info) != 0 || !OwnedDirectory(info)) {
		return std::nullopt;
	}
	const auto identity = Identity(info);
	return identity.node
		? std::optional(NativeRoot{ std::move(directory), identity, *containment })
		: std::nullopt;
}

NativeLeaf OpenLeaf(const NativeRoot &root, std::string_view relative, bool removing) {
	const auto path = Path(relative);
	auto directory = NativeHandle(fcntl(root.directory.get(), F_DUPFD_CLOEXEC, 0));
	if (!directory) {
		return {};
	}
	for (const auto &part : path.parent_path()) {
		directory = NativeHandle(openat(directory.get(), part.c_str(), kDirectoryFlags));
		if (!directory) {
			return { .status = NativeFailure() };
		}
		auto info = Stat{};
		if (fstat(directory.get(), &info) != 0) {
			return {};
		}
		if (!OwnedDirectory(info) || Identity(info).volume != root.identity.volume
			|| MountIdentity(directory) != root.mount) {
			return { .status = EntryStatus::Unsafe };
		}
	}
	auto name = path.filename().native();
	auto flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
#ifdef O_NOCTTY
	flags |= O_NOCTTY;
#endif
	auto file = NativeHandle(openat(directory.get(), name.c_str(), flags));
	if (!file) {
		return { .status = NativeFailure() };
	}
	const auto info = StatFile(file);
	if (!info || !info->identity.node || info->identity.volume != root.identity.volume
		|| MountIdentity(file) != root.mount) {
		return { .status = EntryStatus::Unsafe };
	}
	if (removing && faccessat(directory.get(), ".", W_OK, 0) != 0) {
		return {};
	}
	return { EntryStatus::Present, std::move(directory), std::move(file), std::move(name) };
}

std::optional<size_t> ReadNative(const NativeHandle &handle, std::span<uint8_t> bytes) {
	auto count = ssize_t(0);
	do {
		count = read(handle.get(), bytes.data(), bytes.size());
	} while (count < 0 && errno == EINTR);
	return count >= 0 ? std::optional(size_t(count)) : std::nullopt;
}

bool RemoveNative(NativeLeaf &leaf, const Snapshot &expected) {
	auto live = Stat{};
	return fstatat(leaf.directory.get(), leaf.name.c_str(), &live, AT_SYMLINK_NOFOLLOW) == 0
		&& OwnedRegular(live) && FileSnapshot(live) == expected
		&& unlinkat(leaf.directory.get(), leaf.name.c_str(), 0) == 0
		&& fsync(leaf.directory.get()) == 0;
}

#endif

struct ObservedLeaf final {
	EntryStatus status = EntryStatus::Unavailable;
	Snapshot snapshot;
	InstallationArtifactDigest digest{};
};

ObservedLeaf Observe(const NativeLeaf &leaf) {
	if (leaf.status != EntryStatus::Present) {
		return { .status = leaf.status };
	}
	const auto before = StatFile(leaf.file);
	if (!before || before->size > kMaxFileBytes) {
		return { .status = EntryStatus::Unsafe };
	}
	const auto digest = Digest(size_t(before->size), [&](std::span<uint8_t> bytes) {
		return ReadNative(leaf.file, bytes);
	});
	if (!digest) {
		return {};
	}
	if (StatFile(leaf.file) != before) {
		return { .status = EntryStatus::Unsafe };
	}
	return { EntryStatus::Present, *before, *digest };
}

bool Matches(const InstallationDataCleanupFile &file, const ObservedLeaf &observed) {
	return observed.status == EntryStatus::Present
		&& observed.snapshot.identity == file.identity && observed.digest == file.digest;
}

Result Failure(EntryStatus status) {
	return (status == EntryStatus::Unavailable)
		? Result::FilesystemFailure : Result::UnexpectedFile;
}

int ReplayOrder(const InstallationDataCleanupFile *file) {
	const auto path = std::string_view(file->relativePath);
	if (path.ends_with("/emergency-recovery.bin")) {
		return 2;
	}
	return path.starts_with("profile-sets/emergency-journal/") ? 1 : 0;
}

constexpr auto kWireMagic = std::array<uint8_t, 8>{ 'S', 'G', 'D', 'C', 0, 0, 0, 1 };
constexpr auto kMaxWireRootBytes = size_t(131'040);
constexpr auto kMaxWireRelativeBytes = size_t(256);

class WireWriter final {
public:
	explicit WireWriter(std::vector<uint8_t> &output) : _output(output) {
	}

	void bytes(std::span<const uint8_t> input) {
		_output.insert(_output.end(), input.begin(), input.end());
	}

	void number(uint64_t value, size_t width) {
		for (auto i = size_t(0); i != width; ++i) {
			_output.push_back(uint8_t(value >> (i * 8)));
		}
	}

	template <typename String>
	void string(const String &text) {
		number(text.size(), 4);
		bytes({ reinterpret_cast<const uint8_t*>(text.data()), text.size() });
	}

	void identity(InstallationDataIdentity value) {
		number(value.volume, 8);
		number(value.node, 8);
	}

private:
	std::vector<uint8_t> &_output;

};

class WireReader final {
public:
	explicit WireReader(std::span<const uint8_t> input) : _input(input) {
	}

	[[nodiscard]] std::span<const uint8_t> bytes(size_t count) {
		if (count > _input.size()) {
			return {};
		}
		const auto result = _input.first(count);
		_input = _input.subspan(count);
		return result;
	}

	[[nodiscard]] std::optional<uint64_t> number(size_t width) {
		const auto encoded = bytes(width);
		if (encoded.empty()) {
			return std::nullopt;
		}
		auto result = uint64_t(0);
		for (auto i = size_t(0); i != width; ++i) {
			result |= uint64_t(encoded[i]) << (i * 8);
		}
		return result;
	}

	template <typename Character>
	[[nodiscard]] std::basic_string<Character> string(size_t maximum) {
		const auto count = number(4);
		if (!count || !*count || *count > maximum) {
			return {};
		}
		const auto encoded = bytes(size_t(*count));
		return std::basic_string<Character>(encoded.begin(), encoded.end());
	}

	[[nodiscard]] std::optional<InstallationDataIdentity> identity() {
		const auto volume = number(8);
		const auto node = number(8);
		return volume && node && *node
			? std::optional(InstallationDataIdentity{ *volume, *node })
			: std::nullopt;
	}

	[[nodiscard]] bool done() const {
		return _input.empty();
	}

private:
	std::span<const uint8_t> _input;

};

} // namespace

bool ValidateInstallationDataCleanupPlan(const InstallationDataCleanupPlan &plan) {
	if (!ValidStableId(plan.installationId.value) || !ValidRootPath(plan.dataDirectory)
		|| !plan.rootIdentity.node || plan.files.size() > kMaxInstallationDataCleanupFiles) {
		return false;
	}
	auto previous = std::string_view();
	auto identities = std::set<std::pair<uint64_t, uint64_t>>();
	for (const auto &file : plan.files) {
		const auto path = std::string_view(file.relativePath);
		if (path <= previous || path.size() > kMaxWireRelativeBytes || !FilePhase(path)
			|| !file.identity.node || file.identity.volume != plan.rootIdentity.volume
			|| file.identity == plan.rootIdentity
			|| !identities.emplace(file.identity.volume, file.identity.node).second
			|| !std::ranges::any_of(file.digest, [](uint8_t byte) { return byte != 0; })) {
			return false;
		}
		previous = path;
	}
	return true;
}

std::optional<InstallationDataCleanupPlan> CaptureInstallationDataCleanupPlan(
		const InstallationDataCleanupScope &scope) {
	if (!ValidStableId(scope.installationId.value) || !ValidRootPath(scope.dataDirectory)) {
		return std::nullopt;
	}
	const auto candidates = Candidates(scope);
	const auto root = OpenRoot(scope.dataDirectory);
	if (!candidates || !root) {
		return std::nullopt;
	}
	auto plan = InstallationDataCleanupPlan{
		.installationId = scope.installationId,
		.dataDirectory = scope.dataDirectory,
		.rootIdentity = root->identity,
	};
	for (const auto &relative : *candidates) {
		const auto observed = Observe(OpenLeaf(*root, relative, false));
		if (observed.status == EntryStatus::Missing) {
			continue;
		}
		if (observed.status != EntryStatus::Present) {
			return std::nullopt;
		}
		if (plan.files.size() == kMaxInstallationDataCleanupFiles) {
			return std::nullopt;
		}
		plan.files.push_back({ relative, observed.snapshot.identity, observed.digest });
	}
	return ValidateInstallationDataCleanupPlan(plan)
		? std::optional(std::move(plan))
		: std::nullopt;
}

std::vector<uint8_t> EncodeInstallationDataCleanupPlan(
		const InstallationDataCleanupPlan &plan) {
	if (!ValidateInstallationDataCleanupPlan(plan)) {
		return {};
	}
	try {
		const auto root = plan.dataDirectory.u8string();
		if (root.empty() || root.size() > kMaxWireRootBytes
			|| Path(root).native() != plan.dataDirectory.native()) {
			return {};
		}
		auto bytes = std::vector<uint8_t>();
		auto writer = WireWriter(bytes);
		writer.bytes(kWireMagic);
		writer.string(plan.installationId.value);
		writer.string(root);
		writer.identity(plan.rootIdentity);
		writer.number(plan.files.size(), 2);
		for (const auto &file : plan.files) {
			writer.string(file.relativePath);
			writer.identity(file.identity);
			writer.bytes(file.digest);
		}
		return bytes.size() <= kMaxInstallationDataCleanupPlanBytes
			? std::move(bytes) : std::vector<uint8_t>();
	} catch (const std::filesystem::filesystem_error &) {
		return {};
	}
}

std::optional<InstallationDataCleanupPlan> DecodeInstallationDataCleanupPlan(
		std::span<const uint8_t> bytes) {
	if (bytes.size() > kMaxInstallationDataCleanupPlanBytes) {
		return std::nullopt;
	}
	auto reader = WireReader(bytes);
	if (!std::ranges::equal(kWireMagic, reader.bytes(kWireMagic.size()))) {
		return std::nullopt;
	}
	auto install = reader.string<char>(128);
	const auto root = reader.string<char8_t>(kMaxWireRootBytes);
	const auto identity = reader.identity();
	const auto count = reader.number(2);
	if (!ValidStableId(install) || root.empty() || !identity
		|| !count || *count > kMaxInstallationDataCleanupFiles) {
		return std::nullopt;
	}
	try {
		auto path = Path(root);
		if (path.u8string() != root || !ValidRootPath(path)) {
			return std::nullopt;
		}
		auto plan = InstallationDataCleanupPlan{
			.installationId = InstallationId(std::move(install)),
			.dataDirectory = std::move(path),
			.rootIdentity = *identity,
		};
		plan.files.reserve(size_t(*count));
		for (auto i = size_t(0); i != *count; ++i) {
			auto relative = reader.string<char>(kMaxWireRelativeBytes);
			const auto fileIdentity = reader.identity();
			const auto fingerprint = reader.bytes(InstallationArtifactDigest().size());
			if (!fileIdentity || fingerprint.empty()) {
				return std::nullopt;
			}
			auto file = InstallationDataCleanupFile{
				.relativePath = std::move(relative),
				.identity = *fileIdentity,
			};
			std::ranges::copy(fingerprint, file.digest.begin());
			plan.files.push_back(std::move(file));
		}
		return reader.done() && ValidateInstallationDataCleanupPlan(plan)
			? std::optional(std::move(plan))
			: std::nullopt;
	} catch (const std::filesystem::filesystem_error &) {
		return std::nullopt;
	}
}

InstallationDataCleanupResult ClearInstallationDataFiles(
		const InstallationId &expectedInstallation,
		const Path &expectedTdata,
		const InstallationDataCleanupPlan &plan,
		InstallationDataCleanupPhase phase) {
	if (expectedInstallation != plan.installationId || expectedTdata.native() != plan.dataDirectory.native()
		|| !ValidateInstallationDataCleanupPlan(plan)
		|| (phase != Phase::AfterExit && phase != Phase::FinalizeRecovery)) {
		return Result::InvalidPlan;
	}
	const auto root = OpenRoot(expectedTdata);
	if (!root || root->identity != plan.rootIdentity) {
		return Result::UnexpectedFile;
	}
	auto pending = std::vector<const InstallationDataCleanupFile*>();
	for (const auto &file : plan.files) {
		const auto role = FilePhase(file.relativePath);
		const auto leaf = OpenLeaf(*root, file.relativePath, role == phase);
		if (leaf.status == EntryStatus::Missing) {
			continue;
		}
		if (leaf.status != EntryStatus::Present) {
			return Failure(leaf.status);
		}
		if (phase == Phase::FinalizeRecovery && role != phase) {
			return Result::NormalFilesRemain;
		}
		const auto checked = Observe(leaf);
		if (!Matches(file, checked)) {
			return Failure(checked.status);
		}
		if (role == phase) {
			pending.push_back(&file);
		}
	}
	if (phase == Phase::FinalizeRecovery) {
		std::stable_sort(pending.begin(), pending.end(), [](const auto first, const auto second) {
			return ReplayOrder(first) < ReplayOrder(second);
		});
	}
	const auto current = OpenRoot(expectedTdata);
	if (!current || current->identity != plan.rootIdentity) {
		return Result::UnexpectedFile;
	}
	for (const auto file : pending) {
		auto leaf = OpenLeaf(*current, file->relativePath, true);
		if (leaf.status == EntryStatus::Missing) {
			continue;
		}
		const auto checked = Observe(leaf);
		if (!Matches(*file, checked)) {
			return Failure(checked.status);
		}
		if (!RemoveNative(leaf, checked.snapshot)) {
			return Result::FilesystemFailure;
		}
	}
	return Result::Complete;
}

} // namespace Ayu::EmergencyActions
