// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/installation_removal.h"

#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <algorithm>
#include <ranges>
#include <set>
#include <string_view>
#include <utility>

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <memory>
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#elif defined(__APPLE__) || defined(__linux__)
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <thread>
#include <unistd.h>

#ifdef __APPLE__
#include <libproc.h>
#endif
#endif

namespace Ayu::EmergencyActions {
namespace {

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
using Path = std::filesystem::path;
using Digest = InstallationArtifactDigest;
constexpr auto kMaxRelativeDepth = size_t(16);
constexpr auto kMaxArtifactBytes = uint64_t(2) * 1024 * 1024 * 1024;
constexpr auto kMaxIdentityBytes = size_t(128);

struct FileIdentity final {
	uint64_t device = 0;
	uint64_t inode = 0;
	uint64_t size = 0;
	uint64_t modifiedSeconds = 0;
	uint64_t modifiedNanoseconds = 0;
	uint64_t changedSeconds = 0;
	uint64_t changedNanoseconds = 0;

	friend bool operator==(const FileIdentity&, const FileIdentity&) = default;
};

bool SafeIdentity(std::string_view value) {
	return !value.empty() && value.size() <= kMaxIdentityBytes
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9')
				|| ch == '-' || ch == '_' || ch == '.' || ch == ':';
		});
}

#endif

#if defined(__APPLE__) || defined(__linux__)
using Stat = struct stat;
using Mount = struct statvfs;
constexpr auto kMaxArtifacts = size_t(2048);
constexpr auto kMaxPathBytes = size_t(4096);
constexpr auto kDirectoryFlags = O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC;

class File final {
public:
	explicit File(int descriptor = -1) : _descriptor(descriptor) {
	}
	File(File &&other) noexcept
	: _descriptor(std::exchange(other._descriptor, -1)) {
	}
	File &operator=(File &&other) noexcept {
		std::swap(_descriptor, other._descriptor);
		return *this;
	}
	~File() {
		if (*this) {
			close(_descriptor);
		}
	}
	[[nodiscard]] explicit operator bool() const {
		return _descriptor >= 0;
	}
	[[nodiscard]] int get() const {
		return _descriptor;
	}

private:
	int _descriptor = -1;

};

struct ApprovedFile final {
	const VerifiedInstallationArtifact *artifact = nullptr;
	FileIdentity identity;
};

struct Inspection final {
	File root;
	FileIdentity rootIdentity;
	Path executable;
	std::vector<ApprovedFile> files;
};

bool SafePath(const Path &path, bool absolute) {
	if (path.empty() || path.is_absolute() != absolute
		|| !path.has_relative_path()
		|| path.native().size() > kMaxPathBytes
		|| path.native().find('\0') != std::string::npos
		|| path.lexically_normal() != path) {
		return false;
	}
	auto depth = size_t(0);
	for (const auto &part : path.relative_path()) {
		if (part.empty() || part == "." || part == ".."
			|| ++depth > kMaxRelativeDepth) {
			return false;
		}
	}
	return true;
}

Path NativeExecutableName(InstallationPackageKind kind) {
#if defined(__APPLE__)
	return (kind == InstallationPackageKind::MacBundle)
		? Path("Contents/MacOS/SleepyGram") : Path();
#else
	return (kind == InstallationPackageKind::LinuxPortable)
		? Path("SleepyGram") : Path();
#endif
}

bool AllowedArtifact(const VerifiedInstallationReceipt &receipt, const Path &path) {
	if (!SafePath(path, false)) {
		return false;
	}
	if (receipt.kind == InstallationPackageKind::MacBundle) {
		return receipt.packageRoot.filename() == "SleepyGram.app"
			&& *path.begin() == "Contents" && path.has_parent_path();
	}
	return path == "SleepyGram" || path == "Updater" || path == "SleepyGramRemovalHelper"
		|| path == "build-manifest.json" || path == "LICENSE-SQLCipher.txt";
}

bool RequiredArtifacts(
		const VerifiedInstallationReceipt &receipt,
		const std::set<Path> &files,
		const Path &executable) {
	return files.contains(executable)
		&& ((receipt.kind == InstallationPackageKind::MacBundle)
			? files.contains("Contents/Info.plist")
				&& files.contains("Contents/Resources/SleepyGram.icns")
				&& files.contains("Contents/Resources/Telegram.rcc")
				&& files.contains("Contents/Resources/BuildManifest.json")
				&& files.contains("Contents/Resources/LICENSE-SQLCipher.txt")
			: files.contains("build-manifest.json")
				&& files.contains("LICENSE-SQLCipher.txt"));
}

FileIdentity Identity(const Stat &stat) {
#ifdef __APPLE__
	const auto &modified = stat.st_mtimespec;
	const auto &changed = stat.st_ctimespec;
#else
	const auto &modified = stat.st_mtim;
	const auto &changed = stat.st_ctim;
#endif
	return {
		.device = uint64_t(stat.st_dev),
		.inode = uint64_t(stat.st_ino),
		.size = uint64_t(stat.st_size),
		.modifiedSeconds = uint64_t(modified.tv_sec),
		.modifiedNanoseconds = uint64_t(modified.tv_nsec),
		.changedSeconds = uint64_t(changed.tv_sec),
		.changedNanoseconds = uint64_t(changed.tv_nsec),
	};
}

bool SafeDirectory(int fd, bool leaf) {
	auto stat = Stat{};
	if (fstat(fd, &stat) != 0 || !S_ISDIR(stat.st_mode)) {
		return false;
	}
	const auto owner = geteuid();
	if (leaf) {
		return stat.st_uid == owner && !(stat.st_mode & 0022)
			&& faccessat(fd, ".", W_OK, 0) == 0;
	}
	return (stat.st_uid == owner || !stat.st_uid)
		&& (!(stat.st_mode & 0022) || (!stat.st_uid && (stat.st_mode & S_ISVTX)));
}

File OpenDirectories(int start, const Path &relative, bool writable) {
	auto current = File(fcntl(start, F_DUPFD_CLOEXEC, 0));
	if (!current) {
		return File();
	}
	for (const auto &component : relative) {
		current = File(openat(current.get(), component.c_str(), kDirectoryFlags));
		if (!current || !SafeDirectory(current.get(), writable)) {
			return File();
		}
	}
	return current;
}

std::optional<Digest> HashFile(int fd) {
	auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
		EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
		return std::nullopt;
	}
	auto total = uint64_t(0);
	auto buffer = std::array<uint8_t, 32 * 1024>{};
	for (;;) {
		const auto bytes = read(fd, buffer.data(), buffer.size());
		if (bytes < 0 && errno == EINTR) {
			continue;
		}
		if (bytes < 0) {
			return std::nullopt;
		}
		if (!bytes) {
			break;
		}
		total += uint64_t(bytes);
		if (total > kMaxArtifactBytes
			|| EVP_DigestUpdate(context.get(), buffer.data(), size_t(bytes)) != 1) {
			return std::nullopt;
		}
	}
	auto result = Digest{};
	auto size = 0U;
	if (EVP_DigestFinal_ex(context.get(), result.data(), &size) != 1
		|| size != result.size()) {
		return std::nullopt;
	}
	return result;
}

std::optional<FileIdentity> CheckArtifact(
		int root,
		const VerifiedInstallationArtifact &artifact) {
	const auto parent = OpenDirectories(root, artifact.relativePath.parent_path(), true);
	if (!parent) {
		return std::nullopt;
	}
	const auto filename = artifact.relativePath.filename();
	const auto file = File(openat(
		parent.get(),
		filename.c_str(),
		O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
	auto before = Stat{};
	if (!file || fstat(file.get(), &before) != 0
		|| !S_ISREG(before.st_mode) || before.st_uid != geteuid()
		|| before.st_nlink != 1 || (before.st_mode & 0022)
		|| before.st_size < 1 || uint64_t(before.st_size) > kMaxArtifactBytes) {
		return std::nullopt;
	}
	const auto digest = HashFile(file.get());
	auto after = Stat{};
	if (!digest || *digest != artifact.digest || fstat(file.get(), &after) != 0
		|| Identity(before) != Identity(after)) {
		return std::nullopt;
	}
	return Identity(after);
}

std::optional<Inspection> Inspect(const VerifiedInstallationReceipt &receipt) {
	const auto executable = NativeExecutableName(receipt.kind);
	if (executable.empty() || !SafeIdentity(receipt.installationId.value)
		|| !SafePath(receipt.packageRoot, true) || geteuid() != getuid()
		|| !geteuid() || receipt.artifacts.empty()
		|| receipt.artifacts.size() > kMaxArtifacts) {
		return std::nullopt;
	}
	auto paths = std::set<Path>();
	for (const auto &artifact : receipt.artifacts) {
		if (!AllowedArtifact(receipt, artifact.relativePath)
			|| !paths.insert(artifact.relativePath).second) {
			return std::nullopt;
		}
	}
	if (!RequiredArtifacts(receipt, paths, executable)) {
		return std::nullopt;
	}
	const auto systemRoot = File(open("/", kDirectoryFlags));
	const auto rootPath = receipt.packageRoot.relative_path();
	const auto parent = systemRoot
		? OpenDirectories(systemRoot.get(), rootPath.parent_path(), false)
		: File();
	if (!parent) {
		return std::nullopt;
	}
	auto root = OpenDirectories(parent.get(), rootPath.filename(), true);
	auto stat = Stat{};
	auto mount = Mount{};
	if (!root || fstat(root.get(), &stat) != 0 || fstatvfs(root.get(), &mount) != 0
		|| (mount.f_flag & ST_RDONLY)
		|| (receipt.kind == InstallationPackageKind::MacBundle
			&& faccessat(parent.get(), ".", W_OK, 0) != 0)) {
		return std::nullopt;
	}
	auto result = Inspection{
		.root = std::move(root),
		.rootIdentity = Identity(stat),
		.executable = receipt.packageRoot / executable,
	};
	for (const auto &artifact : receipt.artifacts) {
		const auto identity = CheckArtifact(result.root.get(), artifact);
		if (!identity || identity->device != result.rootIdentity.device) {
			return std::nullopt;
		}
		result.files.push_back({ &artifact, *identity });
	}
	std::ranges::sort(result.files, {}, [](const auto &file) {
		return file.artifact->relativePath;
	});
	return result;
}

Path ProcessExecutable(pid_t pid) {
	auto result = std::array<char, kMaxPathBytes>{};
#ifdef __APPLE__
	const auto size = proc_pidpath(pid, result.data(), uint32_t(result.size()));
	return (size > 0 && size_t(size) < result.size())
		? Path(result.data()) : Path();
#else
	const auto proc = "/proc/" + std::to_string(pid) + "/exe";
	const auto size = readlink(proc.c_str(), result.data(), result.size());
	return (size > 0 && size_t(size) < result.size())
		? Path(std::string_view(result.data(), size_t(size))) : Path();
#endif
}

bool RemoveFile(int root, const ApprovedFile &file) {
	if (!SafeDirectory(root, true)) {
		return false;
	}
	const auto &path = file.artifact->relativePath;
	const auto parent = OpenDirectories(root, path.parent_path(), true);
	const auto name = path.filename();
	auto stat = Stat{};
	return parent && fstatat(parent.get(), name.c_str(), &stat, AT_SYMLINK_NOFOLLOW) == 0
		&& S_ISREG(stat.st_mode) && stat.st_uid == geteuid() && stat.st_nlink == 1
		&& Identity(stat) == file.identity && unlinkat(parent.get(), name.c_str(), 0) == 0;
}

bool RemoveEmptyBundleDirectories(const Inspection &inspected) {
	auto directories = std::set<Path>();
	for (const auto &file : inspected.files) {
		auto path = file.artifact->relativePath.parent_path();
		while (!path.empty()) {
			directories.insert(path);
			path = path.parent_path();
		}
	}
	for (auto i = directories.rbegin(); i != directories.rend(); ++i) {
		const auto parent = OpenDirectories(inspected.root.get(), i->parent_path(), true);
		auto stat = Stat{};
		const auto name = i->filename();
		if (!parent || fstatat(parent.get(), name.c_str(), &stat, AT_SYMLINK_NOFOLLOW) != 0
			|| !S_ISDIR(stat.st_mode) || stat.st_uid != geteuid()
			|| unlinkat(parent.get(), name.c_str(), AT_REMOVEDIR) != 0) {
			return false;
		}
	}
	const auto systemRoot = File(open("/", kDirectoryFlags));
	const auto bundle = inspected.executable.parent_path().parent_path().parent_path();
	const auto parent = systemRoot
		? OpenDirectories(systemRoot.get(), bundle.relative_path().parent_path(), false)
		: File();
	auto stat = Stat{};
	const auto name = bundle.filename();
	return parent && fstatat(parent.get(), name.c_str(), &stat, AT_SYMLINK_NOFOLLOW) == 0
		&& S_ISDIR(stat.st_mode) && uint64_t(stat.st_dev) == inspected.rootIdentity.device
		&& uint64_t(stat.st_ino) == inspected.rootIdentity.inode
		&& unlinkat(parent.get(), name.c_str(), AT_REMOVEDIR) == 0;
}
#elif defined(_WIN32)

constexpr auto kMaxPathBytes = size_t(32760);
constexpr auto kParentAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;

class WindowsHandle final {
public:
	explicit WindowsHandle(HANDLE handle = nullptr) : _handle(handle) {
	}
	WindowsHandle(WindowsHandle &&other) noexcept
	: _handle(std::exchange(other._handle, nullptr)) {
	}
	WindowsHandle &operator=(WindowsHandle &&other) noexcept {
		std::swap(_handle, other._handle);
		return *this;
	}
	~WindowsHandle() {
		reset();
	}

	void reset() {
		if (*this) {
			CloseHandle(_handle);
		}
		_handle = nullptr;
	}
	[[nodiscard]] explicit operator bool() const {
		return _handle && _handle != INVALID_HANDLE_VALUE;
	}
	[[nodiscard]] HANDLE get() const {
		return _handle;
	}

private:
	HANDLE _handle = nullptr;

};

struct ApprovedFile final {
	const VerifiedInstallationArtifact *artifact = nullptr;
	FileIdentity identity;
	Path nativePath;
	WindowsHandle handle;
};

struct Inspection final {
	std::vector<WindowsHandle> directories;
	FileIdentity rootIdentity;
	Path executable;
	std::vector<ApprovedFile> files;
};

uint64_t TimeValue(FILETIME time) {
	return (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::optional<uint64_t> CreationTime(HANDLE process) {
	auto created = FILETIME();
	auto exited = FILETIME();
	auto kernel = FILETIME();
	auto user = FILETIME();
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
		return std::nullopt;
	}
	const auto result = TimeValue(created);
	return result ? std::optional(result) : std::nullopt;
}

bool SafeWindowsParts(const Path &path) {
	auto depth = size_t(0);
	for (const auto &part : path) {
		const auto &text = part.native();
		if (text.empty() || part == L"." || part == L".."
			|| text.back() == L'.' || text.back() == L' '
			|| text.find_first_of(L"<>:\"|?*") != std::wstring::npos
			|| std::ranges::any_of(text, [](wchar_t ch) { return ch < L' '; })
			|| ++depth > kMaxRelativeDepth) {
			return false;
		}
	}
	return true;
}

std::optional<Path> WindowsDrivePath(Path path) {
	path.make_preferred();
	constexpr auto prefix = std::wstring_view(L"\\\\?\\");
	if (path.native().starts_with(prefix)) {
		path = Path(path.native().substr(prefix.size()));
	}
	const auto drive = path.root_name().native();
	if (!path.is_absolute() || !path.has_relative_path() || drive.size() != 2
		|| drive[1] != L':'
		|| !((drive[0] >= L'A' && drive[0] <= L'Z')
			|| (drive[0] >= L'a' && drive[0] <= L'z'))
		|| path.native().size() > kMaxPathBytes || !SafeWindowsParts(path.relative_path())) {
		return std::nullopt;
	}
	return path;
}

Path ProcessExecutable(HANDLE process) {
	auto name = std::wstring(kMaxPathBytes, L'\0');
	auto size = DWORD(name.size());
	if (!QueryFullProcessImageNameW(process, 0, name.data(), &size) || !size) {
		return {};
	}
	name.resize(size);
	auto path = WindowsDrivePath(Path(std::move(name)));
	return path ? std::move(*path) : Path();
}

bool SameWindowsPath(const Path &first, const Path &second) {
	return !first.empty() && !second.empty()
			&& CompareStringOrdinal(
				first.c_str(),
				int(first.native().size()),
				second.c_str(),
				int(second.native().size()),
				TRUE) == CSTR_EQUAL;
}

Path ExtendedWindowsPath(const Path &path) {
	return Path(L"\\\\?\\" + path.native());
}

WindowsHandle DuplicateParentHandle(InstallationRemovalProcessHandle inherited) {
	auto handle = HANDLE();
	return inherited.value
		&& DuplicateHandle(
			GetCurrentProcess(),
			reinterpret_cast<HANDLE>(inherited.value),
			GetCurrentProcess(),
			&handle,
			kParentAccess,
			FALSE,
			0)
		? WindowsHandle(handle)
		: WindowsHandle();
}

class ProcessOwner final {
public:
	explicit ProcessOwner(HANDLE process) {
		auto raw = HANDLE();
		if (!OpenProcessToken(process, TOKEN_QUERY, &raw)) {
			return;
		}
		const auto token = WindowsHandle(raw);
		auto elevation = TOKEN_ELEVATION();
		auto size = DWORD(0);
		if (!GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &size)
			|| elevation.TokenIsElevated) {
			return;
		}
		auto storage = std::vector<uint8_t>(sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE);
		if (!GetTokenInformation(token.get(), TokenUser, storage.data(), DWORD(storage.size()), &size)) {
			return;
		}
		const auto sid = reinterpret_cast<const TOKEN_USER*>(storage.data())->User.Sid;
		if (sid && IsValidSid(sid)) {
			_storage = std::move(storage);
		}
	}
	[[nodiscard]] PSID sid() const {
		return _storage.empty()
			? nullptr
			: reinterpret_cast<const TOKEN_USER*>(_storage.data())->User.Sid;
	}

private:
	std::vector<uint8_t> _storage;

};

bool OwnedBy(const WindowsHandle &file, PSID owner) {
	auto candidate = PSID();
	auto descriptor = PSECURITY_DESCRIPTOR();
	const auto result = GetSecurityInfo(
		file.get(),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		&candidate,
		nullptr,
		nullptr,
		nullptr,
		&descriptor);
	const auto matches = result == ERROR_SUCCESS && candidate && EqualSid(owner, candidate);
	if (descriptor) {
		LocalFree(descriptor);
	}
	return matches;
}

WindowsHandle OpenWindowsFile(const Path &path, DWORD access, DWORD sharing) {
	return WindowsHandle(CreateFileW(
		path.c_str(),
		access,
		sharing,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr));
}

std::optional<BY_HANDLE_FILE_INFORMATION> WindowsFileInfo(const WindowsHandle &handle) {
	auto info = BY_HANDLE_FILE_INFORMATION();
	if (!handle || GetFileType(handle.get()) != FILE_TYPE_DISK
		|| !GetFileInformationByHandle(handle.get(), &info)
		|| (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		|| (!info.nFileIndexHigh && !info.nFileIndexLow)) {
		return std::nullopt;
	}
	return info;
}

std::optional<FileIdentity> WindowsFileIdentity(
		const WindowsHandle &handle,
		const BY_HANDLE_FILE_INFORMATION &info) {
	auto basic = FILE_BASIC_INFO();
	if (!GetFileInformationByHandleEx(handle.get(), FileBasicInfo, &basic, sizeof(basic))) {
		return std::nullopt;
	}
	return FileIdentity{
		.device = info.dwVolumeSerialNumber,
		.inode = (uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow,
		.size = (uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow,
		.modifiedSeconds = TimeValue(info.ftLastWriteTime),
		.changedSeconds = uint64_t(basic.ChangeTime.QuadPart),
	};
}

std::optional<Digest> HashWindowsFile(const WindowsHandle &file, uint64_t size) {
	auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
		EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
		return std::nullopt;
	}
	auto buffer = std::array<uint8_t, 32 * 1024>{};
	while (size) {
		auto bytes = DWORD(0);
		if (!ReadFile(file.get(), buffer.data(), DWORD(std::min<uint64_t>(size, buffer.size())),
				&bytes, nullptr)
			|| !bytes || EVP_DigestUpdate(context.get(), buffer.data(), bytes) != 1) {
			return std::nullopt;
		}
		size -= bytes;
	}
	auto result = Digest();
	auto count = 0U;
	return EVP_DigestFinal_ex(context.get(), result.data(), &count) == 1 && count == result.size()
		? std::optional(result)
		: std::nullopt;
}

bool PinWindowsDirectory(
		Inspection &inspection,
		const Path &path,
		DWORD extraAccess,
		PSID owner = nullptr) {
	auto handle = OpenWindowsFile(
		path,
		FILE_READ_ATTRIBUTES | extraAccess | (owner ? READ_CONTROL : 0),
		FILE_SHARE_READ | FILE_SHARE_WRITE);
	const auto info = WindowsFileInfo(handle);
	if (!info || !(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		|| (owner && !OwnedBy(handle, owner))) {
		return false;
	}
	inspection.directories.push_back(std::move(handle));
	return true;
}

bool WindowsPortablePaths(const VerifiedInstallationReceipt &receipt, const Path &executable) {
	auto paths = std::set<Path>();
	const auto packaged = std::array{
		executable,
		Path(L"build-manifest.json"),
		Path(L"LICENSE-SQLCipher.txt"),
		Path(L"Updater.exe"),
		Path(L"modules/x64/d3d/d3dcompiler_47.dll"),
		Path(L"SleepyGramRemovalHelper.exe"),
	};
	for (const auto &artifact : receipt.artifacts) {
		if (std::ranges::find(packaged, artifact.relativePath) == packaged.end()
			|| !paths.insert(artifact.relativePath).second) {
			return false;
		}
	}
	return paths.contains(executable) && paths.contains(packaged[1]) && paths.contains(packaged[2]);
}

std::optional<ApprovedFile> InspectWindowsArtifact(
		Inspection &inspection,
		const Path &extendedRoot,
		const VerifiedInstallationArtifact &artifact,
		PSID owner,
		bool forDeletion) {
	auto path = extendedRoot;
	for (const auto &part : artifact.relativePath.parent_path()) {
		path /= part;
		if (!PinWindowsDirectory(inspection, path, 0, owner)) {
			return std::nullopt;
		}
	}
	path /= artifact.relativePath.filename();
	auto handle = OpenWindowsFile(
		path,
		GENERIC_READ | READ_CONTROL | (forDeletion ? DELETE : 0),
		FILE_SHARE_READ);
	const auto info = WindowsFileInfo(handle);
	if (!info || (info->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY
			| FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM))
		|| info->nNumberOfLinks != 1 || !OwnedBy(handle, owner)) {
		return std::nullopt;
	}
	const auto identity = WindowsFileIdentity(handle, *info);
	if (!identity || !identity->size || identity->size > kMaxArtifactBytes
		|| identity->device != inspection.rootIdentity.device
		|| HashWindowsFile(handle, identity->size) != artifact.digest) {
		return std::nullopt;
	}
	const auto checked = WindowsFileInfo(handle);
	if (!checked || checked->nNumberOfLinks != 1 || WindowsFileIdentity(handle, *checked) != identity) {
		return std::nullopt;
	}
	return ApprovedFile{
		.artifact = &artifact,
		.identity = *identity,
		.nativePath = std::move(path),
		.handle = std::move(handle),
	};
}

std::optional<Inspection> Inspect(const VerifiedInstallationReceipt &receipt, bool forDeletion) {
	const auto executable = Path(L"SleepyGram.exe");
	const auto root = WindowsDrivePath(receipt.packageRoot);
	const auto owner = ProcessOwner(GetCurrentProcess());
	if (receipt.kind != InstallationPackageKind::WindowsPortable
		|| !SafeIdentity(receipt.installationId.value) || !root || !owner.sid()
		|| receipt.artifacts.size() > 6 || !WindowsPortablePaths(receipt, executable)) {
		return std::nullopt;
	}
	const auto drive = GetDriveTypeW(root->root_path().c_str());
	if (drive != DRIVE_FIXED && drive != DRIVE_REMOVABLE) {
		return std::nullopt;
	}
	auto result = Inspection{ .executable = *root / executable };
	auto extended = ExtendedWindowsPath(root->root_path());
	if (!PinWindowsDirectory(result, extended, 0)) {
		return std::nullopt;
	}
	const auto relative = root->relative_path();
	for (const auto &part : relative.parent_path()) {
		extended /= part;
		if (!PinWindowsDirectory(result, extended, 0)) {
			return std::nullopt;
		}
	}
	extended /= relative.filename();
	if (!PinWindowsDirectory(result, extended, FILE_ADD_FILE, owner.sid())) {
		return std::nullopt;
	}
	const auto &directory = result.directories.back();
	const auto info = WindowsFileInfo(directory);
	const auto identity = info ? WindowsFileIdentity(directory, *info) : std::nullopt;
	if (!identity) {
		return std::nullopt;
	}
	result.rootIdentity = *identity;
	for (const auto &artifact : receipt.artifacts) {
		auto checked = InspectWindowsArtifact(result, extended, artifact, owner.sid(), forDeletion);
		if (!checked) {
			return std::nullopt;
		}
		result.files.push_back(std::move(*checked));
	}
	std::ranges::sort(result.files, {}, [](const auto &file) {
		return file.artifact->relativePath;
	});
	return result;
}

bool RemoveWindowsFiles(Inspection &inspection, bool &changed) {
	for (auto &file : inspection.files) {
		auto disposition = FILE_DISPOSITION_INFO{ .DeleteFile = TRUE };
		if (!SetFileInformationByHandle(
				file.handle.get(), FileDispositionInfo, &disposition, sizeof(disposition))) {
			return false;
		}
		changed = true;
		file.handle.reset();
		if (GetFileAttributesW(file.nativePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
			return false;
		}
		const auto error = GetLastError();
		if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
			return false;
		}
	}
	return true;
}
#endif

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
void AppendNumber(std::string &transcript, uint64_t value) {
	for (auto i = 0; i != 8; ++i) {
		transcript.push_back(char(value >> (8 * i)));
	}
}

void AppendString(std::string &transcript, std::string_view value) {
	AppendNumber(transcript, value.size());
	transcript.append(value);
}

void AppendPath(std::string &transcript, const Path &path) {
#ifdef _WIN32
	const auto &native = path.native();
	AppendNumber(transcript, native.size() * 2);
	for (const auto unit : native) {
		transcript.push_back(char(uint16_t(unit) & 0xff));
		transcript.push_back(char(uint16_t(unit) >> 8));
	}
#else
	AppendString(transcript, path.native());
#endif
}

void AppendIdentity(std::string &transcript, FileIdentity identity) {
	AppendNumber(transcript, identity.device);
	AppendNumber(transcript, identity.inode);
	AppendNumber(transcript, identity.size);
	AppendNumber(transcript, identity.modifiedSeconds);
	AppendNumber(transcript, identity.modifiedNanoseconds);
	AppendNumber(transcript, identity.changedSeconds);
	AppendNumber(transcript, identity.changedNanoseconds);
}

std::optional<Digest> TicketAuthentication(
		const VerifiedInstallationReceipt &receipt,
		const Inspection &inspected,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> secret) {
	if (secret.size() != kInstallationRemovalKeyBytes
		|| std::ranges::none_of(secret, [](auto byte) { return byte != 0; })
		|| receipt.dataCleanup.size() > kMaxInstallationRemovalDataBytes
		|| !SafeIdentity(ticket.operationId.value)) {
		return std::nullopt;
	}
	auto transcript = std::string("SleepyGram installation removal handoff v1");
	AppendString(transcript, receipt.installationId.value);
	AppendNumber(transcript, uint8_t(receipt.kind));
	AppendPath(transcript, receipt.packageRoot);
	AppendString(transcript, ticket.operationId.value);
	AppendNumber(transcript, ticket.parentProcessId);
#ifdef _WIN32
	AppendNumber(transcript, ticket.parentCreationTime);
#endif
	AppendNumber(transcript, inspected.rootIdentity.device);
	AppendNumber(transcript, inspected.rootIdentity.inode);
	AppendNumber(transcript, inspected.files.size());
	for (const auto &file : inspected.files) {
		AppendPath(transcript, file.artifact->relativePath);
		transcript.append(reinterpret_cast<const char*>(file.artifact->digest.data()),
			file.artifact->digest.size());
		AppendIdentity(transcript, file.identity);
	}
	if (!receipt.dataCleanup.empty()) {
		AppendString(transcript, std::string_view(
			reinterpret_cast<const char*>(receipt.dataCleanup.data()), receipt.dataCleanup.size()));
	}
	auto result = Digest{};
	auto size = 0U;
	if (!HMAC(
			EVP_sha256(),
			secret.data(),
			int(secret.size()),
			reinterpret_cast<const uint8_t*>(transcript.data()),
			transcript.size(),
			result.data(),
			&size)
		|| size != result.size()) {
		return std::nullopt;
	}
	return result;
}

bool MatchesTicket(
		const VerifiedInstallationReceipt &receipt,
		const Inspection &inspection,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> secret) {
	const auto proof = TicketAuthentication(receipt, inspection, ticket, secret);
	return proof
		&& CRYPTO_memcmp(proof->data(), ticket.authentication.data(), proof->size()) == 0;
}

#endif

} // namespace

InstallationRemovalCapability InspectInstallationRemoval(
		const VerifiedInstallationReceipt &receipt) {
	if (receipt.installationId.valid()
		&& receipt.kind == InstallationPackageKind::RegisteredPackage) {
		return InstallationRemovalCapability::OsConfirmationRequired;
	}
#ifdef _WIN32
	const auto inspected = Inspect(receipt, false);
	if (inspected && SameWindowsPath(ProcessExecutable(GetCurrentProcess()), inspected->executable)) {
		return InstallationRemovalCapability::Automatic;
	}
#elif defined(__APPLE__) || defined(__linux__)
	const auto inspected = Inspect(receipt);
	if (inspected && ProcessExecutable(getpid()) == inspected->executable) {
		return InstallationRemovalCapability::Automatic;
	}
#endif
	return InstallationRemovalCapability::Unavailable;
}

std::optional<InstallationRemovalTicket> MakeInstallationRemovalTicket(
		const VerifiedInstallationReceipt &receipt,
		const EmergencyActionJournal &completedCleanup,
		std::span<const uint8_t> handoffSecret) {
	if (completedCleanup.installationId != receipt.installationId
		|| completedCleanup.action != EmergencyAction::RemoveInstallation
		|| completedCleanup.targetScope != TargetScope::CurrentInstallation
		|| completedCleanup.installationRemoval.state != EffectState::InProgress
		|| !std::ranges::all_of(completedCleanup.accounts, [](const auto &account) {
			return account.localDataClear.state == EffectState::Succeeded;
		}) || EncodeJournal(completedCleanup).empty()
		|| handoffSecret.size() != kInstallationRemovalKeyBytes) {
		return std::nullopt;
	}
#ifdef _WIN32
	const auto inspected = Inspect(receipt, false);
	const auto process = GetCurrentProcess();
	const auto creation = CreationTime(process);
	if (inspected && creation && SameWindowsPath(ProcessExecutable(process), inspected->executable)) {
		auto result = InstallationRemovalTicket{
			.operationId = completedCleanup.operationId,
			.parentProcessId = GetCurrentProcessId(),
			.parentCreationTime = *creation,
		};
		const auto authentication = TicketAuthentication(receipt, *inspected, result, handoffSecret);
		if (authentication) {
			result.authentication = *authentication;
			return result;
		}
	}
#elif defined(__APPLE__) || defined(__linux__)
	const auto inspected = Inspect(receipt);
	if (inspected && ProcessExecutable(getpid()) == inspected->executable) {
		auto result = InstallationRemovalTicket{
			.operationId = completedCleanup.operationId,
			.parentProcessId = uint64_t(getpid()),
		};
		if (const auto authentication = TicketAuthentication(receipt, *inspected, result, handoffSecret)) {
			result.authentication = *authentication;
			return result;
		}
	}
#endif
	return std::nullopt;
}

InstallationRemovalResult InstallationRemovalReceiver::RemoveAfterParentExit(
		const InstallationId &expectedInstallation,
		const VerifiedInstallationReceipt &receipt,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> handoffSecret,
		std::chrono::milliseconds timeout,
		const std::function<bool()> &acknowledge,
		InstallationRemovalProcessHandle inheritedParent,
		const InstallationRemovalDataEffects &dataEffects) {
	if (_used.exchange(true) || !expectedInstallation.valid()
		|| receipt.installationId != expectedInstallation
		|| !ticket.operationId.valid()
		|| handoffSecret.size() != kInstallationRemovalKeyBytes
		|| !acknowledge
		|| (bool(dataEffects.clear) != !receipt.dataCleanup.empty())
		|| (bool(dataEffects.finalize) != !receipt.dataCleanup.empty())
		|| (dataEffects.refuse && receipt.dataCleanup.empty())
		|| timeout < std::chrono::milliseconds::zero()
		|| timeout > std::chrono::minutes(5)) {
		return InstallationRemovalResult::TicketRejected;
	}
#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
	const auto refuse = [&](InstallationRemovalResult result) {
		return dataEffects.refuse && !dataEffects.refuse()
			? InstallationRemovalResult::RefusalNotRecorded
			: result;
	};
#endif
#ifdef _WIN32
	const auto parent = DuplicateParentHandle(inheritedParent);
	if (!parent || !ticket.parentProcessId || ticket.parentProcessId == GetCurrentProcessId()
		|| ticket.parentProcessId != GetProcessId(parent.get())
		|| !ticket.parentCreationTime || CreationTime(parent.get()) != ticket.parentCreationTime
		|| WaitForSingleObject(parent.get(), 0) != WAIT_TIMEOUT) {
		return InstallationRemovalResult::ParentUnavailable;
	}
	{
		const auto owner = ProcessOwner(GetCurrentProcess());
		const auto parentOwner = ProcessOwner(parent.get());
		const auto inspected = Inspect(receipt, false);
		if (!inspected || !owner.sid() || !parentOwner.sid()
			|| !EqualSid(owner.sid(), parentOwner.sid())
			|| !SameWindowsPath(ProcessExecutable(parent.get()), inspected->executable)) {
			return InstallationRemovalResult::InstallationChanged;
		}
		if (!MatchesTicket(receipt, *inspected, ticket, handoffSecret)) {
			return InstallationRemovalResult::TicketRejected;
		}
	}
	if (WaitForSingleObject(parent.get(), 0) != WAIT_TIMEOUT || !acknowledge()) {
		return InstallationRemovalResult::ParentUnavailable;
	}
	const auto wait = WaitForSingleObject(parent.get(), DWORD(timeout.count()));
	if (wait != WAIT_OBJECT_0) {
		return (wait == WAIT_TIMEOUT)
			? InstallationRemovalResult::ParentStillRunning
			: InstallationRemovalResult::ParentUnavailable;
	}
	if (dataEffects.clear && !dataEffects.clear()) {
		return InstallationRemovalResult::Partial;
	}
	auto ready = Inspect(receipt, true);
	if (!ready) {
		const auto current = Inspect(receipt, false);
		return (current && MatchesTicket(receipt, *current, ticket, handoffSecret))
			? InstallationRemovalResult::Partial
			: refuse(InstallationRemovalResult::InstallationChanged);
	}
	if (!MatchesTicket(receipt, *ready, ticket, handoffSecret)) {
		return refuse(InstallationRemovalResult::InstallationChanged);
	}
	auto changed = false;
	if (!RemoveWindowsFiles(*ready, changed)) {
		ready.reset();
		return changed ? refuse(InstallationRemovalResult::Partial) : InstallationRemovalResult::Partial;
	}
	return (!dataEffects.finalize || dataEffects.finalize())
		? InstallationRemovalResult::Removed
		: InstallationRemovalResult::Partial;
#elif defined(__APPLE__) || defined(__linux__)
	const auto parent = getppid();
	if (inheritedParent.value || ticket.parentCreationTime
		|| parent <= 1 || ticket.parentProcessId != uint64_t(parent)) {
		return InstallationRemovalResult::ParentUnavailable;
	}
	const auto inspected = Inspect(receipt);
	if (!inspected || ProcessExecutable(parent) != inspected->executable
		|| getppid() != parent) {
		return InstallationRemovalResult::InstallationChanged;
	}
	if (!MatchesTicket(receipt, *inspected, ticket, handoffSecret)) {
		return InstallationRemovalResult::TicketRejected;
	}
	if (!acknowledge()) {
		return InstallationRemovalResult::ParentUnavailable;
	}
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	while (getppid() == parent) {
		if (std::chrono::steady_clock::now() >= deadline) {
			return InstallationRemovalResult::ParentStillRunning;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	if (dataEffects.clear && !dataEffects.clear()) {
		return InstallationRemovalResult::Partial;
	}
	const auto ready = Inspect(receipt);
	if (!ready || !MatchesTicket(receipt, *ready, ticket, handoffSecret)) {
		return refuse(InstallationRemovalResult::InstallationChanged);
	}
	auto changed = false;
	for (const auto &file : ready->files) {
		if (!RemoveFile(ready->root.get(), file)) {
			if (changed) {
				return refuse(InstallationRemovalResult::Partial);
			}
			const auto current = Inspect(receipt);
			if (!current || !MatchesTicket(receipt, *current, ticket, handoffSecret)) {
				return refuse(InstallationRemovalResult::InstallationChanged);
			}
			return InstallationRemovalResult::Partial;
		}
		changed = true;
	}
	if (receipt.kind == InstallationPackageKind::MacBundle
		&& !RemoveEmptyBundleDirectories(*ready)) {
		return refuse(InstallationRemovalResult::Partial);
	}
	return (!dataEffects.finalize || dataEffects.finalize())
		? InstallationRemovalResult::Removed : InstallationRemovalResult::Partial;
#else
	if (inheritedParent.value) {
		return InstallationRemovalResult::ParentUnavailable;
	}
	return InstallationRemovalResult::Unavailable;
#endif
}

} // namespace Ayu::EmergencyActions
