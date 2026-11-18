// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/installation_removal_launcher.h"

#include "ayu/features/emergency_actions/installation_removal_handoff.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <memory>
#include <ranges>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#elif defined(__APPLE__) || defined(__linux__)
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <dirent.h>
#include <dlfcn.h>
#endif
#endif

namespace Ayu::EmergencyActions {
namespace {

using Result = InstallationRemovalLaunchResult;
#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
using Path = std::filesystem::path;
using Clock = std::chrono::steady_clock;
constexpr auto kMaxHelperBytes = uint64_t(128) * 1024 * 1024;

struct OneTimeSecret final {
	~OneTimeSecret() {
		OPENSSL_cleanse(bytes.data(), bytes.size());
	}

	InstallationArtifactDigest bytes{};
};

bool SafePath(const Path &path) {
	return path.is_absolute() && path.has_relative_path()
		&& path.native().find(Path::value_type(0)) == Path::string_type::npos
		&& std::ranges::none_of(path.relative_path(), [](const Path &part) {
			return part.empty() || part == "." || part == "..";
		});
}

template <typename Read, typename Write>
bool CopyVerifiedHelper(
		Read &&read,
		Write &&write,
		const InstallationArtifactDigest &expected) {
	auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
		EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
		return false;
	}
	auto total = uint64_t(0);
	auto buffer = std::array<uint8_t, 64 * 1024>{};
	for (;;) {
		const auto count = read(std::span<uint8_t>(buffer));
		if (!count || *count > buffer.size()) {
			return false;
		}
		if (!*count) {
			break;
		}
		total += *count;
		const auto data = std::span<const uint8_t>(buffer).first(*count);
		if (total > kMaxHelperBytes
			|| EVP_DigestUpdate(context.get(), data.data(), data.size()) != 1
			|| !write(data)) {
			return false;
		}
	}
	auto digest = InstallationArtifactDigest();
	auto size = 0U;
	return total && EVP_DigestFinal_ex(context.get(), digest.data(), &size) == 1
		&& size == digest.size()
		&& CRYPTO_memcmp(digest.data(), expected.data(), digest.size()) == 0;
}

int Remaining(Clock::time_point deadline) {
	const auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now());
	return int(std::max(left, std::chrono::milliseconds::zero()).count());
}
#endif

#if defined(__APPLE__) || defined(__linux__)
using Stat = struct stat;
constexpr auto kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
constexpr auto kHelperFilename = "sleepygram-remove";

class Descriptor final {
public:
	explicit Descriptor(int fd = -1) : _fd(fd) {
	}
	Descriptor(Descriptor &&other) noexcept
	: _fd(std::exchange(other._fd, -1)) {
	}
	Descriptor &operator=(Descriptor &&other) noexcept {
		std::swap(_fd, other._fd);
		return *this;
	}
	~Descriptor() {
		close();
	}

	void close() {
		if (*this) {
			::close(std::exchange(_fd, -1));
		}
	}
	[[nodiscard]] explicit operator bool() const {
		return _fd >= 0;
	}
	[[nodiscard]] int get() const {
		return _fd;
	}

private:
	int _fd = -1;

};

Descriptor AboveStdio(Descriptor fd) {
	if (fd && fd.get() > STDERR_FILENO) {
		return fd;
	}
	return Descriptor(fd ? fcntl(fd.get(), F_DUPFD_CLOEXEC, STDERR_FILENO + 1) : -1);
}

Descriptor OpenDirectory(const Path &path) {
	auto current = Descriptor(open("/", kDirectoryFlags));
	for (const auto &part : path.relative_path()) {
		if (!current) {
			return Descriptor();
		}
		current = Descriptor(openat(current.get(), part.c_str(), kDirectoryFlags));
	}
	return current;
}

bool Within(const Path &path, const Path &parent) {
	const auto relative = path.lexically_relative(parent);
	return !relative.empty() && *relative.begin() != "..";
}

class StagedHelper final {
public:
	StagedHelper(Path path, Descriptor directory)
	: _path(std::move(path))
	, _directory(std::move(directory)) {
	}
	~StagedHelper() {
		if (_directory) {
			unlinkat(_directory.get(), kHelperFilename, 0);
			auto pinned = Stat{};
			auto current = Stat{};
			if (!fstat(_directory.get(), &pinned) && !lstat(_path.c_str(), &current)
				&& pinned.st_ino == current.st_ino && pinned.st_dev == current.st_dev
				&& S_ISDIR(current.st_mode)) {
				rmdir(_path.c_str());
			}
		}
	}

	[[nodiscard]] const Descriptor &directory() const {
		return _directory;
	}
	[[nodiscard]] Path executable() const {
		return _path / kHelperFilename;
	}

private:
	Path _path;
	Descriptor _directory;

};

std::unique_ptr<StagedHelper> StageHelper(
		const VerifiedInstallationRemovalHelper &helper,
		const Path &installationRoot) {
	if (!SafePath(helper.source) || !SafePath(installationRoot)) {
		return nullptr;
	}
	const auto sourceParent = OpenDirectory(helper.source.parent_path());
	const auto input = Descriptor(sourceParent ? openat(
		sourceParent.get(),
		helper.source.filename().c_str(),
		O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC) : -1);
	auto info = Stat{};
	if (!input || fstat(input.get(), &info) || !S_ISREG(info.st_mode)
		|| info.st_nlink != 1 || info.st_size <= 0 || uint64_t(info.st_size) > kMaxHelperBytes
		|| (info.st_uid != geteuid() && info.st_uid != 0) || (info.st_mode & 0022)) {
		return nullptr;
	}
	auto ec = std::error_code();
	const auto temporary = std::filesystem::temp_directory_path(ec);
	if (ec) {
		return nullptr;
	}
	const auto parent = std::filesystem::canonical(temporary, ec);
	const auto package = std::filesystem::canonical(installationRoot, ec);
	if (ec || !SafePath(parent) || Within(parent, package)) {
		return nullptr;
	}
	auto name = (parent / "sleepygram-remove.XXXXXX").native();
	if (!mkdtemp(name.data())) {
		return nullptr;
	}
	const auto path = Path(name);
	auto directory = OpenDirectory(path);
	if (!directory) {
		rmdir(path.c_str());
		return nullptr;
	}
	auto stage = std::make_unique<StagedHelper>(path, std::move(directory));
	auto owned = Stat{};
	if (!stage->directory() || fstat(stage->directory().get(), &owned)
		|| owned.st_uid != geteuid() || (owned.st_mode & 0077)) {
		return nullptr;
	}
	const auto output = Descriptor(openat(
		stage->directory().get(),
		kHelperFilename,
		O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		0600));
	if (!output) {
		return nullptr;
	}
	const auto read = [](const Descriptor &file, std::span<uint8_t> bytes) -> std::optional<size_t> {
		auto size = ssize_t(0);
		do {
			size = ::read(file.get(), bytes.data(), bytes.size());
		} while (size < 0 && errno == EINTR);
		return size >= 0 ? std::optional(size_t(size)) : std::nullopt;
	};
	const auto write = [&](std::span<const uint8_t> bytes) {
		while (!bytes.empty()) {
			const auto size = ::write(output.get(), bytes.data(), bytes.size());
			if (size < 0 && errno == EINTR) {
				continue;
			}
			if (size <= 0) {
				return false;
			}
			bytes = bytes.subspan(size_t(size));
		}
		return true;
	};
	const auto readSource = [&](std::span<uint8_t> bytes) { return read(input, bytes); };
	const auto readStaged = [&](std::span<uint8_t> bytes) { return read(output, bytes); };
	return CopyVerifiedHelper(readSource, write, helper.digest)
		&& lseek(output.get(), 0, SEEK_SET) == 0
		&& CopyVerifiedHelper(readStaged, [](std::span<const uint8_t>) { return true; }, helper.digest)
		&& !fchmod(output.get(), 0500) && !fsync(output.get())
		? std::move(stage)
		: nullptr;
}

struct Pipe final {
	Descriptor input;
	Descriptor output;
};

Pipe MakePipe() {
	auto fds = std::array<int, 2>{};
#ifdef __linux__
	if (pipe2(fds.data(), O_CLOEXEC)) {
		return { Descriptor(), Descriptor() };
	}
#else
	if (pipe(fds.data())) {
		return { Descriptor(), Descriptor() };
	}
#endif
	auto input = AboveStdio(Descriptor(fds[0]));
	auto output = AboveStdio(Descriptor(fds[1]));
	if (!input || !output || fcntl(input.get(), F_SETFD, FD_CLOEXEC)
		|| fcntl(output.get(), F_SETFD, FD_CLOEXEC)) {
		return { Descriptor(), Descriptor() };
	}
	return { std::move(input), std::move(output) };
}

bool Nonblocking(const Descriptor &fd) {
	const auto flags = fcntl(fd.get(), F_GETFL);
	return flags >= 0 && !fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK);
}

class SpawnActions final {
public:
	SpawnActions()
	: initialized(posix_spawn_file_actions_init(&actions) == 0) {
	}
	~SpawnActions() {
		if (initialized) {
			posix_spawn_file_actions_destroy(&actions);
		}
	}

	posix_spawn_file_actions_t actions{};
	bool initialized = false;

};

class SpawnAttributes final {
public:
	SpawnAttributes()
	: initialized(posix_spawnattr_init(&attributes) == 0) {
	}
	~SpawnAttributes() {
		if (initialized) {
			posix_spawnattr_destroy(&attributes);
		}
	}

	posix_spawnattr_t attributes{};
	bool initialized = false;

};

#ifdef __linux__
bool CloseInheritedDescriptors(posix_spawn_file_actions_t &actions) {
	using CloseFrom = int (*)(posix_spawn_file_actions_t*, int);
	const auto closeFrom = reinterpret_cast<CloseFrom>(
		dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_addclosefrom_np"));
	if (closeFrom) {
		return !closeFrom(&actions, STDERR_FILENO + 1);
	}
	const auto closeDirectory = [](DIR *dir) { closedir(dir); };
	const auto directory = std::unique_ptr<DIR, decltype(closeDirectory)>(
		opendir("/proc/self/fd"), closeDirectory);
	if (!directory) {
		return false;
	}
	const auto reader = dirfd(directory.get());
	for (;;) {
		errno = 0;
		const auto entry = readdir(directory.get());
		if (!entry) {
			return errno == 0;
		}
		const auto name = std::string_view(entry->d_name);
		auto fd = 0;
		const auto parsed = std::from_chars(name.data(), name.data() + name.size(), fd);
		if (parsed.ec == std::errc() && parsed.ptr == name.data() + name.size()
			&& fd > STDERR_FILENO && fd != reader
			&& posix_spawn_file_actions_addclose(&actions, fd)) {
			return false;
		}
	}
}
#endif

pid_t SpawnHelper(
		const Path &helper,
		const InstallationId &installation,
		std::chrono::milliseconds timeout,
		const Pipe &request,
		const Pipe &reply) {
	const auto null = AboveStdio(Descriptor(open("/dev/null", O_WRONLY | O_CLOEXEC)));
	auto actions = SpawnActions();
	auto attributes = SpawnAttributes();
	if (!null || !actions.initialized || !attributes.initialized
		|| posix_spawn_file_actions_adddup2(&actions.actions, request.input.get(), STDIN_FILENO)
		|| posix_spawn_file_actions_adddup2(&actions.actions, reply.output.get(), STDOUT_FILENO)
		|| posix_spawn_file_actions_adddup2(&actions.actions, null.get(), STDERR_FILENO)) {
		return -1;
	}
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
	if (posix_spawnattr_setflags(&attributes.attributes, POSIX_SPAWN_CLOEXEC_DEFAULT)) {
		return -1;
	}
#elif defined(__linux__)
	if (!CloseInheritedDescriptors(actions.actions)) {
		return -1;
	}
#endif
	auto name = helper.native();
	auto install = installation.value;
	auto delay = std::to_string(timeout.count());
	auto arguments = std::array<char*, 4>{ name.data(), install.data(), delay.data(), nullptr };
	auto environment = std::array<char*, 1>{ nullptr };
	auto pid = pid_t(-1);
	return !posix_spawn(
		&pid, name.c_str(), &actions.actions, &attributes.attributes, arguments.data(), environment.data())
		? pid
		: pid_t(-1);
}

void Reap(pid_t pid) {
	auto waited = pid_t(0);
	do {
		waited = waitpid(pid, nullptr, 0);
	} while (waited < 0 && errno == EINTR);
}

class ChildProcess final {
public:
	explicit ChildProcess(pid_t pid) : _pid(pid) {
	}
	~ChildProcess() {
		if (_pid > 0) {
			auto active = pid_t(0);
			do {
				active = waitpid(_pid, nullptr, WNOHANG);
			} while (active < 0 && errno == EINTR);
			if (!active) {
				kill(_pid, SIGKILL);
				Reap(_pid);
			}
		}
	}
	[[nodiscard]] bool detach() {
		try {
			auto reaper = std::thread([pid = _pid] { Reap(pid); });
			reaper.detach();
			_pid = -1;
			return true;
		} catch (const std::system_error &) {
			return false;
		}
	}

private:
	pid_t _pid = -1;

};

bool Await(int fd, short event, Clock::time_point deadline) {
	while (Remaining(deadline)) {
		auto monitor = pollfd{ .fd = fd, .events = event };
		const auto result = poll(&monitor, 1, Remaining(deadline));
		if (result < 0 && errno == EINTR) {
			continue;
		}
		return result == 1 && (monitor.revents & (event | POLLHUP));
	}
	return false;
}

Result LaunchNative(
		const VerifiedInstallationRemovalHelper &helper,
		const VerifiedInstallationReceipt &receipt,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> secret,
		std::chrono::milliseconds timeout) {
	auto stage = StageHelper(helper, receipt.packageRoot);
	if (!stage) {
		return Result::HelperUnavailable;
	}
	auto signals = sigset_t();
	using SignalAction = struct sigaction;
	auto signalAction = SignalAction{};
	if (sigemptyset(&signals) || sigaddset(&signals, SIGPIPE)
		|| pthread_sigmask(SIG_BLOCK, &signals, nullptr)
		|| sigaction(SIGCHLD, nullptr, &signalAction)
		|| signalAction.sa_handler == SIG_IGN || (signalAction.sa_flags & SA_NOCLDWAIT)) {
		return Result::TransportFailed;
	}
	auto request = MakePipe();
	auto reply = MakePipe();
	if (!request.input || !request.output || !reply.input || !reply.output
		|| !Nonblocking(request.output) || !Nonblocking(reply.input)) {
		return Result::TransportFailed;
	}
	const auto pid = SpawnHelper(stage->executable(), receipt.installationId, timeout, request, reply);
	if (pid <= 0) {
		return Result::HelperUnavailable;
	}
	auto child = ChildProcess(pid);
	request.input.close();
	reply.output.close();
	const auto deadline = Clock::now() + timeout;
	const auto write = [&](std::span<const uint8_t> bytes) -> std::optional<size_t> {
		while (Await(request.output.get(), POLLOUT, deadline)) {
			const auto count = ::write(request.output.get(), bytes.data(), bytes.size());
			if (count < 0 && (errno == EINTR || errno == EAGAIN)) {
				continue;
			}
			return count > 0 ? std::optional(size_t(count)) : std::nullopt;
		}
		return std::nullopt;
	};
	const auto sent = WriteInstallationRemovalHandoff(receipt, ticket, secret, write);
	request.output.close();
	if (!sent) {
		return Remaining(deadline)
			? Result::TransportFailed
			: Result::AcknowledgmentUnconfirmed;
	}
	auto ack = uint8_t(0);
	while (Await(reply.input.get(), POLLIN, deadline)) {
		const auto count = ::read(reply.input.get(), &ack, 1);
		if (count < 0 && (errno == EINTR || errno == EAGAIN)) {
			continue;
		}
		if (count == 1 && ack == kInstallationRemovalHandoffAck && child.detach()) {
			return Result::ReadyToExit;
		}
		break;
	}
	return Result::AcknowledgmentUnconfirmed;
}
#elif defined(_WIN32)

constexpr auto kHelperFilename = L"sleepygram-remove.exe";
constexpr auto kParentAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;

class Handle final {
public:
	explicit Handle(HANDLE handle = nullptr) : _handle(handle) {
	}
	Handle(Handle &&other) noexcept
	: _handle(std::exchange(other._handle, nullptr)) {
	}
	Handle &operator=(Handle &&other) noexcept {
		std::swap(_handle, other._handle);
		return *this;
	}
	~Handle() {
		close();
	}

	void close() {
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

std::optional<Path> DrivePath(Path path) {
	path.make_preferred();
	constexpr auto prefix = std::wstring_view(L"\\\\?\\");
	if (path.native().starts_with(prefix)) {
		path = Path(path.native().substr(prefix.size()));
	}
	const auto drive = path.root_name().native();
	if (!SafePath(path) || drive.size() != 2 || drive[1] != L':'
		|| !((drive[0] >= L'A' && drive[0] <= L'Z')
			|| (drive[0] >= L'a' && drive[0] <= L'z'))
		|| std::ranges::any_of(path.relative_path(), [](const Path &part) {
			const auto &text = part.native();
			return text.back() == L'.' || text.back() == L' '
				|| text.find_first_of(L"<>:\"|?*") != std::wstring::npos;
		})) {
		return std::nullopt;
	}
	return path;
}

bool Within(const Path &path, const Path &parent) {
	auto current = path.begin();
	for (const auto &element : parent) {
		if (current == path.end() || CompareStringOrdinal(
				current->c_str(), int(current->native().size()),
				element.c_str(), int(element.native().size()), TRUE) != CSTR_EQUAL) {
			return false;
		}
		++current;
	}
	return true;
}

Path Extended(const Path &path) {
	return Path(L"\\\\?\\" + path.native());
}

Handle OpenExisting(const Path &path, DWORD access, DWORD sharing) {
	return Handle(CreateFileW(
		path.c_str(), access, sharing, nullptr, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
}

std::optional<BY_HANDLE_FILE_INFORMATION> Info(const Handle &handle) {
	auto info = BY_HANDLE_FILE_INFORMATION();
	return handle && GetFileType(handle.get()) == FILE_TYPE_DISK
		&& GetFileInformationByHandle(handle.get(), &info)
		&& !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		? std::optional(info)
		: std::nullopt;
}

bool PinDirectories(const Path &path, std::vector<Handle> &ancestors) {
	auto current = Extended(path.root_path());
	const auto pin = [&] {
		auto opened = OpenExisting(
			current, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE);
		const auto info = Info(opened);
		if (!info || !(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			return false;
		}
		ancestors.push_back(std::move(opened));
		return true;
	};
	if (!pin()) {
		return false;
	}
	for (const auto &part : path.relative_path()) {
		current /= part;
		if (!pin()) {
			return false;
		}
	}
	return true;
}

bool CreatePrivateDirectory(const Path &path) {
	auto tokenHandle = HANDLE();
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
		return false;
	}
	const auto token = Handle(tokenHandle);
	auto buffer = std::vector<uint8_t>(sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE);
	auto size = DWORD(0);
	if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), DWORD(buffer.size()), &size)) {
		return false;
	}
	const auto sid = reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid;
	if (!sid || !IsValidSid(sid)) {
		return false;
	}
	auto ace = EXPLICIT_ACCESS_W();
	ace.grfAccessPermissions = GENERIC_ALL;
	ace.grfAccessMode = SET_ACCESS;
	ace.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	BuildTrusteeWithSidW(&ace.Trustee, sid);
	auto rawAcl = PACL();
	if (SetEntriesInAclW(1, &ace, nullptr, &rawAcl) != ERROR_SUCCESS) {
		return false;
	}
	const auto acl = std::unique_ptr<ACL, decltype(&LocalFree)>(rawAcl, LocalFree);
	auto descriptor = SECURITY_DESCRIPTOR();
	if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION)
		|| !SetSecurityDescriptorDacl(&descriptor, TRUE, acl.get(), FALSE)
		|| !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
		return false;
	}
	auto security = SECURITY_ATTRIBUTES{
		.nLength = sizeof(SECURITY_ATTRIBUTES),
		.lpSecurityDescriptor = &descriptor,
		.bInheritHandle = FALSE,
	};
	return CreateDirectoryW(path.c_str(), &security);
}

class StagedHelper final {
public:
	StagedHelper(Path path, std::vector<Handle> parents, Handle directory)
	: _path(std::move(path))
	, _parents(std::move(parents))
	, _directory(std::move(directory)) {
	}
	~StagedHelper() {
		_verifiedFile.close();
		if (_fileIdentity) {
			const auto file = OpenExisting(
				Extended(executable()), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ);
			const auto live = Info(file);
			if (live && matches(*live)) {
				auto disposition = FILE_DISPOSITION_INFO{ .DeleteFile = TRUE };
				SetFileInformationByHandle(
					file.get(), FileDispositionInfo, &disposition, sizeof(disposition));
			}
		}
		_directory.close();
		RemoveDirectoryW(Extended(_path).c_str());
	}

	[[nodiscard]] Path executable() const {
		return _path / kHelperFilename;
	}
	void noteIdentity(BY_HANDLE_FILE_INFORMATION identity) {
		_fileIdentity = identity;
	}
	[[nodiscard]] bool matches(const BY_HANDLE_FILE_INFORMATION &info) const {
		return _fileIdentity && info.nNumberOfLinks == 1
			&& !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			&& info.dwVolumeSerialNumber == _fileIdentity->dwVolumeSerialNumber
			&& info.nFileIndexHigh == _fileIdentity->nFileIndexHigh
			&& info.nFileIndexLow == _fileIdentity->nFileIndexLow;
	}
	void seal(Handle file) {
		_verifiedFile = std::move(file);
	}

private:
	Path _path;
	std::vector<Handle> _parents;
	Handle _directory;
	Handle _verifiedFile;
	std::optional<BY_HANDLE_FILE_INFORMATION> _fileIdentity;

};

std::shared_ptr<StagedHelper> StageHelper(
		const VerifiedInstallationRemovalHelper &helper,
		const Path &installationRoot) {
	const auto source = DrivePath(helper.source);
	const auto package = DrivePath(installationRoot);
	if (!source || !package) {
		return nullptr;
	}
	auto sourceParents = std::vector<Handle>();
	if (!PinDirectories(source->parent_path(), sourceParents)) {
		return nullptr;
	}
	const auto input = OpenExisting(Extended(*source), GENERIC_READ, FILE_SHARE_READ);
	const auto info = Info(input);
	const auto length = info ? (uint64_t(info->nFileSizeHigh) << 32) | info->nFileSizeLow : 0;
	if (!info || (info->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE))
		|| info->nNumberOfLinks != 1 || !length || length > kMaxHelperBytes) {
		return nullptr;
	}
	auto ec = std::error_code();
	const auto temporary = std::filesystem::temp_directory_path(ec);
	if (ec) {
		return nullptr;
	}
	const auto parent = DrivePath(std::filesystem::canonical(temporary, ec));
	if (ec || !parent || Within(*parent, *package)) {
		return nullptr;
	}
	auto parents = std::vector<Handle>();
	if (!PinDirectories(*parent, parents)) {
		return nullptr;
	}
	auto nonce = std::array<uint8_t, 16>();
	if (RAND_bytes(nonce.data(), int(nonce.size())) != 1) {
		return nullptr;
	}
	constexpr auto digits = std::wstring_view(L"0123456789abcdef");
	auto name = std::wstring(L"sleepygram-remove.");
	for (const auto byte : nonce) {
		name.push_back(digits[byte >> 4]);
		name.push_back(digits[byte & 15]);
	}
	const auto path = *parent / name;
	if (!CreatePrivateDirectory(Extended(path))) {
		return nullptr;
	}
	auto directory = OpenExisting(
		Extended(path), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE);
	const auto openedDirectory = Info(directory);
	if (!openedDirectory || !(openedDirectory->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		directory.close();
		RemoveDirectoryW(Extended(path).c_str());
		return nullptr;
	}
	auto stage = std::make_shared<StagedHelper>(path, std::move(parents), std::move(directory));
	auto output = Handle(CreateFileW(
		Extended(stage->executable()).c_str(),
		GENERIC_WRITE,
		0,
		nullptr,
		CREATE_NEW,
		FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr));
	const auto fresh = Info(output);
	if (!fresh || (fresh->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		|| fresh->nNumberOfLinks != 1 || (!fresh->nFileIndexHigh && !fresh->nFileIndexLow)) {
		return nullptr;
	}
	stage->noteIdentity(*fresh);
	const auto read = [](const Handle &file, std::span<uint8_t> bytes) -> std::optional<size_t> {
		auto count = DWORD(0);
		return ReadFile(file.get(), bytes.data(), DWORD(bytes.size()), &count, nullptr)
			? std::optional(size_t(count))
			: std::nullopt;
	};
	const auto write = [&](std::span<const uint8_t> bytes) {
		while (!bytes.empty()) {
			auto count = DWORD(0);
			if (!WriteFile(output.get(), bytes.data(), DWORD(bytes.size()), &count, nullptr)
				|| !count || count > bytes.size()) {
				return false;
			}
			bytes = bytes.subspan(count);
		}
		return true;
	};
	const auto readSource = [&](std::span<uint8_t> bytes) { return read(input, bytes); };
	if (!CopyVerifiedHelper(readSource, write, helper.digest) || !FlushFileBuffers(output.get())) {
		return nullptr;
	}
	output.close();
	auto pinned = OpenExisting(Extended(stage->executable()), GENERIC_READ, FILE_SHARE_READ);
	const auto readback = Info(pinned);
	const auto readStaged = [&](std::span<uint8_t> bytes) { return read(pinned, bytes); };
	if (!readback || !stage->matches(*readback)
		|| !CopyVerifiedHelper(readStaged, [](std::span<const uint8_t>) { return true; }, helper.digest)) {
		return nullptr;
	}
	stage->seal(std::move(pinned));
	return stage;
}

struct Pipe final {
	Handle input;
	Handle output;
};

Pipe MakePipe() {
	auto input = HANDLE();
	auto output = HANDLE();
	if (!CreatePipe(&input, &output, nullptr, 0)) {
		return { Handle(), Handle() };
	}
	return { Handle(input), Handle(output) };
}

Handle SpawnHelper(
		const Path &helper,
		const InstallationId &installation,
		std::chrono::milliseconds timeout,
		const Pipe &request,
		const Pipe &reply) {
	auto parentHandle = HANDLE();
	if (!DuplicateHandle(
			GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &parentHandle,
			kParentAccess, TRUE, 0)) {
		return Handle();
	}
	const auto parent = Handle(parentHandle);
	auto security = SECURITY_ATTRIBUTES{
		.nLength = sizeof(SECURITY_ATTRIBUTES),
		.bInheritHandle = TRUE,
	};
	const auto null = Handle(CreateFileW(
		L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!null
		|| !SetHandleInformation(request.input.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
		|| !SetHandleInformation(reply.output.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
		return Handle();
	}
	auto required = SIZE_T(0);
	InitializeProcThreadAttributeList(nullptr, 1, 0, &required);
	if (!required) {
		return Handle();
	}
	auto storage = std::vector<uint8_t>(required);
	auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
	if (!InitializeProcThreadAttributeList(attributes, 1, 0, &required)) {
		return Handle();
	}
	const auto owner = std::unique_ptr<
		std::remove_pointer_t<LPPROC_THREAD_ATTRIBUTE_LIST>,
		decltype(&DeleteProcThreadAttributeList)>(attributes, DeleteProcThreadAttributeList);
	auto inherited = std::array{ request.input.get(), reply.output.get(), null.get(), parent.get() };
	if (!UpdateProcThreadAttribute(
			owner.get(), 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(),
			sizeof(inherited), nullptr, nullptr)) {
		return Handle();
	}
	auto startup = STARTUPINFOEXW();
	startup.StartupInfo.cb = sizeof(startup);
	startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	startup.StartupInfo.hStdInput = request.input.get();
	startup.StartupInfo.hStdOutput = reply.output.get();
	startup.StartupInfo.hStdError = null.get();
	startup.lpAttributeList = owner.get();
	const auto id = std::wstring(installation.value.begin(), installation.value.end());
	auto args = L"\"" + helper.native() + L"\" " + id + L" "
		+ std::to_wstring(timeout.count()) + L" "
		+ std::to_wstring(reinterpret_cast<uintptr_t>(parent.get()));
	auto system = std::array<wchar_t, 1024>{};
	const auto characters = GetWindowsDirectoryW(system.data(), UINT(system.size()));
	if (!characters || characters >= system.size()) {
		return Handle();
	}
	auto environment = std::wstring(L"SystemRoot=") + system.data();
	environment.push_back(L'\0');
	auto process = PROCESS_INFORMATION();
	if (!CreateProcessW(
			helper.c_str(),
			args.data(),
			nullptr,
			nullptr,
			TRUE,
			EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
			environment.data(),
			helper.parent_path().c_str(),
			&startup.StartupInfo,
			&process)) {
		return Handle();
	}
	CloseHandle(process.hThread);
	return Handle(process.hProcess);
}

class ChildProcess final {
public:
	explicit ChildProcess(Handle process) : _process(std::move(process)) {
	}
	~ChildProcess() {
		if (!_released) {
			stop();
		}
	}

	void stop() {
		if (_process && WaitForSingleObject(_process.get(), 0) == WAIT_TIMEOUT) {
			if (TerminateProcess(_process.get(), ERROR_OPERATION_ABORTED)) {
				WaitForSingleObject(_process.get(), 5000);
			}
		}
	}
	[[nodiscard]] HANDLE handle() const {
		return _process.get();
	}
	[[nodiscard]] bool detach(std::shared_ptr<StagedHelper> stage) {
		auto duplicate = HANDLE();
		if (!DuplicateHandle(
				GetCurrentProcess(), handle(), GetCurrentProcess(), &duplicate,
				SYNCHRONIZE, FALSE, 0)) {
			return false;
		}
		try {
			auto reaper = std::thread([wait = Handle(duplicate), stage = std::move(stage)]() mutable {
				WaitForSingleObject(wait.get(), INFINITE);
				stage.reset();
			});
			reaper.detach();
			_released = true;
			return true;
		} catch (const std::system_error &) {
			return false;
		}
	}

private:
	Handle _process;
	bool _released = false;

};

Result LaunchNative(
		const VerifiedInstallationRemovalHelper &helper,
		const VerifiedInstallationReceipt &receipt,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> secret,
		std::chrono::milliseconds timeout) {
	auto stage = StageHelper(helper, receipt.packageRoot);
	if (!stage) {
		return Result::HelperUnavailable;
	}
	auto request = MakePipe();
	auto reply = MakePipe();
	const auto completed = Handle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
	if (!request.input || !request.output || !reply.input || !reply.output || !completed) {
		return Result::TransportFailed;
	}
	auto spawned = SpawnHelper(stage->executable(), receipt.installationId, timeout, request, reply);
	if (!spawned) {
		return Result::HelperUnavailable;
	}
	auto child = ChildProcess(std::move(spawned));
	request.input.close();
	reply.output.close();
	const auto deadline = Clock::now() + timeout;
	auto cancelled = std::atomic_bool(false);
	auto sent = std::atomic_bool(false);
	auto writer = std::thread([&] {
		const auto write = [&](std::span<const uint8_t> bytes) -> std::optional<size_t> {
			auto written = DWORD(0);
			return !cancelled && WriteFile(
				request.output.get(), bytes.data(), DWORD(bytes.size()), &written, nullptr)
				? std::optional(size_t(written))
				: std::nullopt;
		};
		try {
			sent = WriteInstallationRemovalHandoff(receipt, ticket, secret, write);
		} catch (const std::exception &) {
		}
		request.output.close();
		SetEvent(completed.get());
	});
	const auto written = WaitForSingleObject(completed.get(), DWORD(Remaining(deadline)));
	if (written != WAIT_OBJECT_0) {
		cancelled = true;
		CancelSynchronousIo(writer.native_handle());
		child.stop();
	}
	writer.join();
	if (!sent || written != WAIT_OBJECT_0) {
		return (written == WAIT_TIMEOUT || !Remaining(deadline))
			? Result::AcknowledgmentUnconfirmed
			: Result::TransportFailed;
	}
	while (const auto remaining = Remaining(deadline)) {
		auto available = DWORD(0);
		if (!PeekNamedPipe(reply.input.get(), nullptr, 0, nullptr, &available, nullptr)) {
			break;
		}
		if (available) {
			auto ack = uint8_t(0);
			auto count = DWORD(0);
			if (ReadFile(reply.input.get(), &ack, 1, &count, nullptr)
				&& count == 1 && ack == kInstallationRemovalHandoffAck && child.detach(stage)) {
				return Result::ReadyToExit;
			}
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(std::min(remaining, 10)));
	}
	return Result::AcknowledgmentUnconfirmed;
}
#endif

Result Launch(
		const VerifiedInstallationRemovalHelper &helper,
		const VerifiedInstallationReceipt &receipt,
		const EmergencyActionJournal &cleanup,
		std::chrono::milliseconds timeout) {
	if (!helper.source.is_absolute() || !receipt.installationId.valid()
		|| !cleanup.operationId.valid() || timeout <= std::chrono::milliseconds::zero()
		|| timeout > std::chrono::minutes(5)) {
		return Result::Rejected;
	}
#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
	auto secret = OneTimeSecret();
	if (RAND_bytes(secret.bytes.data(), int(secret.bytes.size())) != 1) {
		return Result::HelperUnavailable;
	}
	const auto ticket = MakeInstallationRemovalTicket(receipt, cleanup, secret.bytes);
	if (!ticket) {
		return Result::Rejected;
	}
	return LaunchNative(helper, receipt, *ticket, secret.bytes, timeout);
#else
	return Result::HelperUnavailable;
#endif
}

} // namespace

std::future<InstallationRemovalLaunchResult> LaunchInstallationRemoval(
		VerifiedInstallationRemovalHelper helper,
		VerifiedInstallationReceipt receipt,
		EmergencyActionJournal completedCleanup,
		std::chrono::milliseconds timeout) {
	auto worker = std::packaged_task<Result()>([
			helper = std::move(helper),
			receipt = std::move(receipt),
			cleanup = std::move(completedCleanup),
			timeout] {
		try {
			return Launch(helper, receipt, cleanup, timeout);
		} catch (const std::exception &) {
			return Result::HelperUnavailable;
		}
	});
	auto future = worker.get_future();
	try {
		std::thread(std::move(worker)).detach();
	} catch (const std::system_error &) {
		auto rejected = std::promise<Result>();
		rejected.set_value(Result::HelperUnavailable);
		return rejected.get_future();
	}
	return future;
}

} // namespace Ayu::EmergencyActions
