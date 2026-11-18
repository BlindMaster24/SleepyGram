#include "ayu/features/emergency_actions/installation_removal.h"
#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <cstdio>
#include <string_view>

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <iterator>
#include <memory>
#include <thread>
#include <type_traits>
#endif

namespace {

using namespace Ayu::EmergencyActions;
using Path = std::filesystem::path;

auto failures = 0;

void Check(const char *name, bool passed) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
	failures += !passed;
}

auto Receipt() {
	auto result = VerifiedInstallationReceipt{
		.installationId = InstallationId("synthetic-install"),
	};
	return result;
}

std::optional<EmergencyActionJournal> CompletedCleanup(bool finished) {
	const auto install = Receipt().installationId;
	const auto account = AccountId("synthetic-account");
	const auto session = SessionId("synthetic-session");
	const auto rule = EmergencyRule{
		.id = RuleId("synthetic-uninstall"),
		.installationId = install,
		.action = EmergencyAction::RemoveInstallation,
		.targetScope = TargetScope::CurrentInstallation,
	};
	const auto live = LiveInstallation{
		.id = install,
		.accounts = {{ .id = account, .currentSessionId = session, .sessionIds = { session } }},
	};
	auto journal = MakeJournal(BuildDryRunPlan(OperationId("closed-and-cleared"), rule, live));
	if (!journal || !FinishRemotePhase(*journal)
		|| BeginEffect(*journal, JournalEffect::LocalDataClear, account) != TransitionResult::Applied
		|| (finished && (ResolveEffect(*journal, JournalEffect::LocalDataClear,
			EffectResult::ConfirmedSuccess, account) != TransitionResult::Applied
			|| BeginEffect(*journal, JournalEffect::InstallationRemoval) != TransitionResult::Applied))) {
		return std::nullopt;
	}
	return journal;
}

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)

using namespace std::chrono_literals;

constexpr auto kKind =
#ifdef __APPLE__
	InstallationPackageKind::MacBundle;
#elif defined(_WIN32)
	InstallationPackageKind::WindowsPortable;
#else
	InstallationPackageKind::LinuxPortable;
#endif

const auto kExecutable = Path(
#ifdef __APPLE__
	"Contents/MacOS/SleepyGram"
#elif defined(_WIN32)
	"SleepyGram.exe"
#else
	"SleepyGram"
#endif
);
const auto kManifest = Path(
#ifdef __APPLE__
	"Contents/Resources/BuildManifest.json"
#else
	"build-manifest.json"
#endif
);
const auto kLicense = kManifest.parent_path() / "LICENSE-SQLCipher.txt";

class FixtureDirectory final {
public:
	FixtureDirectory() {
#ifdef _WIN32
		auto nonce = std::array<unsigned char, 16>();
		if (RAND_bytes(nonce.data(), int(nonce.size())) != 1) {
			return;
		}
		auto name = std::wstring(L"sleepygram-windows-removal-");
		constexpr auto digits = std::wstring_view(L"0123456789abcdef");
		for (const auto byte : nonce) {
			name.append({ digits[byte >> 4], digits[byte & 15] });
		}
		auto created = std::filesystem::canonical(std::filesystem::temp_directory_path()) / name;
		if (std::filesystem::create_directory(created)) {
			path = std::move(created);
		}
#else
		auto pattern = (std::filesystem::canonical(
			std::filesystem::temp_directory_path())
			/ "sleepygram-package-fixture.XXXXXX").native();
		if (mkdtemp(pattern.data())) {
			path = Path(pattern);
		}
#endif
	}

	~FixtureDirectory() {
		if (!path.empty()) {
			auto error = std::error_code();
			std::filesystem::remove_all(path, error);
		}
	}

	Path path;

};

bool Write(const Path &path, std::string_view value) {
	auto file = std::ofstream(path, std::ios::binary | std::ios::trunc);
	file.write(value.data(), value.size());
	return bool(file);
}

std::optional<InstallationArtifactDigest> Digest(const Path &path) {
	auto file = std::ifstream(path, std::ios::binary);
	auto contents = std::vector<char>(
		std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	auto result = InstallationArtifactDigest{};
	auto size = 0U;
	return file && EVP_Digest(contents.data(), contents.size(), result.data(), &size,
		EVP_sha256(), nullptr) == 1 && size == result.size()
		? std::optional(result)
		: std::nullopt;
}

std::optional<VerifiedInstallationReceipt> ReadFixtureReceipt(const Path &root) {
	auto result = Receipt();
	result.kind = kKind;
	result.packageRoot = root;
	auto files = std::vector<Path>{ kExecutable, kManifest, kLicense };
#ifdef __APPLE__
	files.emplace_back("Contents/Info.plist");
	files.emplace_back("Contents/Resources/SleepyGram.icns");
	files.emplace_back("Contents/Resources/Telegram.rcc");
#elif defined(_WIN32)
	files.emplace_back("modules/x64/d3d/d3dcompiler_47.dll");
#endif
	for (const auto &file : files) {
		const auto digest = Digest(root / file);
		if (!digest) {
			return std::nullopt;
		}
		result.artifacts.push_back({ file, *digest });
	}
	return result;
}

#ifndef _WIN32
int Wait(pid_t child) {
	auto status = 0;
	return waitpid(child, &status, 0) == child && WIFEXITED(status)
		? WEXITSTATUS(status) : 100;
}
#endif

bool ReadHandoffReport(
		const Path &report,
		InstallationRemovalResult expected) {
	const auto deadline = std::chrono::steady_clock::now() + 3s;
	while (std::chrono::steady_clock::now() < deadline) {
		auto file = std::ifstream(report);
		auto first = -1;
		auto replay = -1;
		if (file >> first >> replay) {
			return first == int(expected)
				&& replay == int(InstallationRemovalResult::TicketRejected);
		}
		std::this_thread::sleep_for(10ms);
	}
	return false;
}

#ifndef _WIN32
int ActAsInstallation(const Path &root, const Path &report, std::string_view scenario) {
	auto receipt = ReadFixtureReceipt(root);
	if (!receipt) {
		return 2;
	}
	if (scenario == "symlink") {
		const auto moved = root.parent_path() / "retained-manifest";
		std::filesystem::rename(root / kManifest, moved);
		std::filesystem::create_symlink(moved, root / kManifest);
		return (InspectInstallationRemoval(*receipt)
			== InstallationRemovalCapability::Unavailable
			&& std::filesystem::is_regular_file(moved)) ? 0 : 3;
	}
	if (scenario == "hardlink") {
		std::filesystem::create_hard_link(root / kManifest, root.parent_path() / "hard-link");
		return (InspectInstallationRemoval(*receipt)
			== InstallationRemovalCapability::Unavailable) ? 0 : 3;
	}
	if (scenario == "foreign-artifact") {
		receipt->artifacts.push_back({ "../neighbor", {} });
		return (InspectInstallationRemoval(*receipt)
			== InstallationRemovalCapability::Unavailable) ? 0 : 3;
	}
	auto secret = InstallationArtifactDigest{};
	if (RAND_bytes(secret.data(), int(secret.size())) != 1) {
		return 4;
	}
	const auto cleanup = CompletedCleanup(scenario != "incomplete-cleanup");
	if (!cleanup) {
		return 4;
	}
	auto ticket = MakeInstallationRemovalTicket(*receipt, *cleanup, secret);
	if (scenario == "incomplete-cleanup") {
		return ticket ? 4 : 0;
	}
	if (!ticket || InspectInstallationRemoval(*receipt) != InstallationRemovalCapability::Automatic) {
		return 5;
	}
	if (scenario == "bad-ticket") {
		ticket->authentication.back() ^= 1;
	}
	if (scenario == "wrong-parent") {
		++ticket->parentProcessId;
	}
	auto pipeEnds = std::array<int, 2>{};
	if (pipe(pipeEnds.data()) != 0) {
		return 6;
	}
	const auto helper = fork();
	if (helper <= 0) {
		if (helper < 0) {
			return 7;
		}
		close(pipeEnds[0]);
		auto receiver = InstallationRemovalReceiver();
		const auto acknowledge = [&] {
			const auto ready = 'R';
			return write(pipeEnds[1], &ready, 1) == 1;
		};
		const auto timeout = (scenario == "still-running") ? 50ms : 2s;
		const auto result = receiver.RemoveAfterParentExit(
			receipt->installationId, *receipt, *ticket, secret, timeout, acknowledge);
		const auto replay = receiver.RemoveAfterParentExit(
			receipt->installationId, *receipt, *ticket, secret, timeout, acknowledge);
		close(pipeEnds[1]);
		const auto saved = Write(report, std::to_string(int(result))
			+ " " + std::to_string(int(replay)) + "\n");
		_exit(saved ? 0 : 8);
	}
	close(pipeEnds[1]);
	auto ready = char(0);
	const auto received = read(pipeEnds[0], &ready, 1);
	close(pipeEnds[0]);
	if (scenario == "bad-ticket" || scenario == "wrong-parent") {
		return received == 0 ? Wait(helper) : 9;
	}
	if (received != 1 || ready != 'R' || !std::filesystem::exists(root / kExecutable)) {
		return 10;
	}
	if (scenario == "still-running") {
		return Wait(helper);
	}
	if (scenario == "changed-after-admission") {
		const auto installed = root / kManifest;
		std::filesystem::remove(installed);
		std::filesystem::create_symlink(root.parent_path() / "neighbor", installed);
	}
	return 0;
}

bool RunFixture(const Path &runner, std::string_view scenario) {
	const auto directory = FixtureDirectory();
	if (directory.path.empty()) {
		return false;
	}
	const auto bundle = directory.path / (kKind == InstallationPackageKind::MacBundle
		? "SleepyGram.app" : "portable");
	const auto binary = bundle / kExecutable;
	const auto report = directory.path / "report";
	const auto neighbor = directory.path / "neighbor";
	std::filesystem::create_directories(binary.parent_path());
	std::filesystem::create_directories((bundle / kManifest).parent_path());
	std::filesystem::copy_file(runner, binary);
	auto preserved = bundle / "downloads";
	if (kKind == InstallationPackageKind::MacBundle && scenario != "partial") {
		preserved = directory.path / "downloads";
	}
	if (!Write(bundle / kManifest, "temporary manifest")
		|| !Write(bundle / kLicense, "temporary test license")
		|| !Write(neighbor, "not part of this package")
		|| !Write(preserved, "export saved outside the package inventory")) {
		return false;
	}
#ifdef __APPLE__
	if (!Write(bundle / "Contents/Info.plist", "temporary bundle metadata")
		|| !Write(bundle / "Contents/Resources/SleepyGram.icns", "temporary icon")
		|| !Write(bundle / "Contents/Resources/Telegram.rcc", "temporary resources")) {
		return false;
	}
#endif
	const auto mode = std::string(scenario);
	const auto child = fork();
	if (child == 0) {
		execl(binary.c_str(), binary.c_str(), bundle.c_str(), report.c_str(), mode.c_str(),
			static_cast<const char*>(nullptr));
		_exit(11);
	}
	if (child < 0 || Wait(child) != 0 || !std::filesystem::is_regular_file(neighbor)) {
		return false;
	}
	if (scenario == "complete") {
		return ReadHandoffReport(report, InstallationRemovalResult::Removed)
			&& !std::filesystem::exists(binary) && std::filesystem::exists(preserved)
			&& !std::filesystem::exists(bundle / kLicense)
			&& (kKind != InstallationPackageKind::MacBundle || !std::filesystem::exists(bundle));
	}
	if (scenario == "partial") {
		return ReadHandoffReport(report, InstallationRemovalResult::Partial)
			&& !std::filesystem::exists(binary) && std::filesystem::exists(preserved);
	}
	if (scenario == "still-running") {
		return ReadHandoffReport(report, InstallationRemovalResult::ParentStillRunning)
			&& std::filesystem::is_regular_file(binary);
	}
	if (scenario == "changed-after-admission") {
		return ReadHandoffReport(report, InstallationRemovalResult::InstallationChanged)
			&& std::filesystem::is_regular_file(binary)
			&& std::filesystem::is_symlink(bundle / kManifest);
	}
	if (scenario == "bad-ticket") {
		return ReadHandoffReport(report, InstallationRemovalResult::TicketRejected)
			&& std::filesystem::is_regular_file(binary);
	}
	if (scenario == "wrong-parent") {
		return ReadHandoffReport(report, InstallationRemovalResult::ParentUnavailable)
			&& std::filesystem::is_regular_file(binary);
	}
	return std::filesystem::is_regular_file(binary) && std::filesystem::exists(preserved);
}

#else

class FixtureHandle final {
public:
	explicit FixtureHandle(HANDLE value = nullptr) : _value(value) {
	}
	FixtureHandle(FixtureHandle &&other) noexcept
	: _value(std::exchange(other._value, nullptr)) {
	}
	~FixtureHandle() {
		reset();
	}

	void reset() {
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

struct FixturePipe final {
	FixtureHandle read;
	FixtureHandle write;
};

FixturePipe Pipe() {
	auto read = HANDLE();
	auto write = HANDLE();
	if (!CreatePipe(&read, &write, nullptr, 0)) {
		return { FixtureHandle(), FixtureHandle() };
	}
	return { FixtureHandle(read), FixtureHandle(write) };
}

FixtureHandle Launch(
		const Path &executable,
		std::span<const std::wstring> args,
		std::span<HANDLE> inherited = {}) {
	auto command = L"\"" + executable.native() + L"\"";
	for (const auto &arg : args) {
		command += L" \"" + arg + L"\"";
	}
	auto startup = STARTUPINFOEXW();
	auto storage = std::vector<uint8_t>();
	const auto flags = inherited.empty() ? DWORD(0) : DWORD(EXTENDED_STARTUPINFO_PRESENT);
	startup.StartupInfo.cb = inherited.empty() ? sizeof(STARTUPINFOW) : sizeof(startup);
	if (!inherited.empty()) {
		auto size = SIZE_T(0);
		InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
		if (!size) {
			return FixtureHandle();
		}
		storage.resize(size);
		startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
		if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size)) {
			return FixtureHandle();
		}
	}
	const auto attribute = std::unique_ptr<
		std::remove_pointer_t<LPPROC_THREAD_ATTRIBUTE_LIST>,
		decltype(&DeleteProcThreadAttributeList)>(
			startup.lpAttributeList, DeleteProcThreadAttributeList);
	if (attribute && !UpdateProcThreadAttribute(
			attribute.get(), 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(),
			inherited.size_bytes(), nullptr, nullptr)) {
		return FixtureHandle();
	}
	auto process = PROCESS_INFORMATION();
	if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, bool(attribute),
			flags, nullptr, nullptr, &startup.StartupInfo, &process)) {
		return FixtureHandle();
	}
	CloseHandle(process.hThread);
	return FixtureHandle(process.hProcess);
}

int Wait(const FixtureHandle &process) {
	auto code = DWORD(0);
	return process && WaitForSingleObject(process.get(), 10000) == WAIT_OBJECT_0
		&& GetExitCodeProcess(process.get(), &code) ? int(code) : 100;
}

bool Elevated() {
	auto token = HANDLE();
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return true;
	}
	const auto bounded = FixtureHandle(token);
	auto elevation = TOKEN_ELEVATION();
	auto size = DWORD(0);
	return !GetTokenInformation(bounded.get(), TokenElevation, &elevation, sizeof(elevation), &size)
		|| elevation.TokenIsElevated;
}

bool FixturePath(const Path &root) {
	return root.filename() == L"portable"
		&& root.parent_path().filename().native().starts_with(L"sleepygram-windows-removal-")
		&& std::filesystem::is_regular_file(root.parent_path() / L"fixture-marker");
}

bool CreateFixtureJunction(const Path &path, const Path &target) {
	const auto display = target.native();
	const auto substitute = L"\\??\\" + display;
	const auto substituteBytes = sizeof(wchar_t) * substitute.size();
	const auto displayBytes = sizeof(wchar_t) * display.size();
	const auto payloadSize = 8 + substituteBytes + displayBytes + 2 * sizeof(wchar_t);
	if (payloadSize >= MAXIMUM_REPARSE_DATA_BUFFER_SIZE - 8
		|| !std::filesystem::create_directory(path)) {
		return false;
	}
	auto buffer = std::vector<uint8_t>();
	const auto append16 = [&](uint16_t value) {
		buffer.push_back(uint8_t(value));
		buffer.push_back(uint8_t(value >> 8));
	};
	append16(uint16_t(IO_REPARSE_TAG_MOUNT_POINT));
	append16(uint16_t(IO_REPARSE_TAG_MOUNT_POINT >> 16));
	append16(uint16_t(payloadSize));
	append16(0);
	append16(0);
	append16(uint16_t(substituteBytes));
	append16(uint16_t(substituteBytes + sizeof(wchar_t)));
	append16(uint16_t(displayBytes));
	for (const auto &name : { substitute, display }) {
		for (const auto character : name) {
			append16(uint16_t(character));
		}
		append16(0);
	}
	const auto directory = FixtureHandle(CreateFileW(
		path.c_str(),
		GENERIC_WRITE,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
		nullptr));
	auto written = DWORD(0);
	return directory && DeviceIoControl(
		directory.get(),
		FSCTL_SET_REPARSE_POINT,
		buffer.data(),
		DWORD(buffer.size()),
		nullptr,
		0,
		&written,
		nullptr);
}

struct WireTicket final {
	uint64_t pid = 0;
	uint64_t birth = 0;
	InstallationArtifactDigest proof{};
	InstallationArtifactDigest secret{};
};

uintptr_t ReadHandle(const wchar_t *value) {
	auto end = static_cast<wchar_t*>(nullptr);
	const auto result = std::wcstoull(value, &end, 10);
	return end && !*end ? uintptr_t(result) : 0;
}

int ActAsWindowsHelper(
		const Path &root,
		const Path &report,
		std::wstring_view scenario,
		uintptr_t inheritedParent,
		uintptr_t inputHandle,
		uintptr_t ackHandle) {
	if (!FixturePath(root) || report != root.parent_path() / L"report") {
		return 20;
	}
	const auto input = FixtureHandle(reinterpret_cast<HANDLE>(inputHandle));
	const auto ack = FixtureHandle(reinterpret_cast<HANDLE>(ackHandle));
	auto wire = WireTicket();
	auto size = DWORD(0);
	if (!input || !ack || !ReadFile(input.get(), &wire, sizeof(wire), &size, nullptr)
		|| size != sizeof(wire)) {
		return 21;
	}
	const auto receipt = ReadFixtureReceipt(root);
	if (!receipt) {
		return 22;
	}
	const auto ticket = InstallationRemovalTicket{
		.operationId = OperationId("closed-and-cleared"),
		.parentProcessId = wire.pid,
		.authentication = wire.proof,
		.parentCreationTime = wire.birth,
	};
	const auto acknowledge = [&] {
		const auto ready = 'R';
		auto size = DWORD(0);
		return WriteFile(ack.get(), &ready, 1, &size, nullptr) && size == 1;
	};
	const auto timeout = (scenario == L"still-running") ? 100ms : 5s;
	auto receiver = InstallationRemovalReceiver();
	const auto execute = [&] {
		return receiver.RemoveAfterParentExit(
			receipt->installationId, *receipt, ticket, wire.secret, timeout,
			acknowledge, { inheritedParent });
	};
	const auto first = execute();
	const auto replay = execute();
	return Write(report, std::to_string(int(first)) + " " + std::to_string(int(replay)) + "\n")
		? 0 : 23;
}

int ActAsWindowsInstallation(
		const Path &root,
		const Path &report,
		std::wstring_view scenario,
		const Path &runner) {
	if (!FixturePath(root) || report != root.parent_path() / L"report") {
		return 24;
	}
	const auto receipt = ReadFixtureReceipt(root);
	if (!receipt) {
		return 25;
	}
	if (scenario == L"elevated") {
		return InspectInstallationRemoval(*receipt) == InstallationRemovalCapability::Unavailable
			? 0 : 26;
	}
	if (scenario == L"hardlink") {
		if (!CreateHardLinkW((root / L"shared-manifest").c_str(), (root / kManifest).c_str(), nullptr)) {
			return 27;
		}
		return InspectInstallationRemoval(*receipt) == InstallationRemovalCapability::Unavailable
			? 0 : 28;
	}
	if (scenario == L"junction") {
		const auto path = root / L"modules/x64/d3d";
		const auto retained = root.parent_path() / L"saved-shader";
		std::filesystem::rename(path, retained);
		const auto junction = CreateFixtureJunction(path, retained);
		const auto rejected = junction
			&& InspectInstallationRemoval(*receipt) == InstallationRemovalCapability::Unavailable;
		if (std::filesystem::exists(path) && !RemoveDirectoryW(path.c_str())) {
			return 38;
		}
		std::filesystem::rename(retained, path);
		return rejected ? 0 : 39;
	}
	if (scenario == L"foreign-artifact") {
		auto foreign = *receipt;
		foreign.artifacts.push_back({ L"downloads", {} });
		return InspectInstallationRemoval(foreign) == InstallationRemovalCapability::Unavailable
			? 0 : 29;
	}
	auto wire = WireTicket();
	const auto cleanup = CompletedCleanup(scenario != L"incomplete-cleanup");
	if (!cleanup || RAND_bytes(wire.secret.data(), int(wire.secret.size())) != 1) {
		return 30;
	}
	const auto ticket = MakeInstallationRemovalTicket(*receipt, *cleanup, wire.secret);
	if (scenario == L"incomplete-cleanup") {
		return ticket ? 31 : 0;
	}
	if (!ticket || InspectInstallationRemoval(*receipt) != InstallationRemovalCapability::Automatic) {
		return 32;
	}
	wire.pid = ticket->parentProcessId;
	wire.birth = ticket->parentCreationTime;
	wire.proof = ticket->authentication;
	if (scenario == L"bad-ticket") {
		wire.proof.back() ^= 1;
	}
	if (scenario == L"wrong-parent") {
		wire.birth ^= 1;
	}

	auto payload = Pipe();
	auto acknowledgment = Pipe();
	auto process = HANDLE();
	if (!payload.read || !payload.write || !acknowledgment.read || !acknowledgment.write
		|| !SetHandleInformation(payload.read.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
		|| !SetHandleInformation(acknowledgment.write.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
		|| !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &process,
			SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0)) {
		return 33;
	}
	auto parent = FixtureHandle(process);
	auto inherit = std::array{ parent.get(), payload.read.get(), acknowledgment.write.get() };
	const auto helper = Launch(runner, std::array{
		std::wstring(L"--fixture-helper"),
		root.native(),
		report.native(),
		std::wstring(scenario),
		std::to_wstring(scenario == L"missing-parent" ? 0 : reinterpret_cast<uintptr_t>(parent.get())),
		std::to_wstring(reinterpret_cast<uintptr_t>(payload.read.get())),
		std::to_wstring(reinterpret_cast<uintptr_t>(acknowledgment.write.get())),
	}, inherit);
	parent.reset();
	payload.read.reset();
	acknowledgment.write.reset();
	auto size = DWORD(0);
	if (!helper || !WriteFile(payload.write.get(), &wire, sizeof(wire), &size, nullptr)
		|| size != sizeof(wire)) {
		return 34;
	}
	payload.write.reset();
	auto ready = char(0);
	const auto received = ReadFile(acknowledgment.read.get(), &ready, 1, &size, nullptr)
		&& size == 1 && ready == 'R';
	if (scenario == L"bad-ticket" || scenario == L"wrong-parent" || scenario == L"missing-parent") {
		return received ? 35 : Wait(helper);
	}
	if (!received || !std::filesystem::exists(root / kExecutable)) {
		return 36;
	}
	if (scenario == L"still-running") {
		return Wait(helper);
	}
	if (scenario == L"changed-after-admission" && !Write(root / kManifest, "replacement")) {
		return 37;
	}
	return 0;
}

bool RunWindowsFixture(const Path &runner, std::wstring_view scenario) {
	const auto directory = FixtureDirectory();
	if (directory.path.empty()) {
		return false;
	}
	const auto root = directory.path / L"portable";
	const auto executable = root / kExecutable;
	const auto report = directory.path / L"report";
	const auto sibling = directory.path / L"unrelated";
	const auto shader = root / L"modules/x64/d3d/d3dcompiler_47.dll";
	std::filesystem::create_directories(shader.parent_path());
	std::filesystem::copy_file(runner, executable);
	if (!Write(directory.path / L"fixture-marker", "synthetic temporary fixture")
		|| !Write(root / kManifest, "temporary manifest")
		|| !Write(root / kLicense, "temporary license")
		|| !Write(shader, "temporary approved runtime library")
		|| !Write(shader.parent_path() / L"neighbor.txt", "unapproved neighbor")
		|| !Write(root / L"downloads", "user export")
		|| !Write(sibling, "unrelated file")) {
		return false;
	}
	const auto parent = Launch(executable, std::array{
		std::wstring(L"--fixture-parent"), root.native(), report.native(),
		std::wstring(scenario), runner.native(),
	});
	if (Wait(parent) != 0 || !std::filesystem::exists(sibling)
		|| !std::filesystem::exists(root / L"downloads")
		|| !std::filesystem::exists(shader.parent_path() / L"neighbor.txt")) {
		return false;
	}
	if (scenario == L"complete") {
		return ReadHandoffReport(report, InstallationRemovalResult::Removed)
			&& !std::filesystem::exists(executable) && !std::filesystem::exists(shader)
			&& !std::filesystem::exists(root / kManifest) && !std::filesystem::exists(root / kLicense);
	}
	if (!std::filesystem::exists(executable) || !std::filesystem::exists(shader)) {
		return false;
	}
	if (scenario == L"bad-ticket") {
		return ReadHandoffReport(report, InstallationRemovalResult::TicketRejected);
	}
	if (scenario == L"wrong-parent" || scenario == L"missing-parent") {
		return ReadHandoffReport(report, InstallationRemovalResult::ParentUnavailable);
	}
	if (scenario == L"still-running") {
		return ReadHandoffReport(report, InstallationRemovalResult::ParentStillRunning);
	}
	if (scenario == L"changed-after-admission") {
		return ReadHandoffReport(report, InstallationRemovalResult::InstallationChanged);
	}
	return true;
}

#endif
#endif

} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
	if (argc == 6 && std::wstring_view(argv[1]) == L"--fixture-parent") {
		return ActAsWindowsInstallation(Path(argv[2]), Path(argv[3]), argv[4], Path(argv[5]));
	}
	if (argc == 8 && std::wstring_view(argv[1]) == L"--fixture-helper") {
		return ActAsWindowsHelper(Path(argv[2]), Path(argv[3]), argv[4],
			ReadHandle(argv[5]), ReadHandle(argv[6]), ReadHandle(argv[7]));
	}
#else
int main(int argc, char **argv) {
#if defined(__APPLE__) || defined(__linux__)
	if (argc == 4) {
		return ActAsInstallation(Path(argv[1]), Path(argv[2]), argv[3]);
	}
#endif
#endif
	auto receipt = Receipt();
	Check("unknown-installation-is-unavailable", InspectInstallationRemoval(receipt)
		== InstallationRemovalCapability::Unavailable);
	receipt.kind = InstallationPackageKind::RegisteredPackage;
	Check("verified-package-defers-to-native-confirmation", InspectInstallationRemoval(receipt)
		== InstallationRemovalCapability::OsConfirmationRequired);
#if defined(__APPLE__) || defined(__linux__)
	if (!geteuid()) {
		const auto journal = CompletedCleanup(true);
		Check("elevated-process-cannot-issue-automatic-removal",
			journal && !MakeInstallationRemovalTicket(receipt, *journal, {}));
		return failures ? 1 : 0;
	}
	const auto runner = std::filesystem::canonical(Path(argv[0]));
	Check("exact-package-is-removed-only-after-parent-exits", RunFixture(runner, "complete"));
	Check("foreign-file-inside-bundle-is-retained-and-removal-reports-partial",
		kKind != InstallationPackageKind::MacBundle || RunFixture(runner, "partial"));
	Check("correctly-authenticated-helper-still-waits-for-exact-parent", RunFixture(runner, "still-running"));
	Check("forged-ticket-never-acknowledges-or-deletes", RunFixture(runner, "bad-ticket"));
	Check("wrong-parent-id-never-acknowledges-or-deletes", RunFixture(runner, "wrong-parent"));
	Check("pending-local-cleanup-cannot-issue-handoff", RunFixture(runner, "incomplete-cleanup"));
	Check("replacement-symlink-after-parent-acknowledgment-fails-closed",
		RunFixture(runner, "changed-after-admission"));
	Check("preexisting-symlinks-are-rejected", RunFixture(runner, "symlink"));
	Check("hardlinked-artifacts-are-rejected", RunFixture(runner, "hardlink"));
	Check("paths-outside-trusted-package-are-rejected", RunFixture(runner, "foreign-artifact"));
#elif defined(_WIN32)
	const auto runner = std::filesystem::canonical(Path(argv[0]));
	if (Elevated()) {
		Check("elevated-portable-fixture-is-ineligible", RunWindowsFixture(runner, L"elevated"));
		return failures ? 1 : 0;
	}
	Check("windows-removes-only-the-exact-verified-portable-files", RunWindowsFixture(runner, L"complete"));
	Check("windows-waits-the-real-parent-handle-before-removal", RunWindowsFixture(runner, L"still-running"));
	Check("windows-rejects-a-forged-ticket", RunWindowsFixture(runner, L"bad-ticket"));
	Check("windows-rejects-the-wrong-parent-creation-time", RunWindowsFixture(runner, L"wrong-parent"));
	Check("windows-requires-the-inherited-parent-handle", RunWindowsFixture(runner, L"missing-parent"));
	Check("windows-refuses-before-local-cleanup-completes", RunWindowsFixture(runner, L"incomplete-cleanup"));
	Check("windows-revalidates-artifacts-after-parent-exit", RunWindowsFixture(runner, L"changed-after-admission"));
	Check("windows-rejects-hardlinks", RunWindowsFixture(runner, L"hardlink"));
	Check("windows-rejects-junctions-in-artifact-ancestors", RunWindowsFixture(runner, L"junction"));
	Check("windows-rejects-user-files-in-the-package-receipt", RunWindowsFixture(runner, L"foreign-artifact"));
#endif
	return failures ? 1 : 0;
}
