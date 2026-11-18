// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/installation_removal_handoff.h"

#include "ayu/features/emergency_actions/installation_data_cleanup.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <ranges>
#include <set>
#include <string_view>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <thread>
#elif defined(__APPLE__) || defined(__linux__)
#include <cerrno>
#include <csignal>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu::EmergencyActions {
namespace {

using Kind = InstallationPackageKind;
using Path = std::filesystem::path;
constexpr auto kMagic = std::array<uint8_t, 8>{ 'S', 'G', 'U', 'H', 0, 0, 0, 1 };
constexpr auto kLengthBytes = size_t(4);
constexpr auto kHeaderBytes = kMagic.size() + kLengthBytes;
constexpr auto kMaxIdBytes = size_t(128);
constexpr auto kMaxRelativeDepth = size_t(16);
constexpr auto kMaxPosixPathBytes = size_t(4096);
constexpr auto kMaxWindowsRootUnits = size_t(32760);
constexpr auto kMaxWindowsRootBytes = kMaxWindowsRootUnits * 4;
constexpr auto kMaxArtifacts = size_t(2048);

struct SecretBuffer final {
	SecretBuffer() = default;
	SecretBuffer(const SecretBuffer&) = delete;
	SecretBuffer &operator=(const SecretBuffer&) = delete;
	~SecretBuffer() {
		if (!data.empty()) {
			OPENSSL_cleanse(data.data(), data.size());
		}
	}

	std::vector<uint8_t> data;
};

struct WireArtifact final {
	std::u8string path;
	const InstallationArtifactDigest *digest = nullptr;
};

bool ValidId(std::string_view id) {
	return !id.empty() && id.size() <= kMaxIdBytes
		&& std::ranges::all_of(id, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9')
				|| ch == '-' || ch == '_' || ch == '.' || ch == ':';
		});
}

bool Nonzero(std::span<const uint8_t> bytes) {
	return std::ranges::any_of(bytes, [](uint8_t byte) { return byte != 0; });
}

bool ValidTicket(
		const InstallationRemovalTicket &ticket,
		Kind kind,
		std::span<const uint8_t> secret) {
	return ValidId(ticket.operationId.value)
		&& ticket.parentProcessId > 1
		&& ticket.parentProcessId <= ((kind == Kind::WindowsPortable)
			? uint64_t(0xFFFFFFFF) : uint64_t(0x7FFFFFFF))
		&& ((kind == Kind::WindowsPortable) == bool(ticket.parentCreationTime))
		&& Nonzero(ticket.authentication)
		&& secret.size() == kInstallationRemovalKeyBytes && Nonzero(secret);
}

size_t ArtifactLimit(Kind kind) {
	switch (kind) {
	case Kind::LinuxPortable: return 5;
	case Kind::WindowsPortable: return 6;
	case Kind::MacBundle: return kMaxArtifacts;
	default: return 0;
	}
}

bool ValidUtf8(std::u8string_view text) {
	for (auto i = size_t(0); i < text.size();) {
		const auto first = uint8_t(text[i++]);
		if (first < 0x80) {
			if (first < 0x20 || first == 0x7f) {
				return false;
			}
			continue;
		}
		if (first < 0xc2 || first > 0xf4) {
			return false;
		}
		const auto count = (first < 0xe0) ? 1 : (first < 0xf0) ? 2 : 3;
		if (size_t(count) > text.size() - i) {
			return false;
		}
		const auto second = uint8_t(text[i]);
		if ((first == 0xe0 && second < 0xa0)
			|| (first == 0xed && second >= 0xa0)
			|| (first == 0xf0 && second < 0x90)
			|| (first == 0xf4 && second >= 0x90)) {
			return false;
		}
		for (auto j = 0; j < count; ++j) {
			if ((uint8_t(text[i++]) & 0xc0) != 0x80) {
				return false;
			}
		}
	}
	return true;
}

size_t Utf16Units(std::u8string_view text) {
	auto result = size_t(0);
	for (const auto byte : text) {
		result += (uint8_t(byte) & 0xc0) != 0x80;
		result += uint8_t(byte) >= 0xf0;
	}
	return result;
}

bool WindowsComponent(std::u8string_view component) {
	if (component.back() == u8'.' || component.back() == u8' '
		|| Utf16Units(component) > 255
		|| component.find_first_of(u8"<>:\"|?*/") != std::u8string_view::npos) {
		return false;
	}
	auto base = std::u8string(component.substr(0, component.find(u8'.')));
	for (auto &ch : base) {
		if (ch >= u8'a' && ch <= u8'z') {
			ch = char8_t(ch - u8'a' + u8'A');
		}
	}
	const auto indexed = base.starts_with(u8"COM") || base.starts_with(u8"LPT");
	return base != u8"CON" && base != u8"PRN"
		&& base != u8"AUX" && base != u8"NUL"
		&& base != u8"CONIN$" && base != u8"CONOUT$"
		&& (!indexed || (base.size() != 4 || base.back() < u8'1' || base.back() > u8'9'))
		&& (!indexed || (base.substr(3) != u8"¹" && base.substr(3) != u8"²"
			&& base.substr(3) != u8"³"));
}

bool SafeComponents(std::u8string_view path, char8_t separator, bool windows) {
	if (path.empty() || path.back() == separator) {
		return false;
	}
	auto depth = size_t(0);
	while (!path.empty()) {
		const auto end = path.find(separator);
		const auto component = path.substr(0, end);
		if (component.empty() || component == u8"." || component == u8".."
			|| (windows && !WindowsComponent(component))
			|| ++depth > kMaxRelativeDepth) {
			return false;
		}
		if (end == std::u8string_view::npos) {
			break;
		}
		path.remove_prefix(end + 1);
	}
	return true;
}

bool ValidRoot(Kind kind, std::u8string_view root) {
	if (!ValidUtf8(root)) {
		return false;
	}
	if (kind == Kind::WindowsPortable) {
		return root.size() > 3 && root.size() <= kMaxWindowsRootBytes
			&& Utf16Units(root) <= kMaxWindowsRootUnits
			&& ((root[0] >= u8'A' && root[0] <= u8'Z')
				|| (root[0] >= u8'a' && root[0] <= u8'z'))
			&& root[1] == u8':' && root[2] == u8'\\'
			&& SafeComponents(root.substr(3), u8'\\', true);
	}
	return (kind == Kind::LinuxPortable || kind == Kind::MacBundle)
		&& root.size() <= kMaxPosixPathBytes
		&& root.starts_with(u8"/") && root.find(u8'\\') == std::u8string_view::npos
		&& SafeComponents(root.substr(1), u8'/', false)
		&& (kind != Kind::MacBundle || root.ends_with(u8"/SleepyGram.app"));
}

bool ValidArtifact(Kind kind, std::u8string_view path) {
	if (path.size() > kMaxPosixPathBytes || !ValidUtf8(path)
		|| path.find(u8'\\') != std::u8string_view::npos
		|| !SafeComponents(path, u8'/', false)) {
		return false;
	}
	switch (kind) {
	case Kind::LinuxPortable:
		return path == u8"SleepyGram" || path == u8"Updater"
			|| path == u8"SleepyGramRemovalHelper"
			|| path == u8"build-manifest.json" || path == u8"LICENSE-SQLCipher.txt";
	case Kind::WindowsPortable:
		return path == u8"SleepyGram.exe" || path == u8"Updater.exe"
			|| path == u8"SleepyGramRemovalHelper.exe"
			|| path == u8"build-manifest.json" || path == u8"LICENSE-SQLCipher.txt"
			|| path == u8"modules/x64/d3d/d3dcompiler_47.dll";
	case Kind::MacBundle:
		return path.starts_with(u8"Contents/");
	default:
		return false;
	}
}

bool RequiredArtifacts(Kind kind, const auto &paths) {
	switch (kind) {
	case Kind::LinuxPortable:
	case Kind::WindowsPortable:
		return paths.contains(kind == Kind::LinuxPortable ? u8"SleepyGram" : u8"SleepyGram.exe")
			&& paths.contains(u8"build-manifest.json") && paths.contains(u8"LICENSE-SQLCipher.txt");
	case Kind::MacBundle:
		return paths.contains(u8"Contents/MacOS/SleepyGram") && paths.contains(u8"Contents/Info.plist")
			&& paths.contains(u8"Contents/Resources/BuildManifest.json")
			&& paths.contains(u8"Contents/Resources/LICENSE-SQLCipher.txt")
			&& paths.contains(u8"Contents/Resources/SleepyGram.icns")
			&& paths.contains(u8"Contents/Resources/Telegram.rcc");
	default:
		return false;
	}
}

std::optional<std::u8string> WirePath(const Path &path) {
	try {
		auto text = path.u8string();
		return (Path(text).native() == path.native())
			? std::optional(std::move(text)) : std::nullopt;
	} catch (const std::filesystem::filesystem_error &) {
		return std::nullopt;
	}
}

std::optional<Path> NativePath(std::u8string_view wire) {
	try {
		auto path = Path(wire);
		return (path.u8string() == wire) ? std::optional(std::move(path)) : std::nullopt;
	} catch (const std::filesystem::filesystem_error &) {
		return std::nullopt;
	}
}

template <typename Character>
std::span<const uint8_t> Bytes(std::basic_string_view<Character> text) {
	return { reinterpret_cast<const uint8_t*>(text.data()), text.size() };
}

class Writer final {
public:
	explicit Writer(std::vector<uint8_t> &buffer) : _buffer(buffer) {
	}

	void bytes(std::span<const uint8_t> value) {
		_buffer.insert(_buffer.end(), value.begin(), value.end());
	}

	void number(uint64_t value, size_t width) {
		for (auto i = size_t(0); i != width; ++i) {
			_buffer.push_back(uint8_t(value >> (i * 8)));
		}
	}

	void string(std::span<const uint8_t> value) {
		number(value.size(), kLengthBytes);
		bytes(value);
	}

private:
	std::vector<uint8_t> &_buffer;

};

class Reader final {
public:
	explicit Reader(std::span<const uint8_t> bytes) : _available(bytes) {
	}

	[[nodiscard]] std::span<const uint8_t> take(size_t size) {
		if (size > _available.size()) {
			return {};
		}
		const auto result = _available.first(size);
		_available = _available.subspan(size);
		return result;
	}

	[[nodiscard]] std::optional<uint64_t> number(size_t width) {
		const auto encoded = take(width);
		if (encoded.empty()) {
			return std::nullopt;
		}
		auto result = uint64_t(0);
		for (auto i = size_t(0); i != width; ++i) {
			result |= uint64_t(encoded[i]) << (8 * i);
		}
		return result;
	}

	template <typename Character>
	[[nodiscard]] std::basic_string<Character> string(size_t maximum) {
		const auto size = number(kLengthBytes);
		if (!size || !*size || *size > maximum) {
			return {};
		}
		const auto value = take(size_t(*size));
		return std::basic_string<Character>(value.begin(), value.end());
	}

	[[nodiscard]] bool done() const {
		return _available.empty();
	}

private:
	std::span<const uint8_t> _available;

};

template <typename Buffer, typename Io>
bool Transfer(Buffer buffer, const Io &call) {
	while (!buffer.empty()) {
		const auto count = call(buffer);
		if (!count || !*count || *count > buffer.size()) {
			return false;
		}
		buffer = buffer.subspan(*count);
	}
	return true;
}

#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
bool IsNativePackage(Kind kind) {
#ifdef _WIN32
	return kind == Kind::WindowsPortable;
#elif defined(__APPLE__)
	return kind == Kind::MacBundle;
#else
	return kind == Kind::LinuxPortable;
#endif
}

int RemainingMilliseconds(std::chrono::steady_clock::time_point deadline) {
	const auto left = std::chrono::ceil<std::chrono::milliseconds>(
		deadline - std::chrono::steady_clock::now());
	return int(std::max(left, std::chrono::milliseconds::zero()).count());
}
#endif

} // namespace

InstallationRemovalHandoff::InstallationRemovalHandoff(
		VerifiedInstallationReceipt receipt,
		InstallationRemovalTicket ticket,
		std::span<const uint8_t, kInstallationRemovalKeyBytes> secret)
: _receipt(std::move(receipt))
, _ticket(std::move(ticket)) {
	std::ranges::copy(secret, _secret.begin());
}

InstallationRemovalHandoff::InstallationRemovalHandoff(InstallationRemovalHandoff &&other) noexcept
: _receipt(std::move(other._receipt))
, _ticket(std::move(other._ticket))
, _secret(other._secret) {
	OPENSSL_cleanse(other._secret.data(), other._secret.size());
}

InstallationRemovalHandoff::~InstallationRemovalHandoff() {
	OPENSSL_cleanse(_secret.data(), _secret.size());
}

const VerifiedInstallationReceipt &InstallationRemovalHandoff::receipt() const {
	return _receipt;
}

const InstallationRemovalTicket &InstallationRemovalHandoff::ticket() const {
	return _ticket;
}

std::span<const uint8_t> InstallationRemovalHandoff::secret() const {
	return _secret;
}

bool WriteInstallationRemovalHandoff(
		const VerifiedInstallationReceipt &receipt,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> secret,
		const InstallationRemovalHandoffWrite &write) {
	const auto kind = receipt.kind;
	const auto root = WirePath(receipt.packageRoot);
	if (!write || !ValidId(receipt.installationId.value)
		|| !ValidTicket(ticket, kind, secret) || !root || !ValidRoot(kind, *root)
		|| receipt.dataCleanup.size() > kMaxInstallationRemovalDataBytes
		|| receipt.artifacts.empty() || receipt.artifacts.size() > ArtifactLimit(kind)) {
		return false;
	}
	auto size = kHeaderBytes + 1 + 3 * kLengthBytes + 2 + 2 * 8
		+ receipt.installationId.value.size() + root->size() + ticket.operationId.value.size()
		+ ticket.authentication.size() + secret.size();
	if (!receipt.dataCleanup.empty()) {
		size += kLengthBytes + receipt.dataCleanup.size();
	}
	auto artifacts = std::vector<WireArtifact>();
	for (const auto &artifact : receipt.artifacts) {
		auto path = WirePath(artifact.relativePath);
		if (!path || !ValidArtifact(kind, *path) || !Nonzero(artifact.digest)) {
			return false;
		}
		size += kLengthBytes + path->size() + artifact.digest.size();
		if (size > kMaxInstallationRemovalHandoffBytes) {
			return false;
		}
		artifacts.push_back({ std::move(*path), &artifact.digest });
	}
	std::ranges::sort(artifacts, {}, &WireArtifact::path);
	auto paths = std::set<std::u8string_view>();
	for (const auto &artifact : artifacts) {
		if (!paths.insert(artifact.path).second) {
			return false;
		}
	}
	if (!RequiredArtifacts(kind, paths)) {
		return false;
	}
	auto buffer = SecretBuffer();
	buffer.data.reserve(size);
	auto writer = Writer(buffer.data);
	writer.bytes(kMagic);
	writer.number(size - kHeaderBytes, kLengthBytes);
	writer.number(uint8_t(kind), 1);
	writer.string(Bytes(std::string_view(receipt.installationId.value)));
	writer.string(Bytes(std::u8string_view(*root)));
	writer.number(artifacts.size(), 2);
	for (const auto &artifact : artifacts) {
		writer.string(Bytes(std::u8string_view(artifact.path)));
		writer.bytes(*artifact.digest);
	}
	writer.string(Bytes(std::string_view(ticket.operationId.value)));
	writer.number(ticket.parentProcessId, 8);
	writer.number(ticket.parentCreationTime, 8);
	writer.bytes(ticket.authentication);
	writer.bytes(secret);
	if (!receipt.dataCleanup.empty()) {
		writer.string(receipt.dataCleanup);
	}
	return buffer.data.size() == size
		&& Transfer(std::span<const uint8_t>(buffer.data), write);
}

std::optional<InstallationRemovalHandoff> ReadInstallationRemovalHandoff(
		const InstallationRemovalHandoffRead &read) {
	auto header = std::array<uint8_t, kHeaderBytes>{};
	if (!read || !Transfer(std::span<uint8_t>(header), read)
		|| !std::ranges::equal(kMagic, std::span(header).first(kMagic.size()))) {
		return std::nullopt;
	}
	auto framing = Reader(std::span(header).last(kLengthBytes));
	const auto size = framing.number(kLengthBytes);
	if (!size || !*size || *size > kMaxInstallationRemovalHandoffBytes - kHeaderBytes) {
		return std::nullopt;
	}
	auto buffer = SecretBuffer();
	buffer.data.resize(size_t(*size));
	if (!Transfer(std::span<uint8_t>(buffer.data), read)) {
		return std::nullopt;
	}
	auto extra = uint8_t(0);
	if (read(std::span(&extra, 1)) != size_t(0)) {
		OPENSSL_cleanse(&extra, sizeof(extra));
		return std::nullopt;
	}
	auto reader = Reader(buffer.data);
	const auto kindValue = reader.number(1);
	const auto installation = reader.string<char>(kMaxIdBytes);
	const auto root = reader.string<char8_t>(kMaxWindowsRootBytes);
	const auto count = reader.number(2);
	const auto kind = kindValue ? Kind(*kindValue) : Kind::Unknown;
	if (!ValidId(installation) || !ValidRoot(kind, root)
		|| !count || !*count || *count > ArtifactLimit(kind)) {
		return std::nullopt;
	}
	auto nativeRoot = NativePath(root);
	if (!nativeRoot) {
		return std::nullopt;
	}
	auto receipt = VerifiedInstallationReceipt{
		.installationId = InstallationId(std::string(installation)),
		.kind = kind,
		.packageRoot = std::move(*nativeRoot),
	};
	auto paths = std::set<std::u8string, std::less<>>();
	auto previous = std::u8string_view();
	receipt.artifacts.reserve(size_t(*count));
	for (auto i = size_t(0); i != *count; ++i) {
		auto path = reader.string<char8_t>(kMaxPosixPathBytes);
		const auto digest = reader.take(InstallationArtifactDigest().size());
		if (!ValidArtifact(kind, path) || std::u8string_view(path) <= previous || !Nonzero(digest)) {
			return std::nullopt;
		}
		auto native = NativePath(path);
		if (!native) {
			return std::nullopt;
		}
		previous = *paths.insert(std::move(path)).first;
		auto &entry = receipt.artifacts.emplace_back();
		entry.relativePath = std::move(*native);
		std::ranges::copy(digest, entry.digest.begin());
	}
	const auto operation = reader.string<char>(kMaxIdBytes);
	const auto pid = reader.number(8);
	const auto creation = reader.number(8);
	const auto proof = reader.take(InstallationArtifactDigest().size());
	const auto secret = reader.take(kInstallationRemovalKeyBytes);
	if (!reader.done()) {
		const auto size = reader.number(kLengthBytes);
		if (!size || !*size || *size > kMaxInstallationRemovalDataBytes) {
			return std::nullopt;
		}
		const auto data = reader.take(size_t(*size));
		if (data.empty()) {
			return std::nullopt;
		}
		receipt.dataCleanup.assign(data.begin(), data.end());
	}
	if (!RequiredArtifacts(kind, paths) || !ValidId(operation) || !pid || !creation
		|| !Nonzero(proof) || !reader.done()) {
		return std::nullopt;
	}
	auto ticket = InstallationRemovalTicket{
		.operationId = OperationId(std::string(operation)),
		.parentProcessId = *pid,
		.parentCreationTime = *creation,
	};
	std::ranges::copy(proof, ticket.authentication.begin());
	if (!ValidTicket(ticket, kind, secret)) {
		return std::nullopt;
	}
	return InstallationRemovalHandoff(
		std::move(receipt),
		std::move(ticket),
		secret.first<kInstallationRemovalKeyBytes>());
}

InstallationRemovalResult RunInstallationRemovalHandoff(
		const InstallationId &expectedInstallation,
		InstallationRemovalProcessHandle inheritedParent,
		std::chrono::milliseconds timeout,
		bool requireDataCleanup) {
	if (!ValidId(expectedInstallation.value) || timeout < std::chrono::milliseconds::zero()
		|| timeout > std::chrono::minutes(5)) {
		return InstallationRemovalResult::TicketRejected;
	}
#ifdef _WIN32
	const auto input = GetStdHandle(STD_INPUT_HANDLE);
	const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!input || !output || input == output
		|| GetFileType(input) != FILE_TYPE_PIPE || GetFileType(output) != FILE_TYPE_PIPE) {
		return InstallationRemovalResult::Unavailable;
	}
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	const auto read = [=](std::span<uint8_t> bytes) -> std::optional<size_t> {
		auto available = DWORD(0);
		while (!available) {
			if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) {
				return GetLastError() == ERROR_BROKEN_PIPE ? std::optional<size_t>(0) : std::nullopt;
			}
			if (!available) {
				const auto remaining = RemainingMilliseconds(deadline);
				if (!remaining) {
					return std::nullopt;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(std::min(remaining, 10)));
			}
		}
		auto received = DWORD(0);
		const auto size = DWORD(std::min<size_t>(available, bytes.size()));
		if (!ReadFile(input, bytes.data(), size, &received, nullptr)) {
			return GetLastError() == ERROR_BROKEN_PIPE ? std::optional<size_t>(0) : std::nullopt;
		}
		return size_t(received);
	};
	const auto acknowledge = [=] {
		const auto ack = kInstallationRemovalHandoffAck;
		auto written = DWORD(0);
		return WriteFile(output, &ack, 1, &written, nullptr) && written == 1;
	};
#elif defined(__APPLE__) || defined(__linux__)
	using Stat = struct stat;
	auto input = Stat{};
	auto output = Stat{};
	if (fstat(STDIN_FILENO, &input) != 0 || fstat(STDOUT_FILENO, &output) != 0
		|| !S_ISFIFO(input.st_mode) || !S_ISFIFO(output.st_mode)
		|| (input.st_dev == output.st_dev && input.st_ino == output.st_ino)) {
		return InstallationRemovalResult::Unavailable;
	}
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	const auto read = [=](std::span<uint8_t> bytes) -> std::optional<size_t> {
		for (;;) {
			auto input = pollfd{ .fd = STDIN_FILENO, .events = POLLIN };
			const auto waited = poll(&input, 1, RemainingMilliseconds(deadline));
			if (waited < 0 && errno == EINTR) {
				continue;
			}
			if (waited != 1 || !(input.revents & (POLLIN | POLLHUP))) {
				return std::nullopt;
			}
			const auto received = ::read(STDIN_FILENO, bytes.data(), bytes.size());
			if (received < 0 && errno == EINTR) {
				continue;
			}
			return received >= 0 ? std::optional(size_t(received)) : std::nullopt;
		}
	};
	const auto acknowledge = [] {
		const auto restore = std::signal(SIGPIPE, SIG_IGN);
		if (restore == SIG_ERR) {
			return false;
		}
		const auto ack = kInstallationRemovalHandoffAck;
		auto written = ssize_t(0);
		do {
			written = ::write(STDOUT_FILENO, &ack, 1);
		} while (written < 0 && errno == EINTR);
		std::signal(SIGPIPE, restore);
		return written == 1;
	};
#else
	if (inheritedParent.value) {
		return InstallationRemovalResult::ParentUnavailable;
	}
	return InstallationRemovalResult::Unavailable;
#endif
#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
	const auto handoff = ReadInstallationRemovalHandoff(read);
	if (!handoff || handoff->receipt().installationId != expectedInstallation
		|| !IsNativePackage(handoff->receipt().kind)) {
		return InstallationRemovalResult::TicketRejected;
	}
	const auto &receipt = handoff->receipt();
	const auto hasData = !receipt.dataCleanup.empty();
	const auto data = hasData ? DecodeInstallationDataCleanupPlan(receipt.dataCleanup) : std::nullopt;
	if ((requireDataCleanup && !hasData)
		|| (hasData && (!data || data->installationId != expectedInstallation))) {
		return InstallationRemovalResult::TicketRejected;
	}
	auto effects = InstallationRemovalDataEffects();
	if (data) {
		const auto apply = [&](InstallationDataCleanupPhase phase) {
			return ClearInstallationDataFiles(expectedInstallation, data->dataDirectory, *data, phase)
				== InstallationDataCleanupResult::Complete;
		};
		effects.clear = [apply] { return apply(InstallationDataCleanupPhase::AfterExit); };
		effects.finalize = [apply] { return apply(InstallationDataCleanupPhase::FinalizeRecovery); };
	}
	auto receiver = InstallationRemovalReceiver();
	return receiver.RemoveAfterParentExit(
		expectedInstallation,
		handoff->receipt(),
		handoff->ticket(),
		handoff->secret(),
		timeout,
		acknowledge,
		inheritedParent,
		effects);
#endif
}

} // namespace Ayu::EmergencyActions
