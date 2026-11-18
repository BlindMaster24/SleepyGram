#include "ayu/features/emergency_actions/installation_removal_handoff.h"

#include <algorithm>
#include <cstdio>
#include <ranges>
#include <type_traits>

#if defined(__APPLE__) || defined(__linux__)
#include <cerrno>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using namespace Ayu::EmergencyActions;
using Kind = InstallationPackageKind;
using Path = std::filesystem::path;

auto failures = 0;

void Check(const char *name, bool passed) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
	failures += !passed;
}

InstallationArtifactDigest Marker(uint8_t start) {
	auto result = InstallationArtifactDigest();
	for (auto i = size_t(0); i != result.size(); ++i) {
		result[i] = uint8_t(start + i);
	}
	return result;
}

struct Fixture final {
	explicit Fixture(Kind kind)
	: receipt({
		.installationId = InstallationId("synthetic-receipt"),
		.kind = kind,
	})
	, ticket({
		.operationId = OperationId("synthetic-operation"),
		.parentProcessId = 0x7fffffff,
		.authentication = Marker(31),
		.parentCreationTime = (kind == Kind::WindowsPortable) ? uint64_t(2048) : uint64_t(0),
	}) {
		auto paths = std::vector<std::u8string>();
		switch (kind) {
		case Kind::WindowsPortable:
			receipt.packageRoot = Path(u8"C:\\Synthetic Location\\SleepyGram");
			paths = { u8"SleepyGram.exe", u8"build-manifest.json", u8"LICENSE-SQLCipher.txt",
				u8"modules/x64/d3d/d3dcompiler_47.dll" };
			break;
		case Kind::MacBundle:
			receipt.packageRoot = Path(u8"/synthetic user/Сон/SleepyGram.app");
			paths = { u8"Contents/MacOS/SleepyGram", u8"Contents/Info.plist",
				u8"Contents/Resources/BuildManifest.json",
				u8"Contents/Resources/LICENSE-SQLCipher.txt",
				u8"Contents/Resources/SleepyGram.icns",
				u8"Contents/Resources/Telegram.rcc" };
			break;
		default:
			receipt.packageRoot = Path(u8"/synthetic user/portable");
			paths = { u8"SleepyGram", u8"build-manifest.json", u8"LICENSE-SQLCipher.txt" };
			break;
		}
		for (const auto &path : paths) {
			receipt.artifacts.push_back({ Path(path), Marker(uint8_t(81 + receipt.artifacts.size())) });
		}
	}

	VerifiedInstallationReceipt receipt;
	InstallationRemovalTicket ticket;
	InstallationArtifactDigest secret = Marker(171);

	[[nodiscard]] std::optional<std::vector<uint8_t>> encode() const {
		auto buffer = std::vector<uint8_t>();
		const auto write = [&](std::span<const uint8_t> bytes) -> std::optional<size_t> {
			const auto count = std::min(size_t(3), bytes.size());
			const auto chunk = bytes.first(count);
			buffer.insert(buffer.end(), chunk.begin(), chunk.end());
			return count;
		};
		return WriteInstallationRemovalHandoff(receipt, ticket, secret, write)
			? std::optional(std::move(buffer))
			: std::nullopt;
	}
};

std::optional<InstallationRemovalHandoff> Decode(std::span<const uint8_t> source) {
	return ReadInstallationRemovalHandoff([&](std::span<uint8_t> bytes) -> std::optional<size_t> {
		const auto count = std::min({ bytes.size(), source.size(), size_t(2) });
		std::ranges::copy(source.first(count), bytes.begin());
		source = source.subspan(count);
		return count;
	});
}

bool RoundTrip(Kind kind) {
	const auto f = Fixture(kind);
	const auto frame = f.encode();
	auto opened = frame ? Decode(*frame) : std::nullopt;
	if (!opened) {
		return false;
	}
	const auto &value = opened->receipt();
	const auto &ticket = opened->ticket();
	if (value.kind != kind || value.installationId != f.receipt.installationId
		|| value.packageRoot.native() != f.receipt.packageRoot.native()
		|| ticket.operationId != f.ticket.operationId
		|| ticket.parentProcessId != f.ticket.parentProcessId
		|| ticket.parentCreationTime != f.ticket.parentCreationTime
		|| ticket.authentication != f.ticket.authentication
		|| !std::ranges::equal(opened->secret(), f.secret)
		|| value.artifacts.size() != f.receipt.artifacts.size()) {
		return false;
	}
	for (const auto &entry : value.artifacts) {
		const auto match = std::ranges::find(f.receipt.artifacts, entry.relativePath,
			&VerifiedInstallationArtifact::relativePath);
		if (match == f.receipt.artifacts.end() || entry.digest != match->digest
			|| entry.relativePath.native() != match->relativePath.native()) {
			return false;
		}
	}
	static_assert(!std::is_copy_constructible_v<InstallationRemovalHandoff>);
	const auto moved = std::move(*opened);
	return std::ranges::equal(moved.secret(), f.secret)
		&& std::ranges::none_of(opened->secret(), [](auto byte) { return byte != 0; });
}

void RejectUnsafeReceipts() {
	auto portable = Fixture(Kind::LinuxPortable);
	portable.receipt.artifacts.push_back(portable.receipt.artifacts.back());
	Check("encoder-rejects-repeated-artifact-paths", !portable.encode());
	portable.receipt.artifacts.back().relativePath = Path("../license");
	Check("encoder-rejects-traversal-relative-to-package", !portable.encode());
	portable.receipt.artifacts.pop_back();
	portable.receipt.artifacts.pop_back();
	Check("encoder-requires-package-identity-artifacts", !portable.encode());
	auto mac = Fixture(Kind::MacBundle);
	mac.receipt.packageRoot = Path("/synthetic//SleepyGram.app");
	Check("encoder-rejects-repeated-separators", !mac.encode());
	mac.receipt.packageRoot = Path("/synthetic/../SleepyGram.app");
	Check("encoder-rejects-imported-root-traversal", !mac.encode());
	mac.receipt.packageRoot = Path("/synthetic/Another.app");
	Check("encoder-requires-the-supported-mac-bundle-name", !mac.encode());
	mac.receipt.packageRoot = Path("/synthetic/SleepyGram.app");
	mac.receipt.artifacts.push_back({ Path("Contents/../foreign"), Marker(99) });
	Check("encoder-rejects-cross-bundle-traversal", !mac.encode());

	auto windows = Fixture(Kind::WindowsPortable);
	windows.receipt.packageRoot = Path(u8"\\\\server\\share\\SleepyGram");
	Check("encoder-rejects-windows-unc-root", !windows.encode());
	windows.receipt.packageRoot = Path(u8"\\\\?\\C:\\Synthetic\\SleepyGram");
	Check("encoder-rejects-windows-device-root-spelling", !windows.encode());
	windows.receipt.packageRoot = Path(u8"C:/Synthetic/SleepyGram");
	Check("encoder-rejects-alternate-windows-root-separators", !windows.encode());
	windows.receipt.packageRoot = Path(u8"C:\\Synthetic\\CON.txt");
	Check("encoder-rejects-windows-reserved-device-components", !windows.encode());
	windows.receipt.packageRoot = Path(u8"C:\\Synthetic\\SleepyGram:alternate");
	Check("encoder-rejects-windows-alternate-data-stream-names", !windows.encode());
	windows.receipt.packageRoot = Path(u8"C:\\Synthetic\\SleepyGram.");
	Check("encoder-rejects-windows-trailing-dot-alias", !windows.encode());
	windows.receipt.packageRoot = Path(u8"C:\\Synthetic\\SleepyGram");
	windows.receipt.artifacts.back().relativePath = Path(u8"modules\\x64\\d3d\\d3dcompiler_47.dll");
	Check("encoder-rejects-noncanonical-artifact-separators", !windows.encode());

	auto registered = Fixture(Kind::RegisteredPackage);
	Check("registered-package-route-cannot-be-serialized-as-automatic", !registered.encode());
	auto invalid = Fixture(Kind::WindowsPortable);
	invalid.ticket.parentCreationTime = 0;
	Check("windows-ticket-requires-an-issuer-birth-time", !invalid.encode());
	invalid = Fixture(Kind::LinuxPortable);
	invalid.ticket.parentProcessId = 0;
	Check("portable-ticket-requires-a-bounded-positive-issuer", !invalid.encode());
	invalid = Fixture(Kind::LinuxPortable);
	invalid.secret.fill(0);
	Check("empty-authentication-secret-is-rejected", !invalid.encode());
}

void RejectMalformedFrames() {
	const auto f = Fixture(Kind::LinuxPortable);
	const auto frame = f.encode();
	if (!frame) {
		Check("bounded-protocol-fixture-encoded", false);
		return;
	}
	auto changed = *frame;
	changed[7] = 2;
	Check("reader-rejects-unknown-version", !Decode(changed));
	changed = *frame;
	std::fill_n(changed.begin() + 8, 4, uint8_t(0xff));
	Check("reader-rejects-oversized-body-after-reading-only-header", !Decode(changed));
	changed = *frame;
	changed.push_back(0);
	Check("reader-requires-one-frame-followed-by-eof", !Decode(changed));
	Check("reader-refuses-truncated-secret",
		!Decode(std::span(*frame).first(frame->size() - 1)));
	changed = *frame;
	const auto rootOffset = 12 + 1 + 4 + f.receipt.installationId.value.size() + 4;
	changed[rootOffset + 1] = 0xc0;
	Check("reader-refuses-invalid-utf8-before-native-path-conversion", !Decode(changed));
	changed = *frame;
	std::fill_n(changed.end() - kInstallationRemovalKeyBytes, kInstallationRemovalKeyBytes, uint8_t(0));
	Check("reader-rejects-an-all-zero-secret", !Decode(changed));
	Check("reader-rejects-failed-and-impossible-io-counts",
		!ReadInstallationRemovalHandoff([](std::span<uint8_t>) -> std::optional<size_t> {
			return std::nullopt;
		}) && !ReadInstallationRemovalHandoff([](std::span<uint8_t> buffer) {
			return std::optional(buffer.size() + 1);
		}));
	Check("writer-fails-without-looping-on-zero-byte-progress",
		!WriteInstallationRemovalHandoff(
			f.receipt, f.ticket, f.secret, [](std::span<const uint8_t>) {
				return std::optional<size_t>(0);
			}));

	auto mac = Fixture(Kind::MacBundle);
	mac.receipt.artifacts.push_back({ Path("Contents/Resources/Synthetic-A"), Marker(41) });
	mac.receipt.artifacts.push_back({ Path("Contents/Resources/Synthetic-B"), Marker(42) });
	const auto paired = mac.encode();
	if (!paired) {
		Check("duplicate-path-reader-fixture", false);
		return;
	}
	changed = *paired;
	const auto second = std::string_view("Contents/Resources/Synthetic-B");
	const auto entry = std::ranges::search(changed, second);
	if (entry.empty()) {
		Check("duplicate-path-reader-fixture", false);
		return;
	}
	*(entry.end() - 1) = 'A';
	Check("reader-refuses-a-duplicate-artifact-path-in-a-valid-length-frame", !Decode(changed));
}

#if defined(__APPLE__) || defined(__linux__)
bool NativeDeclinesWithoutAck(bool wrongInstall, bool stall = false) {
#ifdef __APPLE__
	const auto f = Fixture(Kind::MacBundle);
#else
	const auto f = Fixture(Kind::LinuxPortable);
#endif
	const auto frame = f.encode();
	auto input = std::array<int, 2>{};
	auto output = std::array<int, 2>{};
	if (!frame || pipe(input.data()) != 0) {
		return false;
	}
	if (pipe(output.data()) != 0) {
		close(input[0]);
		close(input[1]);
		return false;
	}
	const auto process = fork();
	if (!process) {
		if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0) {
			_exit(125);
		}
		close(input[0]);
		close(input[1]);
		close(output[0]);
		close(output[1]);
		const auto install = wrongInstall ? InstallationId("foreign") : f.receipt.installationId;
		const auto timeout = stall ? std::chrono::milliseconds(50) : std::chrono::seconds(2);
		_exit(int(RunInstallationRemovalHandoff(install, {}, timeout)));
	}
	close(input[0]);
	close(output[1]);
	auto sent = bool(process > 0);
	if (sent && !stall) {
		sent = write(input[1], frame->data(), frame->size()) == ssize_t(frame->size());
		close(input[1]);
	}
	auto outcome = 0;
	const auto waited = (process > 0) && waitpid(process, &outcome, 0) == process;
	if (stall || process <= 0) {
		close(input[1]);
	}
	auto ack = uint8_t(0);
	const auto noAck = read(output[0], &ack, 1) == 0;
	close(output[0]);
	const auto expected = (wrongInstall || stall)
		? InstallationRemovalResult::TicketRejected
		: InstallationRemovalResult::ParentUnavailable;
	return sent && waited && WIFEXITED(outcome) && WEXITSTATUS(outcome) == int(expected) && noAck;
}
#endif

} // namespace

int main() {
	Check("fragmented-linux-handoff-round-trips", RoundTrip(Kind::LinuxPortable));
	Check("fragmented-mac-handoff-round-trips-unicode-path", RoundTrip(Kind::MacBundle));
	Check("fragmented-windows-handoff-preserves-exact-path-and-birth-time",
		RoundTrip(Kind::WindowsPortable));
	RejectUnsafeReceipts();
	RejectMalformedFrames();
#if defined(__APPLE__) || defined(__linux__)
	Check("native-pipes-emit-no-ack-for-foreign-installation", NativeDeclinesWithoutAck(true));
	Check("native-pipes-emit-no-ack-for-wrong-issuer-process", NativeDeclinesWithoutAck(false));
	Check("stalled-inherited-input-times-out-without-ack", NativeDeclinesWithoutAck(false, true));
#endif
	return failures ? 1 : 0;
}
