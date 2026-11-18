#include "ayu/features/emergency_actions/installation_data_cleanup.h"

#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <ranges>

namespace {

using namespace Ayu::EmergencyActions;
using Phase = InstallationDataCleanupPhase;
using Result = InstallationDataCleanupResult;
using Path = std::filesystem::path;

auto failures = 0;

void Check(const char *name, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	failures += !condition;
}

class FixtureDirectory final {
public:
	FixtureDirectory() {
		auto nonce = std::array<uint8_t, 16>{};
		if (RAND_bytes(nonce.data(), int(nonce.size())) != 1) {
			return;
		}
		auto label = std::string("sleepygram-data-cleanup-fixture-");
		constexpr auto digits = std::string_view("0123456789abcdef");
		for (const auto byte : nonce) {
			label.push_back(digits[byte >> 4]);
			label.push_back(digits[byte & 15]);
		}
		const auto directory = std::filesystem::canonical(
			std::filesystem::temp_directory_path()) / label;
		if (std::filesystem::create_directory(directory)) {
			path = directory;
		}
	}
	~FixtureDirectory() {
		if (!path.empty()) {
			auto error = std::error_code();
			std::filesystem::remove_all(path, error);
		}
	}

	Path path;

};

const auto kInstallation = InstallationId("synthetic-installation");
const auto kRecoveryOperation = OperationId("synthetic-removal");
const auto kKnownSet = std::string(32, 'a');
const auto kOtherSet = std::string(32, 'b');
const auto kKnownGeneration = std::string(32, 'c');

bool Write(const Path &path, std::string_view content) {
	std::filesystem::create_directories(path.parent_path());
	auto stream = std::ofstream(path, std::ios::binary | std::ios::trunc);
	stream.write(content.data(), std::streamsize(content.size()));
	return bool(stream);
}

bool CreateJournal(const Path &directory) {
	const auto journal = MakeJournal(BuildDryRunPlan(kRecoveryOperation, {
		.id = RuleId("synthetic-rule"),
		.installationId = kInstallation,
		.action = EmergencyAction::RemoveInstallation,
		.targetScope = TargetScope::CurrentInstallation,
	}, { .id = kInstallation }));
	if (!journal) {
		return false;
	}
	auto store = FileJournalStore(directory);
	const auto lease = store.tryAcquireExecution();
	return lease
		&& store.createAtomically(kRecoveryOperation, EncodeJournal(*journal)) == JournalCreateResult::Created;
}

void OnlyAuthorizedFilesAndCorrectPhaseAreRemoved() {
	const auto fixture = FixtureDirectory();
	if (fixture.path.empty()) {
		Check("isolated-cleanup-fixture", false);
		return;
	}
	const auto root = fixture.path / "tdata";
	const auto workspace = root / "profile-sets";
	const auto set = workspace / "set-settings" / kKnownSet;
	const auto unknownSet = workspace / "set-settings" / kOtherSet;
	const auto generation = workspace / "generations" / kKnownGeneration;
	const auto journal = workspace / "emergency-journal";
	const auto filesReady = Write(root / "settingss", "verified settings")
		&& Write(root / "ayu_settings.json", "verified preferences")
		&& Write(root / "working", "")
		&& Write(set / "sleepy-preferencess", "verified set")
		&& Write(generation / "emergency-recovery.bin", "replay record")
		&& Write(generation / "profile-vault.bin", "sealed profile")
		&& Write(workspace / ".cutover/active", "active generation")
		&& Write(set / "Manual export.txt", "user-owned export")
		&& Write(unknownSet / "sleepy-preferencess", "unknown set")
		&& Write(root / "tdld/downloaded.bin", "download")
		&& Write(root / "offline-history/export.json", "legacy user export")
		&& Write(root / "custom.dat", "unknown local file")
		&& Write(fixture.path / "log.txt", "sibling log")
		&& CreateJournal(journal);
	const auto scope = InstallationDataCleanupScope{
		.installationId = kInstallation,
		.dataDirectory = root,
		.setIds = { kKnownSet },
		.generationIds = { kKnownGeneration },
		.journalIds = { kRecoveryOperation },
	};
	const auto captured = filesReady ? CaptureInstallationDataCleanupPlan(scope) : std::nullopt;
	if (!captured) {
		Check("synthetic-cleanup-inventory-captured", false);
		return;
	}
	const auto bytes = EncodeInstallationDataCleanupPlan(*captured);
	const auto decoded = DecodeInstallationDataCleanupPlan(bytes);
	Check("bounded-plan-round-trips-exact-paths-digests-and-native-identities",
		decoded && decoded->installationId == captured->installationId
		&& decoded->dataDirectory.native() == captured->dataDirectory.native()
		&& decoded->rootIdentity == captured->rootIdentity && decoded->files == captured->files);
	if (!decoded) return;
	const auto cleanup = [&](Phase pass) {
		return ClearInstallationDataFiles(kInstallation, root, *decoded, pass);
	};
	Check("replay-material-cannot-be-finalized-before-normal-cleanup",
		cleanup(Phase::FinalizeRecovery) == Result::NormalFilesRemain
		&& std::filesystem::exists(generation / "emergency-recovery.bin")
		&& std::filesystem::exists(journal / "execution.lock"));
	Check("changed-replay-material-prevents-any-normal-deletion",
		Write(generation / "emergency-recovery.bin", "changed replay record")
		&& cleanup(Phase::AfterExit) == Result::UnexpectedFile
		&& std::filesystem::exists(root / "settingss")
		&& Write(generation / "emergency-recovery.bin", "replay record"));
	Check("normal-cleanup-removes-exact-root-and-approved-set-files",
		cleanup(Phase::AfterExit) == Result::Complete
		&& !std::filesystem::exists(root / "settingss")
		&& !std::filesystem::exists(root / "ayu_settings.json")
		&& !std::filesystem::exists(root / "working")
		&& !std::filesystem::exists(set / "sleepy-preferencess"));
	auto store = FileJournalStore(journal);
	Check("normal-cleanup-preserves-journal-and-commit-authority",
		std::filesystem::exists(generation / "emergency-recovery.bin")
		&& std::filesystem::exists(generation / "profile-vault.bin")
		&& std::filesystem::exists(workspace / ".cutover/active")
		&& std::filesystem::exists(journal / "execution.lock")
		&& LoadJournal(store, kRecoveryOperation).has_value());
	Check("ordinary-cleanup-is-idempotent-after-files-are-missing",
		cleanup(Phase::AfterExit) == Result::Complete);
	Check("finalize-clears-exact-authority-and-current-journal",
		cleanup(Phase::FinalizeRecovery) == Result::Complete
		&& !std::filesystem::exists(generation / "emergency-recovery.bin")
		&& !std::filesystem::exists(workspace / ".cutover/active")
		&& !std::filesystem::exists(journal / "execution.lock")
		&& std::filesystem::is_empty(journal)
		&& cleanup(Phase::FinalizeRecovery) == Result::Complete);
	Check("cleanup-preserves-shared-paths-exports-unknown-sets-and-root",
		std::filesystem::is_directory(root) && std::filesystem::is_directory(set)
		&& std::filesystem::exists(set / "Manual export.txt")
		&& std::filesystem::exists(unknownSet / "sleepy-preferencess")
		&& std::filesystem::exists(root / "custom.dat")
		&& std::filesystem::exists(root / "tdld/downloaded.bin")
		&& std::filesystem::exists(root / "offline-history/export.json")
		&& std::filesystem::exists(fixture.path / "log.txt"));
}

void ChangedOrUnsafeInputsCannotBeginRemoval() {
	const auto fixture = FixtureDirectory();
	if (fixture.path.empty()) {
		Check("isolated-preflight-fixture", false);
		return;
	}
	const auto root = fixture.path / "tdata";
	const auto first = root / "config";
	const auto last = root / "settingss";
	const auto scope = InstallationDataCleanupScope{ .installationId = kInstallation, .dataDirectory = root };
	const auto captured = Write(first, "first") && Write(last, "last")
		? CaptureInstallationDataCleanupPlan(scope) : std::nullopt;
	if (!captured) {
		Check("synthetic-preflight-inventory-captured", false);
		return;
	}
	Check("wrong-installation-or-externally-verified-root-is-rejected",
		ClearInstallationDataFiles(InstallationId("other-installation"), root, *captured, Phase::AfterExit)
			== Result::InvalidPlan
		&& ClearInstallationDataFiles(kInstallation, fixture.path / "different" / "tdata",
			*captured, Phase::AfterExit) == Result::InvalidPlan);
	Check("changed-later-file-preflight-preserves-all-other-files",
		Write(last, "tampered")
		&& ClearInstallationDataFiles(kInstallation, root, *captured, Phase::AfterExit)
			== Result::UnexpectedFile
		&& std::filesystem::exists(first));
	const auto movedFile = fixture.path / "moved-setting";
	std::filesystem::rename(last, movedFile);
	Check("same-name-replacement-is-not-the-captured-identity",
		Write(last, "last")
		&& ClearInstallationDataFiles(kInstallation, root, *captured, Phase::AfterExit)
			== Result::UnexpectedFile
		&& std::filesystem::exists(first));
	const auto retained = fixture.path / "retained";
	std::filesystem::create_hard_link(first, retained);
	Check("capturing-shared-inode-is-rejected",
		!CaptureInstallationDataCleanupPlan(scope) && std::filesystem::exists(retained));
	std::filesystem::remove(retained);
#ifndef _WIN32
	std::filesystem::remove(last);
	std::filesystem::create_symlink(movedFile, last);
	Check("leaf-symlink-is-rejected-without-touching-target-or-neighbor",
		!CaptureInstallationDataCleanupPlan(scope)
		&& ClearInstallationDataFiles(kInstallation, root, *captured, Phase::AfterExit)
			== Result::UnexpectedFile
		&& std::filesystem::exists(first)
		&& std::filesystem::exists(movedFile));
	std::filesystem::remove(last);
	const auto foreign = fixture.path / "foreign";
	std::filesystem::create_directory(foreign);
	std::filesystem::create_directory_symlink(foreign, root / "profile-sets");
	Check("known-managed-ancestor-symlink-fails-capture",
		!CaptureInstallationDataCleanupPlan(scope) && std::filesystem::is_empty(foreign));
	std::filesystem::remove(root / "profile-sets");
#endif
	const auto displaced = fixture.path / "retired-root";
	std::filesystem::rename(root, displaced);
	Check("replaced-tdata-root-is-rejected",
		Write(first, "first")
		&& ClearInstallationDataFiles(kInstallation, root, *captured, Phase::AfterExit)
			== Result::UnexpectedFile
		&& std::filesystem::exists(first)
		&& std::filesystem::exists(displaced / "config"));
#ifndef _WIN32
	std::filesystem::remove(first);
	std::filesystem::remove(root);
	std::filesystem::create_directory_symlink(displaced, root);
	Check("tdata-root-symlink-cannot-retarget-cleanup", !CaptureInstallationDataCleanupPlan(scope)
		&& ClearInstallationDataFiles(kInstallation, root, *captured, Phase::AfterExit)
			== Result::UnexpectedFile
		&& std::filesystem::exists(displaced / "config"));
	std::filesystem::remove(root);
#endif
}

void PlanFramingAndSparseSetScale() {
	const auto fixture = FixtureDirectory();
	if (fixture.path.empty()) {
		Check("isolated-wire-fixture", false);
		return;
	}
	const auto root = fixture.path / "tdata";
	const auto profileRoot = root / "profile-sets/set-settings";
	auto scope = InstallationDataCleanupScope{ .installationId = kInstallation, .dataDirectory = root };
	for (auto i = 1; i <= 1000; ++i) {
		auto scopeId = std::array<char, 33>{};
		std::snprintf(scopeId.data(), scopeId.size(), "%032x", unsigned(i));
		scope.setIds.emplace_back(scopeId.data());
		std::filesystem::create_directories(profileRoot / scope.setIds.back());
	}
	const auto last = profileRoot / scope.setIds.back() / "settingss";
	const auto plan = Write(last, "one file among sparse sets")
		? CaptureInstallationDataCleanupPlan(scope) : std::nullopt;
	Check("one-thousand-sparse-sets-are-not-limited-by-absent-candidates",
		plan && plan->files.size() == 1);
	if (!plan) return;
	const auto wire = EncodeInstallationDataCleanupPlan(*plan);
	auto corrupted = wire;
	corrupted.push_back(0);
	Check("wire-rejects-extra-bytes", !DecodeInstallationDataCleanupPlan(corrupted));
	corrupted.pop_back();
	corrupted.pop_back();
	Check("wire-rejects-truncated-digest", !DecodeInstallationDataCleanupPlan(corrupted));
	auto foreign = *plan;
	foreign.files.front().relativePath = "profile-sets/accounts/owned-but-not-global-policy";
	Check("path-policy-rejects-account-root-or-unknown-paths",
		!ValidateInstallationDataCleanupPlan(foreign) && EncodeInstallationDataCleanupPlan(foreign).empty());
	foreign = *plan;
	foreign.files.push_back(foreign.files.front());
	Check("path-policy-rejects-duplicate-files", !ValidateInstallationDataCleanupPlan(foreign));
	foreign = *plan;
	foreign.files.front().identity.node = foreign.rootIdentity.node;
	Check("path-policy-rejects-file-reusing-root-identity", !ValidateInstallationDataCleanupPlan(foreign));
	foreign = *plan;
	++foreign.files.front().identity.volume;
	Check("path-policy-rejects-cross-volume-file", !ValidateInstallationDataCleanupPlan(foreign));
}

} // namespace

int main() {
	OnlyAuthorizedFilesAndCorrectPhaseAreRemoved();
	ChangedOrUnsafeInputsCannotBeginRemoval();
	PlanFramingAndSparseSetScale();
	return failures ? 1 : 0;
}
