#include "ayu/features/emergency_actions/scoped_account_clear.h"

#include <chrono>
#include <cstdio>
#include <fstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

using namespace Ayu::EmergencyActions;
namespace Fs = std::filesystem;

const auto kInstallation = InstallationId("fixture-installation");
const auto kTarget = AccountId("target-account");
const auto kNeighbor = AccountId("other-account");
constexpr auto kTargetLocator = "1111ac2444293a85533a373f247b25c0";
constexpr auto kNeighborLocator = "22228effc44571a77424d2fbc4575223";

int failures = 0;

void Check(const char *label, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", label);
	failures += !condition;
}

class Fixture final {
public:
	Fixture()
	: root(Fs::canonical(Fs::temp_directory_path()) / ("sleepy-scoped-clear-"
		+ std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())))
	, owned(Fs::create_directory(root)) {
	}

	~Fixture() {
		if (owned) {
			auto error = std::error_code();
			Fs::remove_all(root, error);
		}
	}

	[[nodiscard]] Fs::path dataRoot() const {
		return root / "installation";
	}
	[[nodiscard]] Fs::path accountsRoot() const {
		return dataRoot() / "profile-sets" / "accounts";
	}
	[[nodiscard]] ScopedAccountCleanupBinding binding() const {
		return {
			.installationId = kInstallation,
			.accountStorageRoot = accountsRoot(),
			.accounts = {
				{ kTarget, kTargetLocator },
				{ kNeighbor, kNeighborLocator },
			},
		};
	}
	[[nodiscard]] ScopedAccountClear clearer() const {
		return ScopedAccountClear(kInstallation, dataRoot(), binding());
	}

	const Fs::path root;
	const bool owned;

};

bool WriteFile(const Fs::path &path) {
	Fs::create_directories(path.parent_path());
	auto stream = std::ofstream(path, std::ios::binary);
	stream << "fixture contents";
	stream.close();
	return bool(stream);
}

void RemovesOnlyTheMappedAccountAndCanRepeat() {
	const auto fixture = Fixture();
	if (!fixture.owned) {
		Check("scoped-clear-temporary-fixture-owned", false);
		return;
	}
	const auto target = fixture.accountsRoot() / kTargetLocator;
	const auto neighbor = fixture.accountsRoot() / kNeighborLocator / "auth";
	const auto unmapped = fixture.accountsRoot() / std::string(32, 'a') / "auth";
	const auto download = fixture.root / "downloads" / "download.jpg";
	const auto exported = fixture.root / "exports" / "export.json";
	const auto otherInstall = fixture.root / "other-installation"
		/ "profile-sets" / "accounts" / kTargetLocator / "auth";
	Check("scoped-clear-test-seeds-only-fixtures",
		WriteFile(target / "auth")
		&& WriteFile(target / "data" / "cache" / "item")
		&& WriteFile(target / "user" / "archive.db")
		&& WriteFile(target / "temp" / "pending")
		&& WriteFile(neighbor) && WriteFile(unmapped)
		&& WriteFile(download) && WriteFile(exported) && WriteFile(otherInstall));
	auto error = std::error_code();
	Fs::create_directory_symlink(download.parent_path(), target / "data" / "directory-link", error);
	const auto directoryLink = !error;
	Fs::create_symlink(exported, target / "data" / "file-link", error);
	const auto fileLink = !error;
	Fs::create_hard_link(download, target / "data" / "another-link", error);
	const auto hardLink = !error;
#ifdef _WIN32
	if (!directoryLink || !fileLink || !hardLink) {
		std::printf("SKIP filesystem did not permit all fixture link types\n");
	}
#else
	Check("scoped-clear-fixture-links-created", directoryLink && fileLink && hardLink);
#endif
	auto adapter = fixture.clearer();
	Check("scoped-clear-removes-exact-locator-tree",
		adapter.clear(kTarget) == EffectResult::ConfirmedSuccess && !Fs::exists(target));
	Check("scoped-clear-preserves-neighbors-downloads-exports-other-installations",
		Fs::exists(neighbor) && Fs::exists(unmapped) && Fs::exists(download)
		&& Fs::exists(exported) && Fs::exists(otherInstall));
	auto reopened = fixture.clearer();
	Check("scoped-clear-missing-mapped-target-is-idempotent-after-reopen",
		reopened.clear(kTarget) == EffectResult::ConfirmedSuccess);
	Check("scoped-clear-unmapped-account-does-not-report-success",
		reopened.clear(AccountId("not-in-binding")) == EffectResult::ConfirmedFailure);
}

void InvalidBindingsAndUntrustedTargetTypesFailClosed() {
	const auto fixture = Fixture();
	if (!fixture.owned) {
		Check("scoped-clear-invalid-input-fixture-owned", false);
		return;
	}
	const auto target = fixture.accountsRoot() / kTargetLocator;
	Check("scoped-clear-binding-target-present", WriteFile(target / "auth"));
	auto foreign = ScopedAccountClear(InstallationId("other"), fixture.dataRoot(), fixture.binding());
	Check("scoped-clear-rejects-different-installation", foreign.clear(kTarget) == EffectResult::ConfirmedFailure);
	auto mismatched = fixture.binding();
	mismatched.accountStorageRoot = fixture.root / "other-installation";
	auto rootMismatch = ScopedAccountClear(kInstallation, fixture.dataRoot(), mismatched);
	Check("scoped-clear-rejects-mismatched-workspace", rootMismatch.clear(kTarget) == EffectResult::ConfirmedFailure);
	mismatched.accountStorageRoot = fixture.dataRoot() / ".." / "installation" / "profile-sets" / "accounts";
	auto unnormalizedRoot = ScopedAccountClear(kInstallation, fixture.dataRoot() / ".." / "installation", mismatched);
	Check("scoped-clear-rejects-dot-dot-in-workspace-path",
		unnormalizedRoot.clear(kTarget) == EffectResult::ConfirmedFailure);
	for (const auto locator : {
			"../downloads",
			"1111AC2444293A85533A373F247B25C0",
			"00000000000000000000000000000000",
			"" }) {
		auto invalid = fixture.binding();
		invalid.accounts.front().locator = locator;
		auto adapter = ScopedAccountClear(kInstallation, fixture.dataRoot(), invalid);
		Check("scoped-clear-rejects-noncanonical-locator", adapter.clear(kTarget) == EffectResult::ConfirmedFailure);
	}
	auto duplicateLocation = fixture.binding();
	duplicateLocation.accounts.back().locator = duplicateLocation.accounts.front().locator;
	auto alias = ScopedAccountClear(kInstallation, fixture.dataRoot(), duplicateLocation);
	Check("scoped-clear-rejects-locator-alias", alias.clear(kTarget) == EffectResult::ConfirmedFailure);
	auto duplicateAccount = fixture.binding();
	duplicateAccount.accounts.back().accountId = kTarget;
	auto duplicate = ScopedAccountClear(kInstallation, fixture.dataRoot(), duplicateAccount);
	Check("scoped-clear-rejects-repeated-account-id", duplicate.clear(kTarget) == EffectResult::ConfirmedFailure);
	Check("scoped-clear-invalid-bindings-preserve-intended-target", Fs::exists(target / "auth"));
	const auto replaced = fixture.accountsRoot() / kNeighborLocator;
	Check("scoped-clear-replacement-file-created", WriteFile(replaced));
	auto adapter = fixture.clearer();
	Check("scoped-clear-rejects-file-at-account-directory",
		adapter.clear(kNeighbor) == EffectResult::ConfirmedFailure && Fs::exists(replaced));
}

void RefusesSymlinksAtTargetOrWorkspaceAncestor() {
	const auto fixture = Fixture();
	if (!fixture.owned) {
		Check("scoped-clear-symlink-fixture-owned", false);
		return;
	}
	const auto outside = fixture.root / "another-workspace";
	const auto outsideAccount = outside / "accounts" / kTargetLocator;
	Check("scoped-clear-outside-fixture-present", WriteFile(outsideAccount / "auth"));
	Fs::create_directories(fixture.accountsRoot());
	const auto target = fixture.accountsRoot() / kTargetLocator;
	auto error = std::error_code();
	Fs::create_directory_symlink(outsideAccount, target, error);
	if (error) {
#ifdef _WIN32
		std::printf("SKIP filesystem did not permit directory symlink fixtures\n");
#else
		Check("scoped-clear-target-link-created", false);
#endif
		return;
	}
	auto adapter = fixture.clearer();
	Check("scoped-clear-rejects-link-at-target",
		adapter.clear(kTarget) == EffectResult::ConfirmedFailure
		&& Fs::is_symlink(target) && Fs::exists(outsideAccount / "auth"));
	Fs::rename(fixture.accountsRoot().parent_path(), fixture.root / "saved-workspace");
	Fs::create_directory_symlink(outside, fixture.accountsRoot().parent_path());
	Check("scoped-clear-rejects-replaced-workspace-ancestor",
		adapter.clear(kTarget) == EffectResult::ConfirmedFailure && Fs::exists(outsideAccount / "auth"));
}

void FailedRemovalIsRetriable() {
	const auto fixture = Fixture();
	if (!fixture.owned) {
		Check("scoped-clear-retry-fixture-owned", false);
		return;
	}
	const auto target = fixture.accountsRoot() / kTargetLocator;
	const auto folder = target / "data" / "protected";
	const auto file = folder / "cache";
	Check("scoped-clear-retry-fixture-written", WriteFile(file) && WriteFile(target / "auth"));
	auto adapter = fixture.clearer();
#ifdef _WIN32
	const auto locked = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (locked == INVALID_HANDLE_VALUE) {
		Check("scoped-clear-retry-fixture-lock-held", false);
		return;
	}
	const auto blocked = adapter.clear(kTarget);
	CloseHandle(locked);
#else
	if (geteuid() == 0) {
		std::printf("SKIP directory write restrictions bypassed for root\n");
		return;
	}
	const auto permissions = Fs::status(folder).permissions();
	Fs::permissions(folder, Fs::perms::owner_read | Fs::perms::owner_exec);
	const auto blocked = adapter.clear(kTarget);
	Fs::permissions(folder, permissions);
#endif
	Check("scoped-clear-reports-permission-failure-with-target-remaining",
		blocked == EffectResult::ConfirmedFailure && Fs::exists(file));
	auto reopened = fixture.clearer();
	Check("scoped-clear-retries-partial-cleanup-after-reopen",
		reopened.clear(kTarget) == EffectResult::ConfirmedSuccess && !Fs::exists(target));
}

} // namespace

int main() {
	RemovesOnlyTheMappedAccountAndCanRepeat();
	InvalidBindingsAndUntrustedTargetTypesFailClosed();
	RefusesSymlinksAtTargetOrWorkspaceAncestor();
	FailedRemovalIsRetriable();
	return failures ? 1 : 0;
}
