/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_migration.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QLockFile>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryDir>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <cstdio>

namespace {

using namespace Ayu::ProfileSets;

constexpr auto kCrashCode = 41;
constexpr auto kProfileFixturePrefix = "sleepygram-migration-cas-fixture-";

std::filesystem::path NewWorkspacePath(const char *label) {
	const auto suffix = std::chrono::steady_clock::now()
		.time_since_epoch().count();
	const auto name = std::string("sleepygram-migration-fixture-")
		+ label
		+ '-'
		+ std::to_string(suffix);
	return std::filesystem::path(QDir::tempPath().toStdString()) / name;
}

bool WriteFixture(
		const std::filesystem::path &path,
		const std::string &bytes) {
	auto file = std::ofstream(path, std::ios::binary | std::ios::trunc);
	file.write(bytes.data(), std::streamsize(bytes.size()));
	return file.good();
}

std::string ReadFixture(const std::filesystem::path &path) {
	auto file = std::ifstream(path, std::ios::binary);
	return std::string(
		std::istreambuf_iterator<char>(file),
		std::istreambuf_iterator<char>());
}

std::vector<MigrationInput> Inputs() {
	return {
		{
			.artifact = MigrationArtifact::ProfileVault,
			.encryptedBytes = QByteArray("generated-encrypted-vault-fixture-v1"),
		},
		{
			.artifact = MigrationArtifact::AccountKeyring,
			.encryptedBytes = QByteArray("generated-encrypted-keyring-fixture-v1"),
		},
	};
}

std::vector<MigrationInput> ReplacementInputs() {
	auto inputs = Inputs();
	inputs[0].encryptedBytes += QByteArray("-replaced-vault");
	inputs[1].encryptedBytes += QByteArray("-replaced-keyring");
	return inputs;
}

bool Matches(
		const CommittedMigration &generation,
		const std::vector<MigrationInput> &inputs) {
	return generation.profileVault == inputs[0].encryptedBytes
		&& generation.accountKeyring == inputs[1].encryptedBytes;
}

std::filesystem::path GenerationDirectory(
		const std::filesystem::path &root,
		const QByteArray &id) {
	return root / "generations" / id.toHex().toStdString();
}

int EndDuringReplace(const QString &dataDirectory, const QByteArray &id) {
	const auto container = QFileInfo(dataDirectory).dir();
	if (!container.dirName().startsWith(QLatin1StringView(kProfileFixturePrefix))
		|| QFileInfo(container.path()).dir().canonicalPath()
			!= QDir(QDir::tempPath()).canonicalPath()) {
		return 1;
	}
	const auto workspace = MigrationController::OpenProfileWorkspace(dataDirectory);
	if (!workspace) {
		return 1;
	}
	const auto interrupted = workspace->ReplaceCommitted(
		id,
		ReplacementInputs(),
		[](const CommittedMigration&) -> bool { std::_Exit(kCrashCode); });
	return interrupted ? 2 : 3;
}

int RunChecks() {
	auto passed = 0;
	auto total = 0;
	const auto check = [&](const char *name, bool condition) {
		++total;
		if (condition) {
			++passed;
			std::printf("PASS %s\n", name);
		} else {
			std::printf("FAIL %s\n", name);
		}
	};

	auto error = MigrationError::None;
	const auto unsafe = MigrationController::CreateIsolatedFixtureWorkspace(
		QString::fromStdString((NewWorkspacePath("unsafe").parent_path()
			/ "outside-workspace").string()),
		&error);
	check("workspace-must-be-explicit-dedicated-temp-child",
		!unsafe && error == MigrationError::UnsafeWorkspace);

	const auto primaryPath = NewWorkspacePath("primary");
	auto workspace = MigrationController::CreateIsolatedFixtureWorkspace(
		QString::fromStdString(primaryPath.string()),
		&error);
	check("dedicated-workspace-created", workspace.has_value()
		&& error == MigrationError::None);
	if (!workspace) {
		return 1;
	}
	auto invalidInputs = Inputs();
	invalidInputs[1].artifact = static_cast<MigrationArtifact>(99);
	check("artifact-allowlist-rejects-unknown-kind",
		!workspace->Stage(invalidInputs, &error)
		&& error == MigrationError::InvalidInput
		&& workspace->Recover(&error) == MigrationState::Empty);

	const auto inputs = Inputs();
	check("stage-and-readback-verified",
		workspace->Stage(inputs, &error)
		&& error == MigrationError::None
		&& workspace->Recover(&error) == MigrationState::Staged
		&& error == MigrationError::None);
	check("staged-data-does-not-switch-model",
		!workspace->LoadCommitted(&error)
		&& error == MigrationError::NotStaged);

	const auto recovered = MigrationController::OpenIsolatedFixtureWorkspace(
		QString::fromStdString(primaryPath.string()),
		&error);
	check("pending-transaction-recovers-without-activation",
		recovered.has_value()
		&& recovered->Recover(&error) == MigrationState::Staged
		&& !recovered->LoadCommitted(&error));
	if (!recovered) {
		return 1;
	}
	check("duplicate-stage-is-refused-without-cleanup",
		!recovered->Stage(inputs, &error)
		&& error == MigrationError::AlreadyStaged);

	const auto committed = recovered->Commit(&error);
	check("atomic-commit-returns-verified-model",
		committed
		&& error == MigrationError::None
		&& committed->profileVault == inputs[0].encryptedBytes
		&& committed->accountKeyring == inputs[1].encryptedBytes
		&& committed->transactionId.size() == 16
		&& recovered->Recover(&error) == MigrationState::Committed);
	const auto loaded = recovered->LoadCommitted(&error);
	const auto repeatedCommit = recovered->Commit(&error);
	check("committed-model-survives-reopen-and-repeat",
		committed && loaded && repeatedCommit
		&& loaded->transactionId == committed->transactionId
		&& repeatedCommit->transactionId == committed->transactionId);

	const auto corruptPath = NewWorkspacePath("corrupt");
	auto corrupt = MigrationController::CreateIsolatedFixtureWorkspace(
		QString::fromStdString(corruptPath.string()),
		&error);
	const auto corruptStage = corruptPath / "stage" / "profile-vault.bin";
	const auto corruptionWritten = corrupt
		&& corrupt->Stage(inputs, &error)
		&& WriteFixture(corruptStage, "tampered-fixture");
	check("payload-tamper-blocks-recovery-and-model-switch",
		corruptionWritten
		&& corrupt->Recover(&error) == MigrationState::Invalid
		&& error == MigrationError::ReadbackFailed
		&& !corrupt->LoadCommitted(&error));

	const auto manifestPath = primaryPath / "migration.manifest.committed";
	auto manifest = ReadFixture(manifestPath);
	const auto allowlistEntry = manifest.find("profile-vault");
	if (allowlistEntry != std::string::npos) {
		manifest.replace(allowlistEntry, std::string("profile-vault").size(), "../outside");
	}
	const auto allowlistTamperWritten = (allowlistEntry != std::string::npos)
		&& WriteFixture(manifestPath, manifest);
	check("manifest-path-injection-is-rejected",
		allowlistTamperWritten
		&& recovered->Recover(&error) == MigrationState::Invalid
		&& !std::filesystem::exists(primaryPath / "outside"));

	const auto incompletePath = NewWorkspacePath("incomplete");
	auto incomplete = MigrationController::CreateIsolatedFixtureWorkspace(
		QString::fromStdString(incompletePath.string()),
		&error);
	const auto incompleteFixture = incomplete
		&& std::filesystem::create_directory(incompletePath / "stage")
		&& WriteFixture(
			incompletePath / "stage" / "profile-vault.bin",
			"partial-write");
	check("interrupted-pre-manifest-stage-stays-incomplete",
		incompleteFixture
		&& incomplete->Recover(&error) == MigrationState::Incomplete
		&& !incomplete->LoadCommitted(&error));
	const auto profile = QTemporaryDir(
		QDir::tempPath() + '/' + QString::fromLatin1(kProfileFixturePrefix)
		+ QStringLiteral("XXXXXX"));
	if (!profile.isValid()) {
		return 1;
	}
	const auto dataDirectory = QDir(profile.path()).filePath(QStringLiteral("tdata"));
	if (!QDir(profile.path()).mkdir(QStringLiteral("tdata"))) {
		return 1;
	}
	check("probing-an-existing-legacy-profile-is-read-only",
		MigrationController::ProbeProfileWorkspace(dataDirectory, &error)
			== MigrationState::Empty
		&& error == MigrationError::None
		&& QDir(dataDirectory).isEmpty());
	const auto live = MigrationController::CreateProfileWorkspace(
		dataDirectory,
		&error);
	check("reserved-profile-workspace-keeps-an-explicit-account-root",
		live && !live->isIsolatedFixture()
		&& QFileInfo(live->accountStorageRoot()).isDir()
		&& !MigrationController::OpenIsolatedFixtureWorkspace(live->workspacePath()));
	if (!live) {
		return 1;
	}
	{
		auto lock = QLockFile(QDir(live->workspacePath()).filePath(
			QStringLiteral("migration.lock")));
		check("another-owner-cannot-stage-or-commit",
			lock.tryLock(0)
			&& !live->Stage(inputs, &error)
			&& error == MigrationError::WorkspaceBusy
			&& !live->CommitVerified([](const auto &) { return true; }, &error)
			&& error == MigrationError::WorkspaceBusy);
	}
	check("workspace-can-stage-after-owner-releases-lock",
		live->Stage(inputs, &error) && error == MigrationError::None);
	check("production-commit-requires-explicit-verification",
		!live->Commit(&error) && error == MigrationError::VerificationRequired
		&& !live->LoadCommitted());
	check("failing-verifier-does-not-activate-profile",
		!live->CommitVerified([](const auto &) { return false; }, &error)
		&& error == MigrationError::VerificationFailed
		&& live->Recover() == MigrationState::Staged);
	const auto liveVault = std::filesystem::path(
		live->workspacePath().toStdString()) / "stage" / "profile-vault.bin";
	const auto originalVault = ReadFixture(liveVault);
	check("verification-cannot-publish-a-changed-artifact",
		!live->CommitVerified([&](const auto &) {
			return WriteFixture(liveVault, "changed-during-verification");
		}, &error)
		&& error == MigrationError::ReadbackFailed
		&& !live->LoadCommitted());
	if (!WriteFixture(liveVault, originalVault)) {
		return 1;
	}
	const auto initial = live->CommitVerified(
		[&](const CommittedMigration &files) { return Matches(files, inputs); },
		&error);
	check("verified-profile-commit-is-visible-to-startup",
		initial
		&& MigrationController::ProbeProfileWorkspace(dataDirectory)
			== MigrationState::Committed);
	if (!initial) {
		return 1;
	}
	const auto root = std::filesystem::path(live->workspacePath().toStdString());
	const auto accountRoot = live->accountStorageRoot();
	const auto accountWitness = std::filesystem::path(accountRoot.toStdString())
		/ "unrelated-account-fixture";
	if (!WriteFixture(accountWitness, "account-data")) {
		return 1;
	}
	const auto replacement = ReplacementInputs();
	const auto verify = [&](const CommittedMigration &files) {
		return Matches(files, replacement);
	};
	const auto isActive = [&](const QByteArray &id) {
		const auto active = live->LoadCommitted();
		return active && active->transactionId == id;
	};
	{
		auto lock = QLockFile(QDir(live->workspacePath()).filePath(
			QStringLiteral("migration.lock")));
		check("another-owner-cannot-replace-or-retire",
			lock.tryLock(0)
			&& !live->ReplaceCommitted(
				initial->transactionId,
				replacement,
				verify,
				&error)
			&& error == MigrationError::WorkspaceBusy
			&& !live->RetireInactiveGenerations(initial->transactionId, &error)
			&& error == MigrationError::WorkspaceBusy);
	}
	check("replacement-requires-a-verifier",
		!live->ReplaceCommitted(initial->transactionId, replacement, {}, &error)
		&& error == MigrationError::VerificationRequired);
	check("replacement-cryptographic-refusal-does-not-advance",
		!live->ReplaceCommitted(
			initial->transactionId,
			replacement,
			[](const auto &) { return false; },
			&error)
		&& error == MigrationError::VerificationFailed
		&& isActive(initial->transactionId));
	check("tampered-replacement-is-never-selected",
		!live->ReplaceCommitted(
			initial->transactionId,
			replacement,
			[&](const CommittedMigration &candidate) {
				return Matches(candidate, replacement)
					&& WriteFixture(
						GenerationDirectory(root, candidate.transactionId)
							/ "account-keyring.bin",
						"changed-after-verification");
			},
			&error)
		&& error == MigrationError::ReadbackFailed
		&& isActive(initial->transactionId));

	auto crash = QProcess();
	crash.start(QCoreApplication::applicationFilePath(), {
		QStringLiteral("--end-during-replace"),
		dataDirectory,
		QString::fromLatin1(initial->transactionId.toHex()),
	});
	const auto crashed = crash.waitForFinished()
		&& crash.exitStatus() == QProcess::NormalExit
		&& crash.exitCode() == kCrashCode;
	const auto afterCrash = live->LoadCommitted();
	check("process-exit-with-written-candidate-leaves-old-pair-active",
		crashed && afterCrash && afterCrash->transactionId == initial->transactionId
		&& Matches(*afterCrash, inputs));

	const auto second = live->ReplaceCommitted(
		initial->transactionId,
		replacement,
		[&](const CommittedMigration &candidate) {
			const auto active = live->LoadCommitted();
			return active && active->transactionId == initial->transactionId
				&& Matches(*active, inputs) && verify(candidate);
		},
		&error);
	const auto reopened = MigrationController::OpenProfileWorkspace(dataDirectory);
	const auto reopenedSecond = reopened ? reopened->LoadCommitted() : std::nullopt;
	check("replace-publishes-both-artifacts-as-one-generation",
		second && error == MigrationError::None
		&& second->transactionId != initial->transactionId
		&& reopenedSecond && reopenedSecond->transactionId == second->transactionId
		&& Matches(*reopenedSecond, replacement)
		&& reopened->accountStorageRoot() == accountRoot);
	if (!second || !reopened) {
		return 1;
	}

	auto staleCallbackCalled = false;
	check("stale-cas-rejects-commit-and-retirement",
		!reopened->ReplaceCommitted(
			initial->transactionId,
			inputs,
			[&](const auto &) {
				staleCallbackCalled = true;
				return true;
			},
			&error)
		&& error == MigrationError::StaleGeneration
		&& !staleCallbackCalled
		&& !reopened->RetireInactiveGenerations(initial->transactionId, &error)
		&& error == MigrationError::StaleGeneration
		&& std::filesystem::exists(root / "stage" / "profile-vault.bin"));

	const auto third = reopened->ReplaceCommitted(
		second->transactionId,
		inputs,
		[&](const auto &candidate) { return Matches(candidate, inputs); },
		&error);
	check("replace-supports-a-current-version-two-generation",
		third && error == MigrationError::None
		&& third->transactionId != second->transactionId
		&& Matches(*third, inputs));
	if (!third) {
		return 1;
	}

	const auto selectedVault = GenerationDirectory(root, third->transactionId)
		/ "profile-vault.bin";
	check("damaged-active-artifact-cannot-fall-back-to-a-retired-pair",
		WriteFixture(selectedVault, "tampered-active-vault")
		&& reopened->Recover(&error) == MigrationState::Invalid
		&& error == MigrationError::ReadbackFailed
		&& !reopened->LoadCommitted());
	if (!WriteFixture(selectedVault, inputs[0].encryptedBytes.toStdString())) {
		return 1;
	}
	const auto unknown = root / "stage" / "unmanaged-file";
	check("retirement-refuses-to-remove-unmanaged-storage",
		WriteFixture(unknown, "unmanaged")
		&& !reopened->RetireInactiveGenerations(third->transactionId, &error)
		&& error == MigrationError::RetirementFailed
		&& ReadFixture(unknown) == "unmanaged"
		&& isActive(third->transactionId));
	if (!std::filesystem::remove(unknown)) {
		return 1;
	}
	check("retirement-removes-abandoned-and-previous-artifact-generations",
		reopened->RetireInactiveGenerations(third->transactionId, &error)
		&& error == MigrationError::None
		&& std::distance(
			std::filesystem::directory_iterator(root / "generations"),
			std::filesystem::directory_iterator()) == 1
		&& !std::filesystem::exists(root / "migration.manifest.pending")
		&& !std::filesystem::exists(root / "stage")
		&& std::filesystem::exists(selectedVault)
		&& ReadFixture(accountWitness) == "account-data");
	check("retirement-is-idempotent",
		reopened->RetireInactiveGenerations(third->transactionId, &error)
		&& error == MigrationError::None);
	check("corrupt-committed-profile-cannot-look-like-legacy",
		WriteFixture(
			std::filesystem::path(live->workspacePath().toStdString())
				/ "migration.manifest.committed",
			"damaged")
		&& MigrationController::ProbeProfileWorkspace(dataDirectory)
			== MigrationState::Invalid);
	check("missing-active-manifest-cannot-reactivate-legacy",
		std::filesystem::remove(root / "migration.manifest.committed")
		&& MigrationController::ProbeProfileWorkspace(dataDirectory, &error)
			== MigrationState::Invalid
		&& error == MigrationError::InvalidManifest
		&& !reopened->Stage(inputs, &error)
		&& error == MigrationError::InvalidManifest);

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	const auto arguments = app.arguments();
	if (arguments.size() == 4 && arguments[1] == u"--end-during-replace") {
		return EndDuringReplace(
			arguments[2],
			QByteArray::fromHex(arguments[3].toLatin1()));
	}
	return RunChecks();
}
