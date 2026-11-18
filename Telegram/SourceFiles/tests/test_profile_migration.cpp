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
#include <QtCore/QTemporaryDir>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <cstdio>

namespace {

using namespace Ayu::ProfileSets;

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
	const auto profile = QTemporaryDir();
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
	check("verified-profile-commit-is-visible-to-startup",
		live->CommitVerified([&](const CommittedMigration &files) {
			return files.profileVault == inputs[0].encryptedBytes
				&& files.accountKeyring == inputs[1].encryptedBytes;
		}, &error).has_value()
		&& MigrationController::ProbeProfileWorkspace(dataDirectory)
			== MigrationState::Committed);
	check("corrupt-committed-profile-cannot-look-like-legacy",
		WriteFixture(
			std::filesystem::path(live->workspacePath().toStdString())
				/ "migration.manifest.committed",
			"damaged")
		&& MigrationController::ProbeProfileWorkspace(dataDirectory)
			== MigrationState::Invalid);

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	return RunChecks();
}
