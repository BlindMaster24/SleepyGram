/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QtGlobal>

#include <functional>
#include <optional>
#include <vector>

namespace Ayu::ProfileSets {

enum class MigrationArtifact : quint32 {
	ProfileVault = 1,
	AccountKeyring = 2,
};

struct MigrationInput final {
	MigrationArtifact artifact = MigrationArtifact::ProfileVault;
	QByteArray encryptedBytes;
};

struct CommittedMigration final {
	QByteArray transactionId;
	QByteArray profileVault;
	QByteArray accountKeyring;
};

enum class MigrationState : uchar {
	Empty,
	Incomplete,
	Staged,
	Committed,
	Invalid,
};

enum class ProfileStartupMode : uchar {
	Legacy,
	Preparing,
	Committed,
	RecoveryRequired,
};

enum class MigrationError : uchar {
	None,
	UnsafeWorkspace,
	WorkspaceIo,
	InvalidInput,
	AlreadyStaged,
	NotStaged,
	InvalidManifest,
	UnsupportedVersion,
	ReadbackFailed,
	TooLarge,
	WorkspaceBusy,
	VerificationRequired,
	VerificationFailed,
	StaleGeneration,
	PublicationUncertain, // Reopen the committed generation before retrying.
	RetirementFailed,
	CallbackFailed,
};

class MigrationController final {
public:
	using Verifier = std::function<bool(const CommittedMigration&)>;

	[[nodiscard]] static std::optional<MigrationController>
	CreateProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error = nullptr);
	[[nodiscard]] static std::optional<MigrationController> OpenProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error = nullptr);
	[[nodiscard]] static MigrationState ProbeProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error = nullptr);
	// Preparing reserves the profile for the migration workflow.
	[[nodiscard]] static ProfileStartupMode ProbeProfileStartup(
		const QString &dataDirectory,
		MigrationError *error = nullptr);

	[[nodiscard]] static std::optional<MigrationController>
	CreateIsolatedFixtureWorkspace(
		QString path,
		MigrationError *error = nullptr);
	[[nodiscard]] static std::optional<MigrationController>
	OpenIsolatedFixtureWorkspace(
		QString path,
		MigrationError *error = nullptr);

	[[nodiscard]] bool Stage(
		const std::vector<MigrationInput> &inputs,
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> Commit(
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> CommitVerified(
		const Verifier &verify,
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> ReplaceCommitted(
		const QByteArray &expectedTransactionId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error = nullptr) const;
	// Retire only after readers of the previous generation have stopped.
	[[nodiscard]] bool RetireInactiveGenerations(
		const QByteArray &expectedTransactionId,
		MigrationError *error = nullptr) const;
	[[nodiscard]] MigrationState Recover(
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> LoadCommitted(
		MigrationError *error = nullptr) const;
	// The synchronous lease callback must not acquire the workspace lock.
	[[nodiscard]] bool WithCurrentGeneration(
		const QByteArray &expectedTransactionId,
		const std::function<bool()> &callback,
		MigrationError *error = nullptr) const;

	[[nodiscard]] QString workspacePath() const;
	[[nodiscard]] QString accountStorageRoot() const;
	[[nodiscard]] bool isIsolatedFixture() const;

private:
	explicit MigrationController(QString root, QString profileDataDirectory = {});
	[[nodiscard]] bool validateWorkspace() const;
	[[nodiscard]] std::optional<CommittedMigration> readManifest(
		const char *name,
		MigrationError *error) const;
	[[nodiscard]] std::optional<CommittedMigration> commit(
		const Verifier &verify,
		MigrationError *error) const;

	QString _root;
	QString _profileDataDirectory;

};

} // namespace Ayu::ProfileSets
