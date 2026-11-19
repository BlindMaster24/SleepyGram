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

struct SetId;

enum class MigrationArtifact : quint32 {
	ProfileVault = 1,
	AccountKeyring = 2,
	LegacyRetirement = 3,
	EmergencyRules = 4,
	EmergencyRecovery = 5,
	AccountGateTable = 6,
	RevocableEmergencyRules = 7,
	RevocableEmergencyRecovery = 8,
};

struct MigrationInput final {
	MigrationArtifact artifact = MigrationArtifact::ProfileVault;
	QByteArray encryptedBytes;
};

enum class MigrationGenerationLayout : uchar {
	LegacyKeys,
	RevocableGates,
};

struct MigrationGenerationProof final {
	QByteArray transactionId;
	QByteArray manifestDigest;

	friend bool operator==(
		const MigrationGenerationProof&,
		const MigrationGenerationProof&) = default;
};

struct CommittedMigration final {
	QByteArray transactionId;
	QByteArray profileVault;
	QByteArray accountKeyring;
	QByteArray legacyRetirement;
	QByteArray emergencyRules;
	QByteArray emergencyRecovery;
	MigrationGenerationLayout layout = MigrationGenerationLayout::LegacyKeys;
	QByteArray installationId;
	QByteArray accountGateTable;
	QByteArray revocableEmergencyRules;
	QByteArray revocableEmergencyRecovery;
	QByteArray manifestDigest;
	bool retirementPending = false;

	[[nodiscard]] MigrationGenerationProof proof() const {
		return { transactionId, manifestDigest };
	}
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
	RevocableRetirementRequired,
	RevocableRecoveryRequired,
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
		MigrationError *error = nullptr,
		QByteArray transactionId = {}) const;
	[[nodiscard]] std::optional<CommittedMigration> Commit(
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> CommitVerified(
		const Verifier &verify,
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> ReplaceCommitted(
		const QByteArray &expectedTransactionId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error = nullptr,
		QByteArray transactionId = {}) const;
	[[nodiscard]] std::optional<CommittedMigration> ReplaceRevocableCommitted(
		const MigrationGenerationProof &expected,
		const QByteArray &installationId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error = nullptr,
		QByteArray transactionId = {}) const;
	// Retire only after readers of the previous generation have stopped.
	[[nodiscard]] bool RetireInactiveGenerations(
		const QByteArray &expectedTransactionId,
		MigrationError *error = nullptr) const;
	[[nodiscard]] bool RetireRevocableGenerations(
		const MigrationGenerationProof &expected,
		MigrationError *error = nullptr) const;
	[[nodiscard]] MigrationState Recover(
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> LoadCommitted(
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> LoadStaged(
		MigrationError *error = nullptr) const;
	[[nodiscard]] bool StoreSetupDraft(const CommittedMigration &draft) const;
	[[nodiscard]] std::optional<CommittedMigration> LoadSetupDraft() const;
	[[nodiscard]] static QByteArray NewTransactionId();
	// The synchronous lease callback must not acquire the workspace lock.
	[[nodiscard]] bool WithCurrentGeneration(
		const QByteArray &expectedTransactionId,
		const std::function<bool()> &callback,
		MigrationError *error = nullptr) const;
	[[nodiscard]] bool WithCurrentRevocableGeneration(
		const MigrationGenerationProof &expected,
		const Verifier &callback,
		MigrationError *error = nullptr) const;
	[[nodiscard]] bool WithCurrentRevocableRecovery(
		const MigrationGenerationProof &expected,
		const Verifier &callback,
		MigrationError *error = nullptr) const;
	[[nodiscard]] bool WithPreparingWorkspace(
		const std::function<bool()> &callback,
		MigrationError *error = nullptr) const;
	[[nodiscard]] bool WithStagedSetup(
		const QByteArray &expectedTransactionId,
		const std::function<bool()> &callback,
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<QString> PrepareScopedSettingsDirectory(
		const QByteArray &expectedTransactionId,
		SetId setId,
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<QString> PrepareRevocableScopedSettingsDirectory(
		const MigrationGenerationProof &expected,
		SetId setId,
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<QString> PrepareInitialSettingsDirectory(
		const QByteArray &expectedTransactionId,
		SetId setId) const;

	[[nodiscard]] QString workspacePath() const;
	[[nodiscard]] QString accountStorageRoot() const;
	[[nodiscard]] bool SyncScopedAccount(QStringView locator) const;
	[[nodiscard]] QString emergencyJournalDirectory() const;
	[[nodiscard]] bool isIsolatedFixture() const;

private:
	enum class LeaseKind : uchar {
		Legacy,
		Revocable,
		RevocableRecovery,
	};

	explicit MigrationController(QString root, QString profileDataDirectory = {});
	[[nodiscard]] bool validateWorkspace() const;
	[[nodiscard]] std::optional<QString> ensureScopedSettingsDirectory(SetId setId) const;
	[[nodiscard]] std::optional<CommittedMigration> readManifest(
		const char *name,
		MigrationError *error) const;
	[[nodiscard]] std::optional<CommittedMigration> commit(
		const Verifier &verify,
		MigrationError *error) const;
	[[nodiscard]] std::optional<CommittedMigration> replaceCommitted(
		const MigrationGenerationProof &expected,
		const QByteArray &installationId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error,
		QByteArray transactionId) const;
	[[nodiscard]] bool retireInactiveGenerations(
		const MigrationGenerationProof &expected,
		bool revocable,
		MigrationError *error) const;
	[[nodiscard]] bool withCurrentGeneration(
		const MigrationGenerationProof &expected,
		LeaseKind kind,
		const Verifier &callback,
		MigrationError *error) const;

	QString _root;
	QString _profileDataDirectory;

};

} // namespace Ayu::ProfileSets
