/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/functional.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QtGlobal>

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
};

class MigrationController final {
public:
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
	[[nodiscard]] MigrationState Recover(
		MigrationError *error = nullptr) const;
	[[nodiscard]] std::optional<CommittedMigration> LoadCommitted(
		MigrationError *error = nullptr) const;

	[[nodiscard]] QString workspacePath() const;

private:
	explicit MigrationController(QString root);
	QString _root;
};

} // namespace Ayu::ProfileSets
