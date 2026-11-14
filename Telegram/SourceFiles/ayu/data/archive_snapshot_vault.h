// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/data/ayu_database.h"
#include "ayu/features/profile_sets/account_keyring.h"

#include <QtCore/QByteArray>

#include <optional>

namespace Ayu::ArchiveSnapshotVault {

enum class Error : uchar {
	None,
	InvalidAccountKey,
	InvalidArchiveAccount,
	OutsideAccountScope,
	TooLarge,
	RandomFailure,
	Malformed,
	WrongAccount,
	AuthenticationFailed,
};

// Produces an encrypted, account-key-bound staging artifact. This function
// never reads or writes AyuDatabase; callers provide the scoped snapshot.
[[nodiscard]] QByteArray Seal(
	const ProfileSets::AccountKey &accountKey,
	ID archiveAccountId,
	const AyuDatabase::ArchiveBackupSnapshot &snapshot,
	Error *error = nullptr);

// Authenticates the account binding before returning staged rows. Every row
// is restored with expectedArchiveAccountId as its owner.
[[nodiscard]] std::optional<AyuDatabase::ArchiveBackupSnapshot> Open(
	const ProfileSets::AccountKey &accountKey,
	ID expectedArchiveAccountId,
	const QByteArray &artifact,
	Error *error = nullptr);

} // namespace Ayu::ArchiveSnapshotVault
