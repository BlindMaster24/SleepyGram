/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#if defined _DEBUG || defined TDESKTOP_RELEASE_TEST_HARNESS

#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_migration.h"
#include "core/version.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/details/storage_settings_scheme.h"
#include "test/test_log.h"
#include "test/test_runner.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

namespace Test {
namespace {

using namespace Storage;
using namespace Storage::details;
using namespace Ayu::ProfileSets;

constexpr auto kFixtureVersion = AppVersion - 1;
constexpr auto kFixtureUser = UserId(1ULL << 40);
constexpr auto kFixturePrefs = FileKey(0x1234);

MTP::AuthKeyPtr LocalKey(gsl::byte seed) {
	auto key = MTP::AuthKey::Data();
	key.fill(seed);
	return std::make_shared<MTP::AuthKey>(key);
}

bool WriteFixture(const AccountPaths &paths, const MTP::AuthKeyPtr &key) {
	const auto split = paths.authPath.lastIndexOf('/') + 1;
	auto rawAuth = QByteArray();
	{
		auto stream = QDataStream(&rawAuth, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << quint64(-1) << quint64(kFixtureUser.bare) << qint32(2);
		stream << qint32(1) << qint32(2);
		LocalKey(gsl::byte(42))->write(stream);
		stream << qint32(0);
	}
	auto auth = EncryptedDescriptor(rawAuth.size() + 8);
	auth.stream << quint32(dbiMtpAuthorization) << rawAuth;
	auto authFile = FileWriteDescriptor(
		paths.authPath.mid(split),
		paths.authPath.left(split));
	authFile.writeEncrypted(auth, key);

	auto self = QByteArray();
	{
		auto stream = QDataStream(&self, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << SerializePeerId(peerFromUser(kFixtureUser));
	}
	auto map = EncryptedDescriptor(self.size() + 20);
	map.stream << quint32(0x15) << self;
	map.stream << quint32(0x1e) << quint64(kFixturePrefs);
	auto mapFile = FileWriteDescriptor(u"map"_q, paths.basePath);
	mapFile.writeData(QByteArray());
	mapFile.writeData(QByteArray());
	mapFile.writeEncrypted(map, key);

	auto prefs = EncryptedDescriptor(4);
	prefs.stream << quint32(0);
	auto prefsFile = FileWriteDescriptor(kFixturePrefs, paths.basePath);
	prefsFile.writeEncrypted(prefs, key);

	const auto authWritten = authFile.finishStaged(kFixtureVersion);
	const auto mapWritten = mapFile.finishStaged(kFixtureVersion);
	const auto prefsWritten = prefsFile.finishStaged(kFixtureVersion);
	const auto mapPath = paths.basePath + u"map"_q;
	return authWritten && mapWritten && prefsWritten
		&& QFile::rename(mapPath + 's', mapPath + '0')
		&& QFile::copy(mapPath + '0', mapPath + '1');
}

QByteArray ReadBytes(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

void RunStorageAccountMigration() {
	auto sandbox = QTemporaryDir();
	const auto root = QDir(sandbox.path()).canonicalPath();
	const auto origin = AccountPathsForDataName(root + u"/legacy"_q, u"test"_q);
	const auto legacyReady = sandbox.isValid()
		&& !root.isEmpty()
		&& QDir().mkpath(origin.basePath);
	const auto workspace = legacyReady
		? MigrationController::CreateProfileWorkspace(root + u"/legacy"_q)
		: std::nullopt;
	const auto account = AccountKey{ { 1, 2 }, QByteArray(kAccountKeySize, 'k') };
	const auto locator = AccountVaultLocator{
		account.id,
		QByteArray(kAccountVaultLocatorSize, 'a'),
	};
	const auto target = workspace
		? ScopedAccountPaths(
			workspace->accountStorageRoot(), AccountVaultDataName(locator))
		: std::nullopt;
	const auto setup = target.has_value();
	Check(setup, u"Migration fixture uses temporary storage"_q);
	if (!setup) {
		return;
	}
	const auto oldKey = LocalKey(gsl::byte(2));
	const auto newKey = ProfileAccountStorageKey(account);
	const auto fixture = WriteFixture(origin, oldKey);
	Check(fixture, u"Legacy fixture includes alternate map backups"_q);
	if (!fixture) {
		return;
	}
	const auto map0 = origin.basePath + u"map0"_q;
	const auto map1 = origin.basePath + u"map1"_q;
	const auto backup0 = ReadBytes(map0);
	const auto backup1 = ReadBytes(map1);
	const auto auth = ReadBytes(origin.authPath + 's');
	const auto stage = [&](UserId user) {
		return StageProfileAccount(
			*workspace, origin, oldKey, user, account, locator);
	};
	Check(
		newKey && StageProfileAccount(
			*workspace,
			origin,
			oldKey,
			kFixtureUser,
			account,
			{ { 1, 3 }, locator.value }) == AccountMigrationResult::InvalidPaths,
		u"Account root key must match the authenticated locator"_q);
	const auto rejected = stage(UserId(kFixtureUser.bare + 1));
	Check(
		rejected == AccountMigrationResult::IdentityMismatch
			&& !QFileInfo::exists(target->authPath + 's'),
		u"Wrong account fails before scoped files are published"_q);

	const auto cachePath = origin.databasePath + u"cache"_q;
	const auto cache = QDir().mkpath(cachePath);
	Check(
		cache
			&& stage(kFixtureUser) == AccountMigrationResult::UnsupportedData
			&& !QFileInfo::exists(target->authPath + 's'),
		u"Unmigrated cache blocks the stage"_q);
	if (!cache || !QDir().rmdir(cachePath)) {
		return;
	}
	const auto staged = stage(kFixtureUser);
	Check(staged == AccountMigrationResult::Success,
		u"Authorization and map are staged and verified"_q);
	if (staged != AccountMigrationResult::Success) {
		return;
	}
	Check(
		!auth.isEmpty() && !backup0.isEmpty() && !backup1.isEmpty()
			&& backup0 == ReadBytes(map0)
			&& backup1 == ReadBytes(map1)
			&& auth == ReadBytes(origin.authPath + 's'),
		u"Legacy authorization and backups retain the same bytes"_q);
	Check(
		stage(kFixtureUser) == AccountMigrationResult::Success,
		u"Staging the same account again verifies the existing result"_q);

	auto prefs = FileReadDescriptor();
	const auto readPrefs = ReadEncryptedFile(
		prefs,
		kFixturePrefs,
		target->basePath,
		newKey,
		LegacyBackupPolicy::Preserve);
	auto count = quint32(1);
	prefs.stream >> count;
	Check(
		readPrefs && count == 0 && prefs.version == kFixtureVersion,
		u"Map data is rewrapped with its original writer version"_q);
	auto oldRead = FileReadDescriptor();
	Check(
		!ReadEncryptedFile(
			oldRead,
			kFixturePrefs,
			target->basePath,
			oldKey,
			LegacyBackupPolicy::Preserve),
		u"The shared legacy key cannot open the scoped record"_q);

	const auto corrupted = QFile::remove(target->authPath + 's');
	Check(
		corrupted && VerifyStagedAccount(
			origin,
			oldKey,
			*target,
			newKey,
			kFixtureUser) == AccountMigrationResult::VerificationFailed,
		u"Verify rejects a staged account with missing authorization"_q);
}

[[maybe_unused]] const auto kRegistered = [] {
	RegisterScenarioProvider([](not_null<Runner*> runner) {
		if (!qEnvironmentVariableIsSet("TDESKTOP_TEST_ACCOUNT_STORAGE_MIGRATION")) {
			return false;
		}
		runner->add({
			.name = u"Account storage migration"_q,
			.then = RunStorageAccountMigration,
		});
		return true;
	});
	return true;
}();

} // namespace
} // namespace Test

#endif
