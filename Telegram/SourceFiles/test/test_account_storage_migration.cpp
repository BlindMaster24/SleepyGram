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
#include "mtproto/mtproto_config.h"
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
constexpr auto kFixtureSettings = FileKey(0x2345);

MTP::AuthKeyPtr LocalKey(gsl::byte seed) {
	auto key = MTP::AuthKey::Data();
	key.fill(seed);
	return std::make_shared<MTP::AuthKey>(key);
}

bool WriteFixtureAuth(
		const AccountPaths &paths,
		const MTP::AuthKeyPtr &key,
		UserId user,
		int32 version) {
	const auto split = paths.authPath.lastIndexOf('/') + 1;
	auto rawAuth = QByteArray();
	{
		auto stream = QDataStream(&rawAuth, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << quint64(-1) << quint64(user.bare) << qint32(2);
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
	return authFile.finishStaged(version);
}

bool WriteFixtureMap(
		const AccountPaths &paths,
		const MTP::AuthKeyPtr &key,
		bool active,
		const QByteArray &oldBrowserToken = {}) {
	auto self = QByteArray();
	{
		auto stream = QDataStream(&self, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << SerializePeerId(peerFromUser(kFixtureUser));
	}
	auto map = EncryptedDescriptor(self.size() + 128);
	map.stream << quint32(0x15) << self;
	map.stream << quint32(0x1e) << quint64(kFixturePrefs);
	if (active) {
		map.stream << quint32(0x09) << quint64(kFixtureSettings);
		map.stream << quint32(0x19) << QByteArray("scoped-fixture-token")
			<< QByteArray();
	} else if (!oldBrowserToken.isEmpty()) {
		map.stream << quint32(0x19) << oldBrowserToken << QByteArray(16, 'b');
	}
	auto mapFile = FileWriteDescriptor(u"map"_q, paths.basePath);
	mapFile.writeData(QByteArray());
	mapFile.writeData(QByteArray());
	mapFile.writeEncrypted(map, key);
	return mapFile.finishStaged(active ? AppVersion : kFixtureVersion);
}

bool MakeMapBackups(const AccountPaths &paths) {
	const auto stem = paths.basePath + u"map"_q;
	return QFile::rename(stem + 's', stem + '0')
		&& QFile::copy(stem + '0', stem + '1');
}

bool WriteFixture(
		const AccountPaths &paths,
		const MTP::AuthKeyPtr &key,
		const QByteArray &oldBrowserToken = {}) {
	auto prefs = EncryptedDescriptor(4);
	prefs.stream << quint32(0);
	auto prefsFile = FileWriteDescriptor(kFixturePrefs, paths.basePath);
	prefsFile.writeEncrypted(prefs, key);

	const auto prefsWritten = prefsFile.finishStaged(kFixtureVersion);
	return prefsWritten
		&& WriteFixtureAuth(paths, key, kFixtureUser, kFixtureVersion)
		&& WriteFixtureMap(paths, key, false, oldBrowserToken)
		&& MakeMapBackups(paths);
}

QByteArray ReadBytes(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

bool WriteConfigFixture(
		const AccountPaths &paths,
		const MTP::AuthKeyPtr &key,
		const QByteArray &serialized) {
	auto config = EncryptedDescriptor(serialized.size() + 4);
	config.stream << serialized;
	auto file = FileWriteDescriptor(u"config"_q, paths.basePath);
	file.writeEncrypted(config, key);
	return file.finishStaged(AppVersion);
}

void CheckScopedStartup(
		const AccountPaths &paths,
		const MTP::AuthKeyPtr &oldKey,
		const MTP::AuthKeyPtr &newKey) {
	const auto validate = [&] {
		return ValidateScopedAccountForStartup(paths, newKey);
	};
	const auto initial = validate();
	Check(
		initial && initial->userId == kFixtureUser
			&& initial->environment == MTP::Environment::Production,
		u"Read-only startup validates a staged account with no config"_q);
	Check(
		!ReadScopedAccountConnection(paths, newKey),
		u"Technical connection requires a persisted Telegram environment"_q);
	Check(
		!ValidateScopedAccountForStartup(paths, oldKey),
		u"Scoped startup rejects the old shared key"_q);

	const auto current = WriteFixtureMap(paths, newKey, true)
		&& MakeMapBackups(paths)
		&& QDir().mkpath(paths.databasePath + u"cache"_q)
		&& QFile::remove(paths.basePath + ToFilePart(kFixturePrefs) + 's')
		&& WriteConfigFixture(
			paths,
			newKey,
			MTP::Config(MTP::Environment::Test).serialize());
	Check(current, u"Scoped startup fixture has current local files"_q);
	if (!current) {
		return;
	}
	const auto map0 = paths.basePath + u"map0"_q;
	const auto map1 = paths.basePath + u"map1"_q;
	const auto backup0 = ReadBytes(map0);
	const auto backup1 = ReadBytes(map1);
	const auto modern = validate();
	Check(
		modern && modern->userId == kFixtureUser
			&& modern->environment == MTP::Environment::Test
			&& !backup0.isEmpty() && !backup1.isEmpty()
			&& backup0 == ReadBytes(map0) && backup1 == ReadBytes(map1),
		u"Scoped startup preserves backups and reads the persisted environment"_q);
	const auto connection = ReadScopedAccountConnection(paths, newKey);
	Check(
		connection && connection->mainDcId == 2
			&& connection->mainKey
			&& connection->mainKey->equals(LocalKey(gsl::byte(42)))
			&& connection->config->environment() == MTP::Environment::Test
			&& backup0 == ReadBytes(map0) && backup1 == ReadBytes(map1),
		u"Technical connection reads only the authenticated main DC without writes"_q);
	Check(
		WriteFixtureAuth(paths, newKey, UserId(kFixtureUser.bare + 1), AppVersion)
			&& !validate()
			&& !ReadScopedAccountConnection(paths, newKey),
		u"Scoped startup rejects an authenticated but conflicting identity"_q);
	Check(
		WriteFixtureAuth(paths, newKey, UserId(), AppVersion) && !validate(),
		u"Scoped startup rejects a zero user ID"_q);
	Check(
		WriteFixtureAuth(paths, newKey, kFixtureUser, AppVersion)
			&& WriteConfigFixture(paths, newKey, QByteArray("invalid"))
			&& !validate(),
		u"Scoped startup rejects a present malformed config"_q);
}

void CheckFreshWebviewMigration() {
	auto sandbox = QTemporaryDir();
	const auto root = QDir(sandbox.path()).canonicalPath();
	const auto legacyRoot = root + u"/legacy"_q;
	const auto origin = AccountPathsForDataName(legacyRoot, u"test"_q);
	const auto oldKey = LocalKey(gsl::byte(2));
	const auto newKey = LocalKey(gsl::byte(3));
	const auto browser = origin.databasePath + u"wvbots"_q;
	const auto target = (!root.isEmpty()
		&& QDir().mkpath(origin.basePath)
		&& QDir().mkpath(browser)
		&& QDir().mkpath(legacyRoot + u"/webview-tonsite"_q)
		&& QDir().mkpath(root + u"/scoped"_q)
		&& WriteFixture(origin, oldKey, QByteArray("<legacy>")))
		? ScopedAccountPaths(root + u"/scoped"_q, u"31b8c8c73bea090704338f38d5c46894"_q)
		: std::nullopt;
	Check(target.has_value(), u"Legacy WebView migration fixture is ready"_q);
	if (!target) {
		return;
	}
	const auto oldMap = origin.basePath + u"map0"_q;
	const auto oldBytes = ReadBytes(oldMap);
	const auto auth = target->authPath + 's';
	Check(StageLegacyAccount(origin, oldKey, *target, newKey, kFixtureUser)
		== AccountMigrationResult::UnsupportedData && !QFileInfo::exists(auth),
		u"An existing browser store requires migration consent"_q);
	const auto stage = [&] {
		return StageLegacyAccount(origin, oldKey, *target, newKey, kFixtureUser,
			nullptr, LegacyWebviewTransfer::StartFresh);
	};
	const auto staged = stage() == AccountMigrationResult::Success;
	Check(staged && stage() == AccountMigrationResult::Success
		&& ValidateScopedAccountForStartup(*target, newKey)
		&& !oldBytes.isEmpty() && ReadBytes(oldMap) == oldBytes
		&& QFileInfo::exists(browser),
		u"Opt-in is repeatable and preserves the legacy browser and encrypted map"_q);
	if (!staged) {
		return;
	}
	auto read = FileReadDescriptor();
	auto decoded = EncryptedDescriptor();
	const auto readable = ReadFile(
		read, u"map"_q, target->basePath, LegacyBackupPolicy::Preserve);
	auto salt = QByteArray();
	auto wrapped = QByteArray();
	auto encrypted = QByteArray();
	read.stream >> salt >> wrapped >> encrypted;
	const auto decrypted = readable && DecryptLocal(decoded, encrypted, newKey);
	Check(decrypted, u"Fresh browser identifiers are in the staged map"_q);
	if (!decrypted) {
		return;
	}
	auto stream = QDataStream(decoded.data);
	stream.setVersion(QDataStream::Qt_5_1);
	auto self = quint32();
	auto selfData = QByteArray();
	auto preferences = quint32();
	auto prefsKey = quint64();
	auto webview = quint32();
	auto bots = QByteArray();
	auto other = QByteArray();
	stream.skipRawData(sizeof(quint32));
	stream >> self >> selfData >> preferences >> prefsKey >> webview >> bots >> other;
	Check(stream.status() == QDataStream::Ok && stream.atEnd()
		&& self == 0x15 && !selfData.isEmpty()
		&& preferences == 0x1e && prefsKey == kFixturePrefs
		&& webview == 0x19 && bots.size() == 16 && other.size() == 16
		&& bots != other && other != QByteArray(16, 'b'),
		u"Both browser stores get distinct identifiers and earlier map records survive"_q);
}

void RunStorageAccountMigration() {
	CheckFreshWebviewMigration();
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
	const auto restored = WriteFixtureAuth(
		*target, newKey, kFixtureUser, kFixtureVersion);
	Check(restored, u"Scoped fixture restored for startup checks"_q);
	Check(
		!ValidateScopedAccountForStartup(origin, oldKey),
		u"Scoped startup does not read from the legacy account root"_q);
	if (restored) {
		CheckScopedStartup(*target, oldKey, newKey);
	}
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
