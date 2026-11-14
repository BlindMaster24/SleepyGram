/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/account_storage_plan.h"

#include "base/qt/qt_string.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>
#include <vector>

namespace {

using namespace Ayu::ProfileSets;

QByteArray Verifier(quint32 value) {
	auto result = QByteArray(kVerifierSize, '\0');
	for (auto i = 0; i != 4; ++i) {
		result[i] = char(value >> (8 * i));
	}
	return result;
}

DerivedCredential Credential(quint32 value) {
	return {
		.verifier = Verifier(value),
		.key = QByteArray(kProfileVaultKeySize, char((value % 255) + 1)),
	};
}

QString LegacyFilePart(quint64 value) {
	auto result = QString();
	for (auto i = 0; i != 16; ++i) {
		const auto nibble = uchar(value & 0x0F);
		result.push_back((nibble < 10)
			? QChar('0' + nibble)
			: QChar('A' + (nibble - 10)));
		value >>= 4;
	}
	return result;
}

std::optional<ProfileVault> FixtureVault() {
	const auto metadata = Metadata{
		.verifierSalt = QByteArray(kVerifierSaltSize, 's'),
		.verifierKdf = {
			.kind = 2,
			.memory = 16'384,
			.time = 1,
			.parallel = 1,
		},
		.masterVerifier = Verifier(0xFFFFFFFF),
		.sets = {
			{
				.id = { 1, 1 },
				.name = u"Granted"_q,
				.verifier = Verifier(1),
				.accounts = { { 4, 1 } },
			},
			{
				.id = { 1, 2 },
				.name = u"Empty"_q,
				.verifier = Verifier(2),
			},
		},
	};
	const auto accounts = std::vector<AccountKey>{
		{ .id = { 4, 1 }, .key = QByteArray(kAccountKeySize, 'K') },
	};
	return SealProfileVault(
		metadata,
		accounts,
		Credential(0xFFFFFFFF),
		{
			{ .id = { 1, 1 }, .credential = Credential(1) },
			{ .id = { 1, 2 }, .credential = Credential(2) },
		});
}

bool WriteFixture(const QString &path) {
	if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
		return false;
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly)
		|| file.write("fixture", 7) != 7) {
		return false;
	}
	file.close();
	return true;
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

	auto temporary = QTemporaryDir();
	if (!temporary.isValid()) {
		std::printf("FAIL temporary-fixture-created\n");
		return 1;
	}
	check("temporary-fixture-created", true);

	const auto globalPath = temporary.path() + u"/portable-a/tdata"_q;
	const auto otherGlobalPath = temporary.path() + u"/portable-b/tdata"_q;
	const auto legacyA = Storage::AccountPathsForDataName(
		globalPath,
		u"legacy-name#3"_q);
	const auto legacyB = Storage::AccountPathsForDataName(
		otherGlobalPath,
		u"legacy-name#3"_q);
	const auto legacyName = u"legacy-name#3"_q;
	const auto nameBytes = legacyName.toUtf8();
	const auto digest = QCryptographicHash::hash(
		nameBytes,
		QCryptographicHash::Md5);
	auto legacyKey = quint64(0);
	std::memcpy(&legacyKey, digest.constData(), sizeof(legacyKey));
	const auto pathPrefix = globalPath + '/';
	check("legacy-path-relative-shape-stable-across-portable-roots",
		legacyA.dataNameKey == legacyB.dataNameKey
		&& legacyA.dataNameKey == legacyKey
		&& legacyA.basePath == pathPrefix + LegacyFilePart(legacyKey) + '/'
		&& legacyA.tempPath == pathPrefix + "temp_" + legacyName + '/'
		&& legacyA.databasePath == pathPrefix + "user_" + legacyName + '/'
		&& legacyA.basePath.mid(globalPath.size())
			== legacyB.basePath.mid(otherGlobalPath.size())
		&& legacyA.tempPath.mid(globalPath.size())
			== legacyB.tempPath.mid(otherGlobalPath.size())
		&& legacyA.databasePath.mid(globalPath.size())
			== legacyB.databasePath.mid(otherGlobalPath.size())
		&& !QFileInfo::exists(globalPath));

	const auto vault = FixtureVault();
	check("vault-fixture-created", vault.has_value());
	if (!vault) {
		return 1;
	}
	const auto root = temporary.path() + u"/tdata"_q;
	const auto bindings = std::vector<AccountStorageBinding>{
		{ .id = { 4, 1 }, .dataName = u"profile_4_1"_q },
		{ .id = { 4, 2 }, .dataName = u"profile_4_2"_q },
	};
	auto error = AccountStoragePlanError::InvalidRoot;
	auto plan = BuildAccountStoragePlan(
		root,
		OpenProfileVault(*vault, Credential(1)),
		bindings,
		&error);
	check("verified-set-builds-only-granted-profile",
		plan && error == AccountStoragePlanError::None
		&& plan->targets().size() == 1
		&& plan->targetFor({ 4, 1 })
		&& plan->keyFor({ 4, 1 })
		&& plan->keyFor({ 4, 1 })->key == QByteArray(kAccountKeySize, 'K')
		&& !plan->targetFor({ 4, 2 })
		&& !plan->keyFor({ 4, 2 })
		&& !QFileInfo::exists(root));
	if (!plan || !plan->targetFor({ 4, 1 })) {
		return 1;
	}

	const auto allowedPath = plan->targetFor({ 4, 1 })->paths.basePath
		+ u"fixture.dat"_q;
	const auto ungrantedPath = Storage::AccountPathsForDataName(
		root,
		u"profile_4_2"_q).basePath + u"fixture.dat"_q;
	const auto wroteFixtures = WriteFixture(allowedPath)
		&& WriteFixture(ungrantedPath);
	const auto openForAccount = [&](AccountId id) {
		const auto target = plan->targetFor(id);
		if (!target) {
			return false;
		}
		auto file = QFile(target->paths.basePath + u"fixture.dat"_q);
		return file.open(QIODevice::ReadOnly);
	};
	check("only-granted-profile-fixture-opens",
		wroteFixtures
		&& openForAccount({ 4, 1 })
		&& !openForAccount({ 4, 2 }));

	auto emptyPlan = BuildAccountStoragePlan(
		root,
		OpenProfileVault(*vault, Credential(2)),
		bindings,
		&error);
	check("empty-set-produces-empty-plan",
		emptyPlan && error == AccountStoragePlanError::None
		&& emptyPlan->targets().empty()
		&& !emptyPlan->targetFor({ 4, 1 })
		&& !emptyPlan->targetFor({ 4, 2 }));

	auto missingBinding = BuildAccountStoragePlan(
		root,
		OpenProfileVault(*vault, Credential(1)),
		{},
		&error);
	check("missing-registry-binding-fails-closed",
		!missingBinding
		&& error == AccountStoragePlanError::MissingBinding);

	auto invalidBinding = BuildAccountStoragePlan(
		root,
		OpenProfileVault(*vault, Credential(1)),
		{{ .id = { 4, 1 }, .dataName = u"../outside"_q }},
		&error);
	check("unsafe-data-name-fails-closed",
		!invalidBinding
		&& error == AccountStoragePlanError::InvalidBindings);

	auto wrongPassword = BuildAccountStoragePlan(
		root,
		OpenProfileVault(*vault, Credential(9)),
		bindings,
		&error);
	check("unverified-access-cannot-produce-plan",
		!wrongPassword
		&& error == AccountStoragePlanError::WrongPassword);

	std::printf("%d/%d checks passed\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);
	return RunChecks();
}
