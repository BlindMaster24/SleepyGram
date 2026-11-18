// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/legacy_retirement.h"

#include "base/basic_types.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <array>
#include <cstdio>
#include <filesystem>

namespace {

using namespace Ayu::ProfileSets;
using Result = LegacyRetirementResult;

constexpr auto kVerifiedFilename = "A01920BB01CA1022s";

int Failed = 0;

void Check(bool passed, const char *description) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", description);
	Failed += !passed;
}

bool Write(const QString &path, const QByteArray &contents) {
	auto file = QFile(path);
	return file.open(QIODevice::WriteOnly) && file.write(contents) == contents.size();
}

struct Fixture final {
	QTemporaryDir temporary;
	QString path = QDir(temporary.path()).canonicalPath();
	QString name = u"data"_q;
	QByteArray transaction = QByteArray(16, 'a');
	std::array<int, 2> slotIndices{ 0, 3 };
	std::array<VerifiedLegacyRetirementAccount, 2> accounts;

	bool setup() {
		if (!temporary.isValid() || path.isEmpty()
			|| !Write(path + u"/key_datas"_q, "profile key")
			|| !Write(path + u"/key_data1"_q, "profile key backup")
			|| !Write(path + u"/key_other_profiles"_q, "unrelated profile")
			|| !Write(path + u"/ayudata_98765.db"_q, "older archive backup")
			|| !Write(path + u"/wallet_keyring_datas"_q, "global wallet")
			|| !Write(path + u"/settingss"_q, "global settings")
			|| !QDir(path).mkdir(u"tdld"_q)
			|| !Write(path + u"/tdld/unexplained.download"_q, "shared temp file")) {
			return false;
		}
		for (auto i = 0; i != accounts.size(); ++i) {
			const auto dataName = Storage::AccountDataName(name, slotIndices[i]);
			auto &account = accounts[i];
			account.index = slotIndices[i];
			account.paths = Storage::AccountPathsForDataName(path, dataName);
			const auto &paths = account.paths;
			account.dataFiles = {
				u"maps"_q,
				u"map1"_q,
				u"config0"_q,
				QString::fromLatin1(kVerifiedFilename),
			};
			account.tgwFiles = { u"indexs"_q, u"A01920BB01CA10220"_q };
			if (!QDir().mkpath(paths.basePath + u"tgw"_q)
				|| !QDir().mkpath(paths.databasePath)
				|| !QDir().mkpath(paths.tempPath)
				|| !Write(paths.authPath + 's', "authorization")
				|| !Write(paths.authPath + '0', "authorization backup")) {
				return false;
			}
			for (const auto &file : account.dataFiles) {
				if (!Write(paths.basePath + file, "verified data")) {
					return false;
				}
			}
			for (const auto &file : account.tgwFiles) {
				if (!Write(paths.basePath + u"tgw/"_q + file, "owned archive body")) {
					return false;
				}
			}
		}
		return true;
	}

	std::optional<LegacyRetirementPlan> capture(
			LegacyArchiveRetirement archive = LegacyArchiveRetirement::ExpectedAbsent,
			const QByteArray &preferences = {}) const {
		return CaptureLegacyRetirementPlan(
			path, name, transaction, slotIndices, accounts, archive, preferences);
	}
};

void CheckCapture() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "capture fixture setup");
		return;
	}
	const auto captured = fixture.capture();
	Check(captured.has_value(), "all verified slots and exact flags captured");
	if (!captured) {
		return;
	}
	const auto encoded = SerializeLegacyRetirementPlan(*captured);
	const auto parsed = ParseLegacyRetirementPlan(encoded);
	Check(parsed.has_value()
		&& SerializeLegacyRetirementPlan(*parsed) == encoded, "plan codec round trip");
	Check(!ParseLegacyRetirementPlan(encoded + '\n'), "reject noncanonical encoding");
	auto unsafe = *captured;
	unsafe.entries.back().relativePath = u"../unrelated.file"_q;
	Check(SerializeLegacyRetirementPlan(unsafe).isEmpty(), "reject escaping manifest paths");
	Check(!CaptureLegacyRetirementPlan(
		fixture.path,
		fixture.name,
		fixture.transaction,
		fixture.slotIndices,
		std::span(fixture.accounts).first(1),
		LegacyArchiveRetirement::ExpectedAbsent), "reject omitted legacy slot");
	const auto &paths = fixture.accounts.front().paths;
	const auto unknown = paths.basePath + u"0123456789ABCDEFs"_q;
	Check(Write(unknown, "unverified extra") && !fixture.capture(),
		"capture rejects an unverified file even with a recognized basename");
	Check(QFile::remove(unknown), "remove synthetic unexpected file");
	const auto otherPath = fixture.path + u"/other-profile-file"_q;
	const auto alias = paths.basePath + fixture.accounts.front().dataFiles.front();
	auto error = std::error_code();
	const auto native = [](const QString &filePath) {
		return QFileInfo(filePath).filesystemFilePath();
	};
	const auto removed = QFile::remove(alias);
	if (removed && Write(otherPath, "original target")) {
		std::filesystem::create_hard_link(native(otherPath), native(alias), error);
	}
	Check(removed && QFileInfo::exists(otherPath) && !error && !fixture.capture(),
		"capture rejects a hard link in the verified list");
}

void CheckReplay() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "replay fixture setup");
		return;
	}
	const auto plan = fixture.capture();
	if (!plan) {
		Check(false, "replay capture");
		return;
	}
	const auto run = [&] {
		return RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan);
	};
	const auto key = fixture.path + u"/key_datas"_q;
	const auto backup = fixture.path + u"/key_data1"_q;
	const auto auth = fixture.accounts.front().paths.authPath + 's';
	Check(RetireLegacyProfileFiles(fixture.path, QByteArray(16, 'b'), *plan)
		== Result::InvalidPlan && QFileInfo::exists(key), "different cutover never mutates files");
	Check(RetireLegacyProfileFiles(fixture.path + u"/other"_q, fixture.transaction, *plan)
		== Result::InvalidPlan && QFileInfo::exists(key), "different root never mutates files");
	const auto folder = fixture.accounts.back().paths.basePath;
	const auto unexpected = folder + u".unverified"_q;
	Check(Write(unexpected, "outside inventory")
		&& run() == Result::UnexpectedSource
		&& QFileInfo::exists(key), "extra file in a later account blocks all deletion");
	Check(QFile::remove(unexpected), "remove synthetic extra file");
	const auto config = folder + u"config0"_q;
	Check(Write(config, "modified data")
		&& run() == Result::UnexpectedSource
		&& QFileInfo::exists(key), "changed file fingerprint blocks all deletion");
	Check(Write(config, "verified data"), "restore synthetic verified file");
	const auto alternate = fixture.path + u"/key_data0"_q;
	Check(Write(alternate, "unplanned backup")
		&& run() == Result::UnexpectedSource
		&& QFileInfo::exists(key), "added key_data backup blocks all deletion");
	Check(QFile::remove(alternate), "remove synthetic key backup");
	Check(QFile::remove(key) && QFile::remove(auth), "simulate death during retirement");
	Check(run() == Result::Complete
		&& !QFileInfo::exists(backup)
		&& !QFileInfo::exists(folder)
		&& run() == Result::Complete, "resume interrupted retirement and replay completed plan");
	Check(QFileInfo::exists(fixture.path + u"/key_other_profiles"_q)
		&& QFileInfo::exists(fixture.path + u"/ayudata_98765.db"_q)
		&& QFileInfo::exists(fixture.path + u"/wallet_keyring_datas"_q)
		&& QFileInfo::exists(fixture.path + u"/settingss"_q)
		&& QFileInfo::exists(fixture.path + u"/tdld/unexplained.download"_q),
		"unrelated profile, archive, wallet, settings and shared downloads survive");
}

void CheckLegacyArchive() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "archive fixture setup");
		return;
	}
	const auto archive = fixture.path + u"/ayudata.db"_q;
	const auto wal = archive + u"-wal"_q;
	const auto shm = archive + u"-shm"_q;
	const auto journal = archive + u"-journal"_q;
	const auto verified = LegacyArchiveRetirement::VerifiedPartitioned;
	const auto keyData = fixture.path + u"/key_datas"_q;
	Check(!fixture.capture(verified), "verified archive plan requires the source database");
	Check(Write(wal, "pending frames") && !fixture.capture(),
		"unexpected orphan archive sidecar blocks capture");
	Check(Write(archive, "legacy database") && Write(shm, "shared memory")
		&& !fixture.capture(), "present archive requires verified partitioning");
	Check(Write(journal, "active rollback journal") && !fixture.capture(verified)
		&& QFile::remove(journal), "rollback journal blocks even verified archive capture");
	const auto captured = fixture.capture(verified);
	const auto plan = captured
		? ParseLegacyRetirementPlan(SerializeLegacyRetirementPlan(*captured))
		: std::nullopt;
	if (!plan) {
		Check(false, "verified archive plan captured");
		return;
	}
	const auto run = [&] {
		return RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan);
	};
	Check(Write(journal, "unexpected new journal") && run() == Result::UnexpectedSource
		&& QFileInfo::exists(keyData) && QFile::remove(journal),
		"recovery detects a new rollback journal before mutations");
	Check(run() == Result::Complete
		&& !QFileInfo::exists(archive)
		&& !QFileInfo::exists(wal)
		&& !QFileInfo::exists(shm)
		&& QFileInfo::exists(fixture.path + u"/ayudata_98765.db"_q),
		"verified archive and sidecars retire while rotated backup survives");
}

void CheckLegacyCache() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "cache fixture setup");
		return;
	}
	auto &account = fixture.accounts.front();
	const auto root = account.paths.databasePath;
	const auto blob = u"cache/0/10/203040506070"_q;
	const auto binlog = u"cache/0/binlog"_q;
	const auto unrelated = fixture.path + u"/user_other/cache/0"_q;
	if (!QDir().mkpath(root + u"cache/0/10"_q)
		|| !Write(root + blob, "old encrypted cache body")
		|| !Write(root + binlog, "old encrypted cache index")
		|| !QDir().mkpath(unrelated)
		|| !Write(unrelated + u"/binlog"_q, "other account")) {
		Check(false, "populate synthetic cache inventory");
		return;
	}
	Check(!fixture.capture(), "unverified account cache blocks retirement capture");
	account.cacheDirectories = { u"cache"_q, u"cache/0"_q, u"cache/0/10"_q };
	account.cacheFiles = { binlog, blob };
	const auto captured = fixture.capture();
	const auto plan = captured
		? ParseLegacyRetirementPlan(SerializeLegacyRetirementPlan(*captured))
		: std::nullopt;
	if (!plan) {
		Check(false, "capture and reopen typed verified cache receipt");
		return;
	}
	const auto unexpected = root + u"cache/0/10/FFFFFFFFFFFF"_q;
	const auto key = fixture.path + u"/key_datas"_q;
	const auto run = [&] {
		return RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan);
	};
	Check(Write(unexpected, "unverified cache file")
		&& !fixture.capture()
		&& run() == Result::UnexpectedSource
		&& QFileInfo::exists(key), "recognized but unlisted cache blob blocks all deletion");
	Check(QFile::remove(unexpected) && QFile::remove(root + blob)
		&& run() == Result::Complete
		&& !QFileInfo::exists(root)
		&& QFileInfo::exists(unrelated + u"/binlog"_q)
		&& run() == Result::Complete, "resume cache retirement while preserving other account path");
}

void CheckLegacyPreferences() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "settings fixture setup");
		return;
	}
	const auto preferences = fixture.path + u"/ayu_settings.json"_q;
	const auto unrelated = fixture.path + u"/preferences.yaml"_q;
	const auto data = QByteArray("{\"showMessageSeconds\":true}");
	const auto digest = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
	const auto absent = LegacyArchiveRetirement::ExpectedAbsent;
	if (!Write(preferences, data) || !Write(unrelated, "unrelated: settings")) {
		Check(false, "write synthetic settings");
		return;
	}
	Check(!fixture.capture() && !fixture.capture(absent, QByteArray(32, 'x')),
		"present Ayu JSON requires the exact verified source digest");
	const auto plan = fixture.capture(absent, digest);
	if (!plan) {
		Check(false, "capture verified source JSON");
		return;
	}
	const auto run = [&] {
		return RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan);
	};
	const auto keys = fixture.path + u"/key_datas"_q;
	Check(Write(preferences, data + ' ') && run() == Result::UnexpectedSource
		&& QFileInfo::exists(keys), "changed Ayu JSON blocks all retirement mutations");
	Check(Write(preferences, data) && run() == Result::Complete
		&& !QFileInfo::exists(preferences) && QFileInfo::exists(unrelated)
		&& run() == Result::Complete, "verified Ayu JSON retires without unrelated YAML");
}

void CheckLinks() {
#if !defined Q_OS_WIN
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "link fixture setup");
		return;
	}
	const auto plan = fixture.capture();
	if (!plan) {
		Check(false, "link fixture capture");
		return;
	}
	const auto outside = fixture.path + u"/unrelated-path"_q;
	const auto &paths = fixture.accounts.front().paths;
	const auto auth = paths.authPath + 's';
	const auto native = [](const QString &filePath) {
		return QFileInfo(filePath).filesystemFilePath();
	};
	auto error = std::error_code();
	if (QFile::remove(auth)) {
		std::filesystem::create_symlink(native(outside), native(auth), error);
	} else {
		Check(false, "replace synthetic auth with dangling symlink");
		return;
	}
	Check(!error && !fixture.capture()
		&& RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan)
			== Result::UnexpectedSource, "reject a dangling authorization symlink");
	Check(QFile::remove(auth) && Write(auth, "authorization"), "restore the synthetic auth");
	const auto temp = QDir::cleanPath(paths.tempPath);
	if (QDir().rmdir(temp) && QDir().mkpath(outside)
		&& Write(outside + u"/marker"_q, "preserved")) {
		std::filesystem::create_directory_symlink(native(outside), native(temp), error);
	} else {
		Check(false, "replace synthetic temp path with directory symlink");
		return;
	}
	Check(!error && !fixture.capture()
		&& RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan)
			== Result::UnexpectedSource
		&& QFileInfo::exists(outside + u"/marker"_q)
		&& QFileInfo::exists(fixture.path + u"/key_datas"_q),
		"directory symlink does not expand or partially apply the plan");
#endif
}

void CheckLegacyOfflineHistory() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "offline-history fixture setup");
		return;
	}
	const auto root = u"offline-history"_q;
	const auto account = root + u"/901"_q;
	const auto peer = account + u"/77"_q;
	const auto attachments = peer + u"/attachments"_q;
	const auto snapshot = peer + u"/history.json"_q;
	const auto body = attachments + u"/m-8-d-123.txt"_q;
	const auto raw = QByteArray("verified synthetic offline history");
	const auto digest = QCryptographicHash::hash(raw, QCryptographicHash::Sha256);
	const auto full = [&](const QString &relative) { return fixture.path + '/' + relative; };
	const auto backup = fixture.path + u"/offline-history-backup"_q;
	const auto oldPlan = fixture.capture();
	if (!oldPlan || !QDir().mkpath(full(attachments)) || !QDir().mkpath(backup)
		|| !Write(full(snapshot), raw) || !Write(full(body), raw)
		|| !Write(backup + u"/unrelated.bin"_q, raw)) {
		Check(false, "create synthetic offline snapshot and independent backup");
		return;
	}
	using OfflineEntry = Ayu::OfflineHistory::LegacyOfflineEntry;
	const auto receipt = std::array{
		OfflineEntry{ root },
		OfflineEntry{ account },
		OfflineEntry{ peer },
		OfflineEntry{ attachments },
		OfflineEntry{ snapshot, digest },
		OfflineEntry{ body, digest },
	};
	const auto capture = [&](std::span<const OfflineEntry> entries) {
		return CaptureLegacyRetirementPlan(
			fixture.path, fixture.name, fixture.transaction, fixture.slotIndices,
			fixture.accounts, LegacyArchiveRetirement::ExpectedAbsent, {}, entries);
	};
	const auto keys = fixture.path + u"/key_datas"_q;
	Check(!capture({}) && !capture(std::span(receipt).subspan(1))
		&& RetireLegacyProfileFiles(fixture.path, fixture.transaction, *oldPlan)
			== Result::UnexpectedSource
		&& QFileInfo::exists(keys),
		"offline root requires exact authenticated staging receipt even on resume");
	const auto prepared = capture(receipt);
	const auto plan = prepared
		? ParseLegacyRetirementPlan(SerializeLegacyRetirementPlan(*prepared))
		: std::nullopt;
	if (!plan) {
		Check(false, "persist and reopen offline retirement proof");
		return;
	}
	const auto run = [&] {
		return RetireLegacyProfileFiles(fixture.path, fixture.transaction, *plan);
	};
	const auto extra = full(peer + u"/history.partial.json"_q);
	Check(Write(extra, "unexplained snapshot") && !capture(receipt)
		&& run() == Result::UnexpectedSource && QFileInfo::exists(keys)
		&& QFile::remove(extra), "extra recognized offline file blocks all deletion");
	Check(Write(full(body), raw + ' ') && !capture(receipt)
		&& run() == Result::UnexpectedSource && QFileInfo::exists(keys)
		&& Write(full(body), raw), "changed offline attachment blocks all deletion");
	Check(QFile::remove(full(body)) && run() == Result::Complete
		&& !QFileInfo::exists(full(root))
		&& QFileInfo::exists(backup + u"/unrelated.bin"_q)
		&& run() == Result::Complete,
		"offline retirement resumes and preserves unrelated backup directory");
}

} // namespace

int main(int argc, char *argv[]) {
	const auto app = QCoreApplication(argc, argv);
	CheckCapture();
	CheckReplay();
	CheckLegacyArchive();
	CheckLegacyCache();
	CheckLegacyPreferences();
	CheckLinks();
	CheckLegacyOfflineHistory();
	return Failed ? 1 : 0;
}
