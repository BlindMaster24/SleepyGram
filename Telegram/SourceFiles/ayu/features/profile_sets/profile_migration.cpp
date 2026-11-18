/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_migration.h"

#include "base/basic_types.h"

#include <openssl/rand.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QLockFile>
#include <QtCore/QSaveFile>
#include <QtCore/QCryptographicHash>
#include <QtCore/QStringList>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <set>
#include <utility>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace Ayu::ProfileSets {
namespace {

constexpr auto kStageManifestVersion = 1;
constexpr auto kGenerationManifestVersion = 2;
constexpr auto kWorkspaceMarkerName = ".migration-workspace";
constexpr auto kWorkspaceMarker = "sleepygram-isolated-migration-workspace-v1\n";
constexpr auto kWorkspacePrefix = "sleepygram-migration-fixture-";
constexpr auto kProfileDirectoryName = "profile-sets";
constexpr auto kLegacyProfileMarker
	= "sleepygram-profile-migration-workspace-v1\n";
constexpr auto kPreparingProfileMarker
	= "sleepygram-profile-migration-workspace-v2 preparing\n";
constexpr auto kCutoverProfileMarker
	= "sleepygram-profile-migration-workspace-v2 cutover-started ";
constexpr auto kAccountsDirectoryName = "accounts";
constexpr auto kWorkspaceLockName = "migration.lock";
constexpr auto kPendingManifestName = "migration.manifest.pending";
constexpr auto kCommittedManifestName = "migration.manifest.committed";
constexpr auto kStageDirectoryName = "stage";
constexpr auto kCutoverDirectoryName = ".cutover";
constexpr auto kCutoverPhaseFileName = "phase";
constexpr auto kCutoverActiveFileName = "active";
constexpr auto kGenerationsDirectoryName = "generations";
constexpr auto kTemporaryManifestPrefix = ".manifest-";
constexpr auto kMaximumManifestSize = 4096;
constexpr auto kMaximumArtifactSize = 80 * 1024 * 1024;
constexpr auto kMaximumSidecarSize = 88 * 1024 * 1024;
constexpr auto kTransactionIdSize = 16;

struct Entry final {
	MigrationArtifact artifact = MigrationArtifact::ProfileVault;
	quint64 size = 0;
	QByteArray digest;
};

struct Manifest final {
	int version = kStageManifestVersion;
	QByteArray transactionId;
	std::vector<Entry> entries;
};

enum class ProfilePhase : uchar {
	LegacyFormat,
	Preparing,
	CutoverStarted,
};

struct ProfilePhaseRecord final {
	ProfilePhase phase = ProfilePhase::Preparing;
	QByteArray initialTransactionId;

	friend bool operator==(
		const ProfilePhaseRecord&,
		const ProfilePhaseRecord&) = default;
};

void SetError(MigrationError *error, MigrationError value) {
	if (error) {
		*error = value;
	}
}

QString ArtifactName(MigrationArtifact artifact) {
	switch (artifact) {
	case MigrationArtifact::ProfileVault:
		return u"profile-vault"_q;
	case MigrationArtifact::AccountKeyring:
		return u"account-keyring"_q;
	}
	return QString();
}

QString ArtifactFileName(MigrationArtifact artifact) {
	switch (artifact) {
	case MigrationArtifact::ProfileVault:
		return u"profile-vault.bin"_q;
	case MigrationArtifact::AccountKeyring:
		return u"account-keyring.bin"_q;
	}
	return QString();
}

std::optional<MigrationArtifact> ParseArtifactName(const QString &name) {
	if (name == u"profile-vault") {
		return MigrationArtifact::ProfileVault;
	} else if (name == u"account-keyring") {
		return MigrationArtifact::AccountKeyring;
	}
	return std::nullopt;
}

QString ArtifactPath(const QString &directory, MigrationArtifact artifact) {
	return QDir(directory).filePath(ArtifactFileName(artifact));
}

QString ManifestPath(const QString &root, const char *name) {
	return QDir(root).filePath(QString::fromLatin1(name));
}

QString CanonicalDirectory(const QString &path) {
	const auto info = QFileInfo(path);
	return (info.isDir() && !info.isSymLink() && !info.isJunction())
		? info.canonicalFilePath()
		: QString();
}

QString CanonicalProfileDataDirectory(const QString &path) {
	return (!QDir::isAbsolutePath(path) || path.startsWith(':')
		|| path.contains(QChar(0)))
		? QString()
		: CanonicalDirectory(QDir::cleanPath(path));
}

bool PathPresent(const QString &path) {
	const auto info = QFileInfo(path);
	return info.exists() || info.isSymLink() || info.isJunction();
}

QString Hex(const QByteArray &bytes) {
	return QString::fromLatin1(bytes.toHex());
}

QString ArtifactsDirectory(const QString &root, const Manifest &manifest) {
	if (manifest.version == kStageManifestVersion) {
		return ManifestPath(root, kStageDirectoryName);
	}
	return QDir(ManifestPath(root, kGenerationsDirectoryName)).filePath(
		Hex(manifest.transactionId));
}

QString TemporaryManifestPath(const QString &root, const QByteArray &id) {
	return QDir(ManifestPath(root, kGenerationsDirectoryName)).filePath(
		QString::fromLatin1(kTemporaryManifestPrefix) + Hex(id));
}

bool ValidGenerationName(QStringView name) {
	return name.size() == 2 * kTransactionIdSize
		&& std::all_of(name.cbegin(), name.cend(), [](QChar ch) {
			return (ch >= u'0' && ch <= u'9') || (ch >= u'a' && ch <= u'f');
		});
}

QByteArray Digest(const QByteArray &bytes) {
	return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
}

QJsonObject ManifestEntry(const Entry &entry) {
	return QJsonObject{
		{ u"name"_q, ArtifactName(entry.artifact) },
		{ u"size"_q, double(entry.size) },
		{ u"sha256"_q, Hex(entry.digest) },
	};
}

QByteArray SerializeManifest(const Manifest &manifest) {
	auto entries = QJsonArray();
	for (const auto &entry : manifest.entries) {
		entries.push_back(ManifestEntry(entry));
	}
	return QJsonDocument(QJsonObject{
		{ u"format"_q, u"sleepygram-profile-migration"_q },
		{ u"version"_q, manifest.version },
		{ u"transaction_id"_q, Hex(manifest.transactionId) },
		{ u"entries"_q, entries },
	}).toJson(QJsonDocument::Compact);
}

bool HasExactKeys(const QJsonObject &object, std::set<QString> expected) {
	const auto keys = object.keys();
	return (keys.size() == int(expected.size()))
		&& std::all_of(keys.cbegin(), keys.cend(), [&](const QString &key) {
			return expected.contains(key);
		});
}

bool ParseManifest(
		const QByteArray &bytes,
		Manifest *manifest,
		MigrationError *error) {
	SetError(error, MigrationError::InvalidManifest);
	if (bytes.isEmpty() || bytes.size() > kMaximumManifestSize) {
		SetError(error, MigrationError::TooLarge);
		return false;
	}
	QJsonParseError parseError;
	const auto document = QJsonDocument::fromJson(bytes, &parseError);
	if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
		return false;
	}
	const auto object = document.object();
	if (!HasExactKeys(object, {
			u"format"_q,
			u"version"_q,
			u"transaction_id"_q,
			u"entries"_q,
		})
		|| object.value(u"format"_q).toString()
			!= u"sleepygram-profile-migration"_q
		|| !object.value(u"version"_q).isDouble()) {
		return false;
	}
	const auto version = object.value(u"version"_q).toDouble();
	if (version != kStageManifestVersion
		&& version != kGenerationManifestVersion) {
		SetError(error, MigrationError::UnsupportedVersion);
		return false;
	}
	const auto idText = object.value(u"transaction_id"_q).toString().toLatin1();
	const auto id = QByteArray::fromHex(idText);
	if (id.size() != kTransactionIdSize || id.toHex() != idText) {
		return false;
	}
	const auto array = object.value(u"entries"_q).toArray();
	if (array.size() != 2) {
		return false;
	}
	auto parsed = Manifest{ .version = int(version), .transactionId = id };
	auto seen = std::set<MigrationArtifact>();
	auto totalSize = quint64(0);
	for (const auto &value : array) {
		if (!value.isObject()) {
			return false;
		}
		const auto item = value.toObject();
		if (!HasExactKeys(item, { u"name"_q, u"size"_q, u"sha256"_q })
			|| !item.value(u"name"_q).isString()
			|| !item.value(u"size"_q).isDouble()
			|| !item.value(u"sha256"_q).isString()) {
			return false;
		}
		const auto artifact = ParseArtifactName(item.value(u"name"_q).toString());
		const auto sizeNumber = item.value(u"size"_q).toDouble();
		const auto digestText = item.value(u"sha256"_q).toString().toLatin1();
		const auto digest = QByteArray::fromHex(digestText);
		if (!artifact || !seen.insert(*artifact).second
			|| sizeNumber < 1
			|| sizeNumber > kMaximumArtifactSize
			|| sizeNumber != double(quint64(sizeNumber))
			|| digest.size() != 32
			|| digest.toHex() != digestText) {
			return false;
		}
		parsed.entries.push_back({
			.artifact = *artifact,
			.size = quint64(sizeNumber),
			.digest = digest,
		});
		totalSize += quint64(sizeNumber);
	}
	if (totalSize > kMaximumSidecarSize) {
		SetError(error, MigrationError::TooLarge);
		return false;
	}
	std::sort(parsed.entries.begin(), parsed.entries.end(), [](
			const Entry &a,
			const Entry &b) {
		return a.artifact < b.artifact;
	});
	*manifest = std::move(parsed);
	SetError(error, MigrationError::None);
	return true;
}

bool WriteAtomic(const QString &path, const QByteArray &bytes) {
	QSaveFile file(path);
	file.setDirectWriteFallback(false);
	if (!file.open(QIODevice::WriteOnly)
		|| file.write(bytes) != bytes.size()) {
		file.cancelWriting();
		return false;
	}
	return file.commit();
}

bool SyncDirectory(const QString &path) {
#ifdef Q_OS_WIN
	return true;
#else
	const auto encoded = QFile::encodeName(path);
	const auto fd = open(
		encoded.constData(),
		O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	const auto synced = fsync(fd) == 0;
	close(fd);
	return synced;
#endif
}

bool WriteNewFile(const QString &path, const QByteArray &bytes) {
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly)
		|| file.write(bytes) != bytes.size()
		|| !file.flush()) {
		return false;
	}
#ifdef Q_OS_WIN
	const auto handle = reinterpret_cast<HANDLE>(_get_osfhandle(file.handle()));
	return handle != INVALID_HANDLE_VALUE && FlushFileBuffers(handle);
#else
	return fsync(file.handle()) == 0;
#endif
}

bool PublishManifest(const QString &source, const QString &target) {
#ifdef Q_OS_WIN
	return MoveFileExW(
		reinterpret_cast<const wchar_t*>(source.utf16()),
		reinterpret_cast<const wchar_t*>(target.utf16()),
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
#else
	return rename(
		QFile::encodeName(source).constData(),
		QFile::encodeName(target).constData()) == 0;
#endif
}

std::optional<QByteArray> ReadBounded(
		const QString &path,
		qsizetype maximum) {
	const auto info = QFileInfo(path);
	if (!info.exists() || !info.isFile() || info.isSymLink() || info.isJunction()) {
		return std::nullopt;
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	const auto size = file.size();
	if (size < 1 || size > maximum) {
		return std::nullopt;
	}
	const auto bytes = file.read(maximum + 1);
	return (file.error() == QFileDevice::NoError
			&& file.atEnd()
			&& bytes.size() == size)
		? std::optional<QByteArray>(bytes)
		: std::nullopt;
}

std::optional<ProfilePhaseRecord> ReadProfilePhase(const QString &root) {
	const auto marker = ReadBounded(ManifestPath(root, kWorkspaceMarkerName), 128);
	if (!marker) {
		return std::nullopt;
	} else if (*marker == kLegacyProfileMarker) {
		return ProfilePhaseRecord{ .phase = ProfilePhase::LegacyFormat };
	} else if (*marker == kPreparingProfileMarker) {
		return ProfilePhaseRecord();
	}
	const auto prefix = QByteArrayView(kCutoverProfileMarker);
	if (!marker->startsWith(prefix)
		|| marker->size() != prefix.size() + 2 * kTransactionIdSize + 1
		|| marker->back() != '\n') {
		return std::nullopt;
	}
	const auto idText = marker->mid(prefix.size(), 2 * kTransactionIdSize);
	const auto id = QByteArray::fromHex(idText);
	return (id.size() == kTransactionIdSize && id.toHex() == idText)
		? std::optional(ProfilePhaseRecord{
			.phase = ProfilePhase::CutoverStarted,
			.initialTransactionId = id,
		})
		: std::nullopt;
}

bool ActiveMatchesProfilePhase(const QString &root, const Manifest &manifest) {
	const auto phase = ReadProfilePhase(root);
	return phase && (phase->phase == ProfilePhase::LegacyFormat
		|| (phase->phase == ProfilePhase::CutoverStarted
			&& (manifest.version == kGenerationManifestVersion
				|| manifest.transactionId == phase->initialTransactionId)));
}

bool PublishInitialFile(
		const QString &root,
		const char *temporaryName,
		const char *targetName,
		const QByteArray &bytes,
		MigrationError *error) {
	const auto directory = ManifestPath(root, kCutoverDirectoryName);
	const auto temporary = ManifestPath(directory, temporaryName);
	const auto target = ManifestPath(root, targetName);
	const auto previous = QFileInfo(temporary);
	if ((!PathPresent(directory)
			&& !QDir(root).mkdir(QString::fromLatin1(kCutoverDirectoryName)))
		|| CanonicalDirectory(directory) != directory
		|| (PathPresent(temporary)
			&& (!previous.isFile() || previous.isSymLink()
				|| previous.isJunction() || !QFile::remove(temporary)))
		|| !WriteNewFile(temporary, bytes)
		|| !SyncDirectory(directory)
		|| !SyncDirectory(root)) {
		SetError(error, MigrationError::WorkspaceIo);
		return false;
	}
	if (!PublishManifest(temporary, target)) {
		SetError(error, ReadBounded(target, kMaximumManifestSize) == bytes
			? MigrationError::PublicationUncertain
			: MigrationError::WorkspaceIo);
		return false;
	}
	if (!SyncDirectory(root)) {
		SetError(error, MigrationError::PublicationUncertain);
		return false;
	}
	return true;
}

bool ValidateFixtureRoot(const QString &root) {
	const auto canonicalRoot = CanonicalDirectory(root);
	const auto rootCanonicalInfo = QFileInfo(canonicalRoot);
	const auto expectedParent = QFileInfo(QDir::tempPath()).canonicalFilePath();
	return !canonicalRoot.isEmpty()
		&& rootCanonicalInfo.dir().canonicalPath() == expectedParent
		&& rootCanonicalInfo.fileName().startsWith(
			QString::fromLatin1(kWorkspacePrefix));
}

bool ValidateRootEntries(const QString &root, bool profile) {
	if (profile
			? !ReadProfilePhase(root)
			: ReadBounded(ManifestPath(root, kWorkspaceMarkerName), 128)
				!= QByteArray(kWorkspaceMarker)) {
		return false;
	}
	const auto entries = QDir(root).entryInfoList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
	auto allowed = std::set<QString>{
		QString::fromLatin1(kWorkspaceMarkerName),
		QString::fromLatin1(kStageDirectoryName),
		QString::fromLatin1(kPendingManifestName),
		QString::fromLatin1(kCommittedManifestName),
		QString::fromLatin1(kWorkspaceLockName),
		QString::fromLatin1(kGenerationsDirectoryName),
	};
	const auto generations = ManifestPath(root, kGenerationsDirectoryName);
	if (PathPresent(generations)
		&& CanonicalDirectory(generations) != generations) {
		return false;
	}
	if (profile) {
		const auto accounts = ManifestPath(root, kAccountsDirectoryName);
		const auto cutover = ManifestPath(root, kCutoverDirectoryName);
		if (CanonicalDirectory(accounts) != accounts
			|| (PathPresent(cutover) && CanonicalDirectory(cutover) != cutover)) {
			return false;
		}
		allowed.emplace(QString::fromLatin1(kAccountsDirectoryName));
		allowed.emplace(QString::fromLatin1(kCutoverDirectoryName));
	}
	for (const auto &entry : entries) {
		if (entry.isSymLink() || entry.isJunction()
			|| !allowed.contains(entry.fileName())) {
			return false;
		}
	}
	return true;
}

bool ValidateArtifactFiles(const QString &directory) {
	if (CanonicalDirectory(directory) != directory) {
		return false;
	}
	const auto entries = QDir(directory).entryInfoList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
	auto names = QStringList();
	for (const auto &entry : entries) {
		if (entry.isSymLink() || entry.isJunction() || !entry.isFile()) {
			return false;
		}
		names.push_back(entry.fileName());
	}
	std::sort(names.begin(), names.end());
	auto expected = QStringList{
		ArtifactFileName(MigrationArtifact::AccountKeyring),
		ArtifactFileName(MigrationArtifact::ProfileVault),
	};
	std::sort(expected.begin(), expected.end());
	if (names != expected) {
		return false;
	}
	return true;
}

std::unique_ptr<QLockFile> LockWorkspace(const QString &root) {
	auto lock = std::make_unique<QLockFile>(ManifestPath(root, kWorkspaceLockName));
	lock->setStaleLockTime(0);
	return lock->tryLock(0) ? std::move(lock) : nullptr;
}

std::optional<Manifest> PrepareManifest(
		const std::vector<MigrationInput> &inputs,
		int version,
		MigrationError *error) {
	SetError(error, MigrationError::InvalidInput);
	if (inputs.size() != 2) {
		return std::nullopt;
	}
	auto manifest = Manifest{ .version = version };
	auto artifacts = std::set<MigrationArtifact>();
	auto total = qsizetype(0);
	for (const auto &input : inputs) {
		const auto size = input.encryptedBytes.size();
		if (ArtifactName(input.artifact).isEmpty()
			|| size < 1 || size > kMaximumArtifactSize
			|| !artifacts.insert(input.artifact).second) {
			return std::nullopt;
		}
		total += size;
		manifest.entries.push_back({
			.artifact = input.artifact,
			.size = quint64(size),
			.digest = Digest(input.encryptedBytes),
		});
	}
	if (total > kMaximumSidecarSize) {
		return std::nullopt;
	}
	std::sort(manifest.entries.begin(), manifest.entries.end(), [](
			const Entry &a,
			const Entry &b) {
		return a.artifact < b.artifact;
	});
	manifest.transactionId = QByteArray(kTransactionIdSize, Qt::Uninitialized);
	if (RAND_bytes(
		reinterpret_cast<unsigned char*>(manifest.transactionId.data()),
		int(manifest.transactionId.size())) != 1) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	return manifest;
}

std::optional<Manifest> ReadManifest(
		const QByteArray &bytes,
		bool committed,
		MigrationError *error) {
	auto result = Manifest();
	if (bytes.isEmpty()) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	} else if (!ParseManifest(bytes, &result, error)) {
		return std::nullopt;
	} else if (!committed && result.version != kStageManifestVersion) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	return result;
}

std::optional<CommittedMigration> ReadArtifacts(
		const QString &root,
		const Manifest &manifest,
		MigrationError *error) {
	const auto directory = ArtifactsDirectory(root, manifest);
	if (!ValidateArtifactFiles(directory)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	auto result = CommittedMigration{
		.transactionId = manifest.transactionId,
	};
	for (const auto &entry : manifest.entries) {
		auto bytes = ReadBounded(
			ArtifactPath(directory, entry.artifact),
			kMaximumArtifactSize);
		if (!bytes || quint64(bytes->size()) != entry.size
			|| Digest(*bytes) != entry.digest) {
			SetError(error, MigrationError::ReadbackFailed);
			return std::nullopt;
		}
		if (entry.artifact == MigrationArtifact::ProfileVault) {
			result.profileVault = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::AccountKeyring) {
			result.accountKeyring = std::move(*bytes);
		} else {
			SetError(error, MigrationError::InvalidManifest);
			return std::nullopt;
		}
	}
	if (result.profileVault.isEmpty() || result.accountKeyring.isEmpty()) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	SetError(error, MigrationError::None);
	return result;
}

std::optional<CommittedMigration> ReadAndVerify(
		const QString &root,
		const char *manifestName,
		bool profile,
		MigrationError *error) {
	const auto manifestBytes = ReadBounded(
		ManifestPath(root, manifestName),
		kMaximumManifestSize);
	const auto committed = (QByteArrayView(manifestName) == kCommittedManifestName);
	const auto manifest = ReadManifest(
		manifestBytes.value_or(QByteArray()), committed, error);
	if (manifest && committed && profile
		&& !ActiveMatchesProfilePhase(root, *manifest)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	return manifest ? ReadArtifacts(root, *manifest, error) : std::nullopt;
}

std::optional<Manifest> ReadExpectedGeneration(
		const QString &root,
		const QByteArray &manifestBytes,
		const QByteArray &expectedId,
		bool profile,
		MigrationError *error) {
	if (expectedId.size() != kTransactionIdSize) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	auto manifest = ReadManifest(manifestBytes, true, error);
	if (!manifest) {
		return std::nullopt;
	} else if (profile && !ActiveMatchesProfilePhase(root, *manifest)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	} else if (manifest->transactionId != expectedId) {
		SetError(error, MigrationError::StaleGeneration);
		return std::nullopt;
	}
	return ReadArtifacts(root, *manifest, error) ? std::move(manifest) : std::nullopt;
}

bool RemoveGenerationDirectory(const QString &directory) {
	if (!PathPresent(directory)) {
		return true;
	} else if (CanonicalDirectory(directory) != directory) {
		return false;
	}
	const auto entries = QDir(directory).entryInfoList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
	for (const auto &entry : entries) {
		if (entry.isSymLink() || entry.isJunction() || !entry.isFile()
			|| (entry.fileName()
					!= ArtifactFileName(MigrationArtifact::ProfileVault)
				&& entry.fileName()
					!= ArtifactFileName(MigrationArtifact::AccountKeyring))) {
			return false;
		}
	}
	for (const auto &entry : entries) {
		if (!QFile::remove(entry.absoluteFilePath())) {
			return false;
		}
	}
	return QDir().rmdir(directory);
}

bool RemoveInactiveGenerations(const QString &root, const Manifest &active) {
	const auto directory = ManifestPath(root, kGenerationsDirectoryName);
	if (!PathPresent(directory)) {
		return active.version == kStageManifestVersion;
	} else if (CanonicalDirectory(directory) != directory) {
		return false;
	}
	const auto activeName = Hex(active.transactionId);
	const auto prefix = QLatin1StringView(kTemporaryManifestPrefix);
	const auto entries = QDir(directory).entryInfoList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
	for (const auto &entry : entries) {
		const auto name = entry.fileName();
		if (active.version == kGenerationManifestVersion && name == activeName) {
			continue;
		}
		if (entry.isSymLink() || entry.isJunction()) {
			return false;
		} else if (ValidGenerationName(name)) {
			if (!RemoveGenerationDirectory(entry.absoluteFilePath())) {
				return false;
			}
		} else if (!entry.isFile()
			|| !name.startsWith(prefix)
			|| !ValidGenerationName(QStringView(name).sliced(prefix.size()))
			|| !QFile::remove(entry.absoluteFilePath())) {
			return false;
		}
	}
	return SyncDirectory(directory);
}

} // namespace

MigrationController::MigrationController(QString root, QString profileDataDirectory)
: _root(std::move(root))
, _profileDataDirectory(std::move(profileDataDirectory)) {
}

std::optional<MigrationController> MigrationController::CreateProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto parent = CanonicalProfileDataDirectory(dataDirectory);
	if (parent.isEmpty()) {
		return std::nullopt;
	}
	const auto root = ManifestPath(parent, kProfileDirectoryName);
	if (PathPresent(root)) {
		return std::nullopt;
	}
	if (!QDir(parent).mkdir(QString::fromLatin1(kProfileDirectoryName))
		|| CanonicalDirectory(root) != root
		|| !QDir(root).mkdir(QString::fromLatin1(kAccountsDirectoryName))
		|| !WriteNewFile(
			ManifestPath(root, kWorkspaceMarkerName),
			QByteArray(kPreparingProfileMarker))
		|| !SyncDirectory(root)
		|| !SyncDirectory(parent)) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	return OpenProfileWorkspace(parent, error);
}

std::optional<MigrationController> MigrationController::OpenProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto parent = CanonicalProfileDataDirectory(dataDirectory);
	if (parent.isEmpty()) {
		return std::nullopt;
	}
	auto result = MigrationController(
		ManifestPath(parent, kProfileDirectoryName),
		parent);
	if (!result.validateWorkspace()) {
		return std::nullopt;
	}
	SetError(error, MigrationError::None);
	return result;
}

MigrationState MigrationController::ProbeProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error) {
	const auto parent = CanonicalProfileDataDirectory(dataDirectory);
	if (parent.isEmpty()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return MigrationState::Invalid;
	}
	if (!PathPresent(ManifestPath(parent, kProfileDirectoryName))) {
		SetError(error, MigrationError::None);
		return MigrationState::Empty;
	}
	const auto workspace = OpenProfileWorkspace(parent, error);
	return workspace ? workspace->Recover(error) : MigrationState::Invalid;
}

ProfileStartupMode MigrationController::ProbeProfileStartup(
		const QString &dataDirectory,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto parent = CanonicalProfileDataDirectory(dataDirectory);
	if (parent.isEmpty()) {
		const auto alias = QFileInfo(dataDirectory);
		const auto resolved = alias.canonicalFilePath();
		if (QDir::isAbsolutePath(dataDirectory)
			&& !dataDirectory.startsWith(':')
			&& !dataDirectory.contains(QChar(0))
			&& alias.isDir()
			&& alias.isReadable() && !resolved.isEmpty()
			&& !PathPresent(ManifestPath(resolved, kProfileDirectoryName))) {
			SetError(error, MigrationError::None);
			return ProfileStartupMode::Legacy;
		}
		return ProfileStartupMode::RecoveryRequired;
	}
	const auto root = ManifestPath(parent, kProfileDirectoryName);
	if (!PathPresent(root)) {
		SetError(error, MigrationError::None);
		return ProfileStartupMode::Legacy;
	}
	const auto workspace = OpenProfileWorkspace(parent, error);
	if (!workspace) {
		return ProfileStartupMode::RecoveryRequired;
	}
	switch (workspace->Recover(error)) {
	case MigrationState::Committed:
		return ProfileStartupMode::Committed;
	case MigrationState::Empty:
	case MigrationState::Staged: {
		const auto phase = ReadProfilePhase(root);
		if (phase && phase->phase == ProfilePhase::Preparing
			&& !PathPresent(ManifestPath(root, kCutoverDirectoryName))
			&& !PathPresent(ManifestPath(root, kCommittedManifestName))) {
			return ProfileStartupMode::Preparing;
		}
		SetError(error, MigrationError::InvalidManifest);
		return ProfileStartupMode::RecoveryRequired;
	}
	case MigrationState::Incomplete:
	case MigrationState::Invalid:
		return ProfileStartupMode::RecoveryRequired;
	}
	SetError(error, MigrationError::InvalidManifest);
	return ProfileStartupMode::RecoveryRequired;
}

bool MigrationController::validateWorkspace() const {
	const auto profile = !_profileDataDirectory.isEmpty();
	const auto validRoot = profile
		? (CanonicalDirectory(_root) == _root
			&& CanonicalDirectory(_profileDataDirectory) == _profileDataDirectory)
		: ValidateFixtureRoot(_root);
	return validRoot && ValidateRootEntries(_root, profile);
}

std::optional<CommittedMigration> MigrationController::readManifest(
		const char *name,
		MigrationError *error) const {
	if (!validateWorkspace()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return std::nullopt;
	}
	return ReadAndVerify(_root, name, !isIsolatedFixture(), error);
}

std::optional<MigrationController>
MigrationController::CreateIsolatedFixtureWorkspace(
		QString path,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto absolute = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
	const auto parent = QFileInfo(absolute).dir().canonicalPath();
	const auto temp = QFileInfo(QDir::tempPath()).canonicalFilePath();
	const auto name = QFileInfo(absolute).fileName();
	if (parent.isEmpty() || parent != temp
		|| !name.startsWith(QString::fromLatin1(kWorkspacePrefix))
		|| PathPresent(absolute)) {
		return std::nullopt;
	}
	if (!QDir(parent).mkdir(name)) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	const auto root = QDir(parent).filePath(name);
	const auto markerPath = ManifestPath(root, kWorkspaceMarkerName);
	if (!WriteAtomic(markerPath, QByteArray(kWorkspaceMarker))) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	SetError(error, MigrationError::None);
	return MigrationController(root);
}

std::optional<MigrationController>
MigrationController::OpenIsolatedFixtureWorkspace(
		QString path,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto absolute = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
	if (!ValidateFixtureRoot(absolute)) {
		return std::nullopt;
	}
	const auto markerPath = ManifestPath(absolute, kWorkspaceMarkerName);
	const auto marker = ReadBounded(markerPath, 128);
	if (!marker || *marker != QByteArray(kWorkspaceMarker)) {
		return std::nullopt;
	}
	SetError(error, MigrationError::None);
	return MigrationController(CanonicalDirectory(absolute));
}

bool MigrationController::Stage(
		const std::vector<MigrationInput> &inputs,
		MigrationError *error) const {
	SetError(error, MigrationError::UnsafeWorkspace);
	if (!validateWorkspace()) {
		return false;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return false;
	}
	if (!validateWorkspace()) {
		return false;
	}
	if (PathPresent(ManifestPath(_root, kGenerationsDirectoryName))
		&& !PathPresent(ManifestPath(_root, kCommittedManifestName))) {
		SetError(error, MigrationError::InvalidManifest);
		return false;
	}
	if (QFileInfo::exists(ManifestPath(_root, kCommittedManifestName))
		|| QFileInfo::exists(ManifestPath(_root, kPendingManifestName))
		|| QFileInfo::exists(QDir(_root).filePath(
			QString::fromLatin1(kStageDirectoryName)))) {
		SetError(error, MigrationError::AlreadyStaged);
		return false;
	}
	const auto profile = !isIsolatedFixture();
	if (profile) {
		const auto phase = ReadProfilePhase(_root);
		if (!phase || phase->phase != ProfilePhase::Preparing
			|| PathPresent(ManifestPath(_root, kCutoverDirectoryName))) {
			SetError(error, MigrationError::InvalidManifest);
			return false;
		}
	}
	const auto manifest = PrepareManifest(inputs, kStageManifestVersion, error);
	if (!manifest) {
		return false;
	}
	if (!QDir(_root).mkdir(QString::fromLatin1(kStageDirectoryName))) {
		SetError(error, MigrationError::WorkspaceIo);
		return false;
	}
	const auto directory = ArtifactsDirectory(_root, *manifest);
	for (const auto &input : inputs) {
		const auto path = ArtifactPath(directory, input.artifact);
		const auto written = profile
			? WriteNewFile(path, input.encryptedBytes)
			: WriteAtomic(path, input.encryptedBytes);
		if (!written) {
			SetError(error, MigrationError::WorkspaceIo);
			return false;
		}
	}
	const auto pending = SerializeManifest(*manifest);
	const auto pendingPath = ManifestPath(_root, kPendingManifestName);
	if (pending.isEmpty() || pending.size() > kMaximumManifestSize) {
		SetError(error, MigrationError::WorkspaceIo);
		return false;
	}
	const auto pendingWritten = profile
		? (SyncDirectory(directory) && WriteNewFile(pendingPath, pending)
			&& SyncDirectory(_root))
		: WriteAtomic(pendingPath, pending);
	if (!pendingWritten) {
		SetError(error, MigrationError::WorkspaceIo);
		return false;
	}
	if (!readManifest(kPendingManifestName, error)) {
		return false;
	}
	SetError(error, MigrationError::None);
	return true;
}

std::optional<CommittedMigration> MigrationController::Commit(
		MigrationError *error) const {
	if (!_profileDataDirectory.isEmpty()) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	return commit({}, error);
}

std::optional<CommittedMigration> MigrationController::CommitVerified(
		const Verifier &verify,
		MigrationError *error) const {
	if (!verify) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	return commit(verify, error);
}

std::optional<CommittedMigration> MigrationController::ReplaceCommitted(
		const QByteArray &expectedTransactionId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error) const {
	if (!verify) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	SetError(error, MigrationError::UnsafeWorkspace);
	if (!validateWorkspace()) {
		return std::nullopt;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return std::nullopt;
	} else if (!validateWorkspace()) {
		return std::nullopt;
	}
	const auto activePath = ManifestPath(_root, kCommittedManifestName);
	if (!PathPresent(activePath)) {
		SetError(error, MigrationError::NotStaged);
		return std::nullopt;
	}
	const auto existing = ReadBounded(activePath, kMaximumManifestSize);
	if (!ReadExpectedGeneration(
			_root,
			existing.value_or(QByteArray()),
			expectedTransactionId,
			!isIsolatedFixture(),
			error)) {
		return std::nullopt;
	}
	const auto manifest = PrepareManifest(
		inputs,
		kGenerationManifestVersion,
		error);
	if (!manifest) {
		return std::nullopt;
	}
	const auto parent = ManifestPath(_root, kGenerationsDirectoryName);
	const auto directory = ArtifactsDirectory(_root, *manifest);
	SetError(error, MigrationError::WorkspaceIo);
	if (manifest->transactionId == expectedTransactionId
		|| (!PathPresent(parent)
			&& !QDir(_root).mkdir(QString::fromLatin1(kGenerationsDirectoryName)))
		|| CanonicalDirectory(parent) != parent
		|| !QDir(parent).mkdir(Hex(manifest->transactionId))) {
		return std::nullopt;
	}
	const auto temporary = TemporaryManifestPath(_root, manifest->transactionId);
	auto published = false;
	const auto cleanup = gsl::finally([&] {
		if (!published && CanonicalDirectory(parent) == parent
			&& ReadBounded(activePath, kMaximumManifestSize) == existing) {
			QFile::remove(temporary);
			RemoveGenerationDirectory(directory);
		}
	});
	for (const auto &input : inputs) {
		if (!WriteNewFile(
				ArtifactPath(directory, input.artifact),
				input.encryptedBytes)) {
			return std::nullopt;
		}
	}
	{
		const auto staged = ReadArtifacts(_root, *manifest, error);
		if (!staged) {
			return std::nullopt;
		} else if (!verify(*staged)) {
			SetError(error, MigrationError::VerificationFailed);
			return std::nullopt;
		}
	}
	auto checked = ReadArtifacts(_root, *manifest, error);
	if (!checked || !validateWorkspace()) {
		SetError(error, MigrationError::ReadbackFailed);
		return std::nullopt;
	}
	const auto stillActive = ReadBounded(activePath, kMaximumManifestSize);
	if (existing != stillActive) {
		SetError(error, MigrationError::StaleGeneration);
		return std::nullopt;
	}
	const auto next = SerializeManifest(*manifest);
	if (next.isEmpty() || next.size() > kMaximumManifestSize
		|| !WriteNewFile(temporary, next)
		|| !SyncDirectory(directory)
		|| !SyncDirectory(parent)
		|| !SyncDirectory(_root)) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	if (!PublishManifest(temporary, activePath)) {
		SetError(error, ReadBounded(activePath, kMaximumManifestSize) == existing
			? MigrationError::WorkspaceIo
			: MigrationError::PublicationUncertain);
		return std::nullopt;
	}
	published = true;
	if (!SyncDirectory(_root)) {
		SetError(error, MigrationError::PublicationUncertain);
		return std::nullopt;
	}
	SetError(error, MigrationError::None);
	return checked;
}

bool MigrationController::RetireInactiveGenerations(
		const QByteArray &expectedTransactionId,
		MigrationError *error) const {
	SetError(error, MigrationError::UnsafeWorkspace);
	if (!validateWorkspace()) {
		return false;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return false;
	} else if (!validateWorkspace()) {
		return false;
	}
	const auto activePath = ManifestPath(_root, kCommittedManifestName);
	if (!PathPresent(activePath)) {
		SetError(error, MigrationError::NotStaged);
		return false;
	}
	const auto activeBytes = ReadBounded(activePath, kMaximumManifestSize);
	const auto active = ReadExpectedGeneration(
		_root,
		activeBytes.value_or(QByteArray()),
		expectedTransactionId,
		!isIsolatedFixture(),
		error);
	if (!active) {
		return false;
	}
	if (!SyncDirectory(_root) || !RemoveInactiveGenerations(_root, *active)) {
		SetError(error, MigrationError::RetirementFailed);
		return false;
	}
	if (active->version == kGenerationManifestVersion) {
		const auto stage = ManifestPath(_root, kStageDirectoryName);
		const auto pending = ManifestPath(_root, kPendingManifestName);
		if (!RemoveGenerationDirectory(stage)
			|| (PathPresent(pending) && !QFile::remove(pending))
			|| !SyncDirectory(_root)) {
			SetError(error, MigrationError::RetirementFailed);
			return false;
		}
	}
	SetError(error, MigrationError::None);
	return true;
}

std::optional<CommittedMigration> MigrationController::commit(
		const Verifier &verify,
		MigrationError *error) const {
	if (!validateWorkspace()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return std::nullopt;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return std::nullopt;
	}
	const auto activePath = ManifestPath(_root, kCommittedManifestName);
	if (PathPresent(activePath)) {
		return LoadCommitted(error);
	}
	if (PathPresent(ManifestPath(_root, kGenerationsDirectoryName))) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	const auto profile = !isIsolatedFixture();
	const auto phase = profile ? ReadProfilePhase(_root) : std::nullopt;
	if (profile && (!phase || phase->phase == ProfilePhase::LegacyFormat)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	const auto pendingPath = ManifestPath(_root, kPendingManifestName);
	const auto pending = ReadBounded(pendingPath, kMaximumManifestSize);
	const auto staged = readManifest(kPendingManifestName, error);
	if (!staged) {
		if (!QFileInfo::exists(ManifestPath(_root, kPendingManifestName))) {
			SetError(error, MigrationError::NotStaged);
		}
		return std::nullopt;
	}
	if (phase && phase->phase == ProfilePhase::CutoverStarted
		&& phase->initialTransactionId != staged->transactionId) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	if (verify && !verify(*staged)) {
		SetError(error, MigrationError::VerificationFailed);
		return std::nullopt;
	}
	const auto checked = readManifest(kPendingManifestName, error);
	if (!pending || !checked || checked->transactionId != staged->transactionId
		|| checked->profileVault != staged->profileVault
		|| checked->accountKeyring != staged->accountKeyring
		|| PathPresent(activePath)
		|| (profile && ReadProfilePhase(_root) != phase)
		|| pending != ReadBounded(pendingPath, kMaximumManifestSize)) {
		SetError(error, MigrationError::ReadbackFailed);
		return std::nullopt;
	}
	if (phase) {
		if (phase->phase == ProfilePhase::Preparing
			&& !PublishInitialFile(
				_root,
				kCutoverPhaseFileName,
				kWorkspaceMarkerName,
				QByteArray(kCutoverProfileMarker)
					+ staged->transactionId.toHex() + '\n',
				error)) {
			return std::nullopt;
		}
		if (!PublishInitialFile(
				_root,
				kCutoverActiveFileName,
				kCommittedManifestName,
				*pending,
				error)) {
			return std::nullopt;
		}
	} else if (!WriteAtomic(activePath, *pending)) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	return LoadCommitted(error);
}

MigrationState MigrationController::Recover(MigrationError *error) const {
	SetError(error, MigrationError::None);
	if (!validateWorkspace()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return MigrationState::Invalid;
	}
	if (PathPresent(ManifestPath(_root, kCommittedManifestName))) {
		return LoadCommitted(error)
			? MigrationState::Committed
			: MigrationState::Invalid;
	}
	if (!isIsolatedFixture()) {
		const auto phase = ReadProfilePhase(_root);
		if (!phase || phase->phase != ProfilePhase::Preparing
			|| PathPresent(ManifestPath(_root, kCutoverDirectoryName))) {
			SetError(error, MigrationError::InvalidManifest);
			return MigrationState::Invalid;
		}
	}
	if (PathPresent(ManifestPath(_root, kGenerationsDirectoryName))) {
		SetError(error, MigrationError::InvalidManifest);
		return MigrationState::Invalid;
	}
	if (QFileInfo::exists(ManifestPath(_root, kPendingManifestName))) {
		return readManifest(kPendingManifestName, error)
			? MigrationState::Staged
			: MigrationState::Invalid;
	}
	if (QFileInfo::exists(QDir(_root).filePath(
			QString::fromLatin1(kStageDirectoryName)))) {
		SetError(error, MigrationError::ReadbackFailed);
		return MigrationState::Incomplete;
	}
	return MigrationState::Empty;
}

std::optional<CommittedMigration> MigrationController::LoadCommitted(
		MigrationError *error) const {
	if (!PathPresent(ManifestPath(_root, kCommittedManifestName))) {
		const auto profile = !isIsolatedFixture();
		const auto phase = profile ? ReadProfilePhase(_root) : std::nullopt;
		const auto unavailable = PathPresent(ManifestPath(
			_root,
			kGenerationsDirectoryName))
			|| (profile && (!phase || phase->phase != ProfilePhase::Preparing
				|| PathPresent(ManifestPath(_root, kCutoverDirectoryName))));
		SetError(error, unavailable
			? MigrationError::InvalidManifest
			: MigrationError::NotStaged);
		return std::nullopt;
	}
	return readManifest(kCommittedManifestName, error);
}

bool MigrationController::WithCurrentGeneration(
		const QByteArray &expectedTransactionId,
		const std::function<bool()> &callback,
		MigrationError *error) const {
	if (expectedTransactionId.size() != kTransactionIdSize || !callback) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	} else if (!validateWorkspace()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return false;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return false;
	}
	{
		const auto committed = LoadCommitted(error);
		if (!committed) {
			return false;
		} else if (committed->transactionId != expectedTransactionId) {
			SetError(error, MigrationError::StaleGeneration);
			return false;
		}
	}
	const auto result = callback();
	SetError(error, result ? MigrationError::None : MigrationError::CallbackFailed);
	return result;
}

bool MigrationController::WithPreparingWorkspace(
		const std::function<bool()> &callback,
		MigrationError *error) const {
	if (!callback || isIsolatedFixture() || !validateWorkspace()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return false;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return false;
	}
	if (ProbeProfileStartup(_profileDataDirectory, error)
		!= ProfileStartupMode::Preparing) {
		SetError(error, MigrationError::StaleGeneration);
		return false;
	}
	const auto result = callback();
	SetError(error, result ? MigrationError::None : MigrationError::CallbackFailed);
	return result;
}

QString MigrationController::workspacePath() const {
	return _root;
}

QString MigrationController::accountStorageRoot() const {
	return (!_profileDataDirectory.isEmpty() && validateWorkspace())
		? ManifestPath(_root, kAccountsDirectoryName)
		: QString();
}

bool MigrationController::isIsolatedFixture() const {
	return _profileDataDirectory.isEmpty();
}

} // namespace Ayu::ProfileSets
