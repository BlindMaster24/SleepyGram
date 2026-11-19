/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_migration.h"
#include "ayu/features/profile_sets/profile_sets.h"

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
#include <QtCore/QtEndian>

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
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu::ProfileSets {
namespace {

constexpr auto kStageManifestVersion = 1;
constexpr auto kGenerationManifestVersion = 2;
constexpr auto kRevocableManifestVersion = 3;
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
constexpr auto kEmergencyJournalName = "emergency-journal";
constexpr auto kSettingsDirectoryName = "set-settings";
constexpr auto kWorkspaceLockName = "migration.lock";
constexpr auto kSetupDraftName = "profile-setup.bin";
constexpr auto kSetupDraftMagic = "SGPD1";
constexpr auto kPendingManifestName = "migration.manifest.pending";
constexpr auto kCommittedManifestName = "migration.manifest.committed";
constexpr auto kStageDirectoryName = "stage";
constexpr auto kCutoverDirectoryName = ".cutover";
constexpr auto kCutoverPhaseFileName = "phase";
constexpr auto kCutoverActiveFileName = "active";
constexpr auto kGenerationsDirectoryName = "generations";
constexpr auto kTemporaryManifestPrefix = ".manifest-";
constexpr auto kRevocableHeadName = ".revocable-head";
constexpr auto kRevocableHeadTemporaryName = ".revocable-head-tmp";
constexpr auto kRevocableHeadMagic = QByteArrayView("SGRH1");
constexpr auto kRevocableFloorName = ".revocable-floor";
constexpr auto kRevocableFloorMagic = QByteArrayView("SGRF1");
constexpr auto kRevocableVaultMagic = QByteArrayView("SPGV\0\0\0\3", 8);
constexpr auto kAccountGateTableMagic = QByteArrayView("SGGT1");
constexpr auto kRevocableRulesMagic = QByteArrayView("SGEB3");
constexpr auto kRevocableRecoveryMagic = QByteArrayView("SGER3");
constexpr auto kMaximumManifestSize = 4096;
constexpr auto kMaximumArtifactSize = 80 * 1024 * 1024;
constexpr auto kMaximumRevocableEmergencyArtifactSize = 4 * 1024 * 1024;
constexpr auto kMaximumRevocableJournalBytes = 1024 * 1024;
constexpr auto kMaximumSidecarSize = 88 * 1024 * 1024;
constexpr auto kTransactionIdSize = 16;
constexpr auto kInstallationIdSize = 16;
constexpr auto kManifestDigestSize = 32;
constexpr auto kGenerationProofSize = kTransactionIdSize + kManifestDigestSize;
constexpr auto kMaximumHeadSize = kRevocableHeadMagic.size() + 1
	+ kInstallationIdSize + 2 * kGenerationProofSize;
constexpr auto kRevocableFloorSize = kRevocableFloorMagic.size() + kInstallationIdSize;

struct Entry final {
	MigrationArtifact artifact = MigrationArtifact::ProfileVault;
	quint64 size = 0;
	QByteArray digest;
};

struct Manifest final {
	int version = kStageManifestVersion;
	QByteArray transactionId;
	QByteArray installationId;
	std::vector<Entry> entries;
};

enum class RevocableHeadState : char {
	Pending = 'P',
	Retiring = 'R',
	Retired = 'C',
};

struct RevocableHead final {
	RevocableHeadState state = RevocableHeadState::Pending;
	QByteArray installationId;
	MigrationGenerationProof current;
	MigrationGenerationProof candidate;
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
	case MigrationArtifact::LegacyRetirement:
		return u"legacy-retirement"_q;
	case MigrationArtifact::EmergencyRules:
		return u"emergency-rules"_q;
	case MigrationArtifact::EmergencyRecovery:
		return u"emergency-recovery"_q;
	case MigrationArtifact::AccountGateTable:
		return u"account-gate-table"_q;
	case MigrationArtifact::RevocableEmergencyRules:
		return u"revocable-emergency-rules"_q;
	case MigrationArtifact::RevocableEmergencyRecovery:
		return u"revocable-emergency-recovery"_q;
	}
	return QString();
}

QString ArtifactFileName(MigrationArtifact artifact) {
	const auto name = ArtifactName(artifact);
	return name.isEmpty() ? QString() : name + u".bin"_q;
}

std::optional<MigrationArtifact> ParseArtifactName(const QString &name) {
	if (name == u"profile-vault") {
		return MigrationArtifact::ProfileVault;
	} else if (name == u"account-keyring") {
		return MigrationArtifact::AccountKeyring;
	} else if (name == u"legacy-retirement") {
		return MigrationArtifact::LegacyRetirement;
	} else if (name == u"emergency-rules") {
		return MigrationArtifact::EmergencyRules;
	} else if (name == u"emergency-recovery") {
		return MigrationArtifact::EmergencyRecovery;
	} else if (name == u"account-gate-table") {
		return MigrationArtifact::AccountGateTable;
	} else if (name == u"revocable-emergency-rules") {
		return MigrationArtifact::RevocableEmergencyRules;
	} else if (name == u"revocable-emergency-recovery") {
		return MigrationArtifact::RevocableEmergencyRecovery;
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

bool HasRevocableState(const QString &root) {
	return PathPresent(ManifestPath(root, kRevocableHeadName))
		|| PathPresent(ManifestPath(root, kRevocableFloorName));
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

bool ValidInstallationId(QByteArrayView id) {
	return id.size() == kInstallationIdSize && std::ranges::any_of(id, [](char ch) {
		return ch != 0;
	});
}

bool ValidProof(const MigrationGenerationProof &proof) {
	return proof.transactionId.size() == kTransactionIdSize
		&& proof.manifestDigest.size() == kManifestDigestSize;
}

bool ValidArtifactLayout(int version, const std::set<MigrationArtifact> &artifacts) {
	using Artifact = MigrationArtifact;
	const auto revocable = (version == kRevocableManifestVersion);
	const auto hasRules = artifacts.contains(Artifact::RevocableEmergencyRules);
	const auto hasRecovery = artifacts.contains(Artifact::RevocableEmergencyRecovery);
	if (!artifacts.contains(Artifact::ProfileVault)) {
		return false;
	}
	if (!revocable) {
		return artifacts.contains(Artifact::AccountKeyring)
			&& !artifacts.contains(Artifact::AccountGateTable) && !hasRules && !hasRecovery;
	}
	return artifacts.contains(Artifact::AccountGateTable)
		&& (!hasRecovery || hasRules)
		&& artifacts.size() == size_t(2 + int(hasRules) + int(hasRecovery));
}

int MaximumArtifactSize(MigrationArtifact artifact) {
	return (artifact == MigrationArtifact::RevocableEmergencyRules
		|| artifact == MigrationArtifact::RevocableEmergencyRecovery)
		? kMaximumRevocableEmergencyArtifactSize
		: kMaximumArtifactSize;
}

const Entry *FindEntry(const Manifest &manifest, MigrationArtifact artifact) {
	const auto found = std::ranges::find(manifest.entries, artifact, &Entry::artifact);
	return (found == end(manifest.entries)) ? nullptr : &*found;
}

bool MatchesEntry(
		const Manifest &a,
		const Manifest &b,
		MigrationArtifact artifact) {
	const auto left = FindEntry(a, artifact);
	const auto right = FindEntry(b, artifact);
	return left && right && left->size == right->size && left->digest == right->digest;
}

bool ValidRevocableArtifact(
		const Manifest &manifest,
		MigrationArtifact artifact,
		QByteArrayView bytes) {
	if (artifact == MigrationArtifact::RevocableEmergencyRules) {
		const auto prefix = kRevocableRulesMagic.size();
		return bytes.size() >= prefix + kInstallationIdSize + 2 * qsizetype(sizeof(quint32))
			&& bytes.startsWith(kRevocableRulesMagic)
			&& ValidInstallationId(bytes.sliced(prefix, kInstallationIdSize));
	} else if (artifact != MigrationArtifact::RevocableEmergencyRecovery) {
		return true;
	}
	const auto prefix = kRevocableRecoveryMagic.size();
	const auto transaction = prefix + kInstallationIdSize;
	const auto gateDigest = transaction + kTransactionIdSize;
	const auto rulesDigest = gateDigest + kManifestDigestSize;
	const auto packageMarker = rulesDigest + kManifestDigestSize;
	const auto gates = FindEntry(manifest, MigrationArtifact::AccountGateTable);
	const auto rules = FindEntry(manifest, MigrationArtifact::RevocableEmergencyRules);
	if (!gates || !rules || bytes.size() <= packageMarker
		|| !bytes.startsWith(kRevocableRecoveryMagic)
		|| bytes.sliced(prefix, kInstallationIdSize) != manifest.installationId
		|| bytes.sliced(transaction, kTransactionIdSize) != manifest.transactionId
		|| bytes.sliced(gateDigest, kManifestDigestSize) != gates->digest
		|| bytes.sliced(rulesDigest, kManifestDigestSize) != rules->digest
		|| uchar(bytes[packageMarker]) > 1) {
		return false;
	}
	const auto length = packageMarker + 1 + (bytes[packageMarker] ? kManifestDigestSize : 0);
	const auto journal = length + qsizetype(sizeof(quint32));
	if (bytes.size() <= journal) {
		return false;
	}
	const auto size = qFromBigEndian<quint32>(bytes.data() + length);
	return size > 0 && size <= kMaximumRevocableJournalBytes && size <= bytes.size() - journal;
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
	auto object = QJsonObject{
		{ u"format"_q, u"sleepygram-profile-migration"_q },
		{ u"version"_q, manifest.version },
		{ u"transaction_id"_q, Hex(manifest.transactionId) },
		{ u"entries"_q, entries },
	};
	if (manifest.version == kRevocableManifestVersion) {
		object.insert(u"installation_id"_q, Hex(manifest.installationId));
	}
	return QJsonDocument(object).toJson(QJsonDocument::Compact);
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
	if (object.value(u"format"_q).toString()
			!= u"sleepygram-profile-migration"_q
		|| !object.value(u"version"_q).isDouble()) {
		return false;
	}
	const auto version = object.value(u"version"_q).toDouble();
	if (version != kStageManifestVersion
		&& version != kGenerationManifestVersion
		&& version != kRevocableManifestVersion) {
		SetError(error, MigrationError::UnsupportedVersion);
		return false;
	}
	auto keys = std::set<QString>{
		u"format"_q, u"version"_q, u"transaction_id"_q, u"entries"_q,
	};
	const auto revocable = (version == kRevocableManifestVersion);
	if (revocable) {
		keys.emplace(u"installation_id"_q);
	}
	if (!HasExactKeys(object, std::move(keys))) {
		return false;
	}
	const auto idText = object.value(u"transaction_id"_q).toString().toLatin1();
	const auto id = QByteArray::fromHex(idText);
	if (id.size() != kTransactionIdSize || id.toHex() != idText) {
		return false;
	}
	const auto array = object.value(u"entries"_q).toArray();
	if (array.size() < 2 || array.size() > 5) {
		return false;
	}
	auto parsed = Manifest{ .version = int(version), .transactionId = id };
	if (revocable) {
		const auto text = object.value(u"installation_id"_q).toString().toLatin1();
		parsed.installationId = QByteArray::fromHex(text);
		if (!ValidInstallationId(parsed.installationId) || parsed.installationId.toHex() != text) {
			return false;
		}
	}
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
			|| sizeNumber > MaximumArtifactSize(*artifact)
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
	if (!ValidArtifactLayout(parsed.version, seen)) {
		return false;
	} else if (totalSize > kMaximumSidecarSize) {
		SetError(error, MigrationError::TooLarge);
		return false;
	}
	std::sort(parsed.entries.begin(), parsed.entries.end(), [](
			const Entry &a,
			const Entry &b) {
		return a.artifact < b.artifact;
	});
	if (revocable && SerializeManifest(parsed) != bytes) {
		return false;
	}
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

bool SingleRegularLink(const QFile &file) {
#ifdef Q_OS_WIN
	const auto handle = reinterpret_cast<HANDLE>(_get_osfhandle(file.handle()));
	auto info = BY_HANDLE_FILE_INFORMATION();
	return handle != INVALID_HANDLE_VALUE && GetFileInformationByHandle(handle, &info)
		&& !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
		&& info.nNumberOfLinks == 1;
#else
	struct stat info = {};
	return fstat(file.handle(), &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1;
#endif
}

bool SingleRegularLink(const QString &path) {
	const auto info = QFileInfo(path);
	if (!info.isFile() || info.isSymLink() || info.isJunction()) {
		return false;
	}
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) && SingleRegularLink(file);
}

std::optional<QByteArray> ReadBounded(
		const QString &path,
		qsizetype maximum,
		bool singleLink = false) {
	const auto info = QFileInfo(path);
	if (!info.exists() || !info.isFile() || info.isSymLink() || info.isJunction()) {
		return std::nullopt;
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly) || (singleLink && !SingleRegularLink(file))) {
		return std::nullopt;
	}
	const auto size = file.size();
	if (size < 1 || size > maximum) {
		return std::nullopt;
	}
	const auto bytes = file.read(maximum + 1);
	return (file.error() == QFileDevice::NoError
			&& file.atEnd()
		&& bytes.size() == size && (!singleLink || SingleRegularLink(file)))
		? std::optional<QByteArray>(bytes)
		: std::nullopt;
}

std::optional<RevocableHead> ReadRevocableHead(const QString &root) {
	const auto bytes = ReadBounded(ManifestPath(root, kRevocableHeadName), kMaximumHeadSize);
	const auto firstProof = kRevocableHeadMagic.size() + 1 + kInstallationIdSize;
	if (!bytes || bytes->size() < firstProof + kGenerationProofSize
		|| !bytes->startsWith(kRevocableHeadMagic)) {
		return std::nullopt;
	}
	const auto state = RevocableHeadState(bytes->at(kRevocableHeadMagic.size()));
	const auto pending = (state == RevocableHeadState::Pending);
	if ((!pending && state != RevocableHeadState::Retiring && state != RevocableHeadState::Retired)
		|| bytes->size() != firstProof + (pending ? 2 : 1) * kGenerationProofSize) {
		return std::nullopt;
	}
	auto result = RevocableHead{
		.state = state,
		.installationId = bytes->mid(firstProof - kInstallationIdSize, kInstallationIdSize),
		.current = {
			bytes->mid(firstProof, kTransactionIdSize),
			bytes->mid(firstProof + kTransactionIdSize, kManifestDigestSize),
		},
	};
	if (pending) {
		const auto next = firstProof + kGenerationProofSize;
		result.candidate = {
			bytes->mid(next, kTransactionIdSize),
			bytes->mid(next + kTransactionIdSize, kManifestDigestSize),
		};
	}
	return ValidInstallationId(result.installationId)
		&& (!pending || result.current.transactionId != result.candidate.transactionId)
		? std::optional(std::move(result))
		: std::nullopt;
}

bool PublishRevocableStateFile(const QString &root, const char *name, const QByteArray &bytes) {
	const auto temporary = ManifestPath(root, kRevocableHeadTemporaryName);
	const auto target = ManifestPath(root, name);
	const auto previous = QFileInfo(temporary);
	if (PathPresent(temporary) && (!previous.isFile() || previous.isSymLink()
		|| previous.isJunction() || !QFile::remove(temporary))) {
		return false;
	}
	return WriteNewFile(temporary, bytes)
		&& PublishManifest(temporary, target)
		&& SyncDirectory(root);
}

bool PublishRevocableHead(const QString &root, const RevocableHead &head) {
	auto bytes = kRevocableHeadMagic.toByteArray();
	bytes.append(char(head.state));
	bytes.append(head.installationId);
	bytes.append(head.current.transactionId);
	bytes.append(head.current.manifestDigest);
	if (head.state == RevocableHeadState::Pending) {
		bytes.append(head.candidate.transactionId);
		bytes.append(head.candidate.manifestDigest);
	}
	return PublishRevocableStateFile(root, kRevocableHeadName, bytes);
}

bool EnsureRevocableFloor(const QString &root, const QByteArray &installationId) {
	const auto path = ManifestPath(root, kRevocableFloorName);
	const auto bytes = kRevocableFloorMagic.toByteArray() + installationId;
	return PathPresent(path)
		? ReadBounded(path, kRevocableFloorSize) == bytes && SyncDirectory(root)
		: PublishRevocableStateFile(root, kRevocableFloorName, bytes);
}

bool AnchorRevocableGeneration(const QString &root, const RevocableHead &head) {
	return EnsureRevocableFloor(root, head.installationId) && PublishRevocableHead(root, head);
}

bool RetiredArtifactInventory(const QString &root, const Manifest &active) {
	const auto directory = ManifestPath(root, kGenerationsDirectoryName);
	const auto entries = QDir(directory).entryList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
	return entries == QStringList{ Hex(active.transactionId) }
		&& !PathPresent(ManifestPath(root, kStageDirectoryName))
		&& !PathPresent(ManifestPath(root, kPendingManifestName))
		&& !PathPresent(ManifestPath(root, kSetupDraftName));
}

bool CheckRevocableHead(
		const QString &root,
		const Manifest &manifest,
		const MigrationGenerationProof &proof,
		bool &retirementPending) {
	retirementPending = false;
	const auto typed = (manifest.version == kRevocableManifestVersion);
	const auto floorPath = ManifestPath(root, kRevocableFloorName);
	const auto hasFloor = PathPresent(floorPath);
	if (hasFloor && (!typed || ReadBounded(floorPath, kRevocableFloorSize)
		!= kRevocableFloorMagic.toByteArray() + manifest.installationId)) {
		return false;
	}
	if (!PathPresent(ManifestPath(root, kRevocableHeadName))) {
		return !typed && !hasFloor;
	}
	const auto head = ReadRevocableHead(root);
	if (!head || (typed && manifest.installationId != head->installationId)) {
		return false;
	}
	if (head->state == RevocableHeadState::Pending) {
		retirementPending = (proof == head->candidate);
		return (proof == head->current && (!typed || hasFloor)) || (typed && retirementPending);
	}
	if (!typed || !hasFloor || proof != head->current) {
		return false;
	}
	retirementPending = (head->state == RevocableHeadState::Retiring)
		|| !RetiredArtifactInventory(root, manifest);
	return true;
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
			&& (manifest.version != kStageManifestVersion
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
		QString::fromLatin1(kRevocableHeadName),
		QString::fromLatin1(kRevocableHeadTemporaryName),
		QString::fromLatin1(kRevocableFloorName),
	};
	const auto generations = ManifestPath(root, kGenerationsDirectoryName);
	if (PathPresent(generations)
		&& CanonicalDirectory(generations) != generations) {
		return false;
	}
	if (profile) {
		const auto accounts = ManifestPath(root, kAccountsDirectoryName);
		const auto cutover = ManifestPath(root, kCutoverDirectoryName);
		const auto settings = ManifestPath(root, kSettingsDirectoryName);
		const auto journal = ManifestPath(root, kEmergencyJournalName);
		if (CanonicalDirectory(accounts) != accounts
			|| (PathPresent(settings) && CanonicalDirectory(settings) != settings)
			|| (PathPresent(journal) && CanonicalDirectory(journal) != journal)
			|| (PathPresent(cutover) && CanonicalDirectory(cutover) != cutover)) {
			return false;
		}
		allowed.emplace(QString::fromLatin1(kAccountsDirectoryName));
		allowed.emplace(QString::fromLatin1(kSettingsDirectoryName));
		allowed.emplace(QString::fromLatin1(kEmergencyJournalName));
		allowed.emplace(QString::fromLatin1(kCutoverDirectoryName));
		allowed.emplace(QString::fromLatin1(kSetupDraftName));
	}
	for (const auto &entry : entries) {
		if (entry.isSymLink() || entry.isJunction()
			|| !allowed.contains(entry.fileName())) {
			return false;
		}
	}
	return true;
}

bool ValidateArtifactFiles(const QString &directory, const Manifest &manifest) {
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
	auto expected = QStringList();
	for (const auto &entry : manifest.entries) {
		expected.push_back(ArtifactFileName(entry.artifact));
	}
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
		QByteArray transactionId,
		MigrationError *error,
		const QByteArray &installationId = {}) {
	SetError(error, MigrationError::InvalidInput);
	if (inputs.size() < 2 || inputs.size() > 5
		|| (!transactionId.isEmpty() && transactionId.size() != kTransactionIdSize)
		|| ((version == kRevocableManifestVersion) != ValidInstallationId(installationId))) {
		return std::nullopt;
	}
	auto manifest = Manifest{ .version = version, .installationId = installationId };
	auto artifacts = std::set<MigrationArtifact>();
	auto total = qsizetype(0);
	for (const auto &input : inputs) {
		const auto size = input.encryptedBytes.size();
		if (ArtifactName(input.artifact).isEmpty()
			|| size < 1 || size > MaximumArtifactSize(input.artifact)
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
	if (!ValidArtifactLayout(version, artifacts)
		|| total > kMaximumSidecarSize) {
		return std::nullopt;
	}
	std::sort(manifest.entries.begin(), manifest.entries.end(), [](
			const Entry &a,
			const Entry &b) {
		return a.artifact < b.artifact;
	});
	manifest.transactionId = transactionId.isEmpty()
		? MigrationController::NewTransactionId()
		: std::move(transactionId);
	if (manifest.transactionId.isEmpty()) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	for (const auto &input : inputs) {
		if (!ValidRevocableArtifact(manifest, input.artifact, input.encryptedBytes)) {
			return std::nullopt;
		}
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
	if (!ValidateArtifactFiles(directory, manifest)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	auto result = CommittedMigration{
		.transactionId = manifest.transactionId,
		.layout = (manifest.version == kRevocableManifestVersion)
			? MigrationGenerationLayout::RevocableGates
			: MigrationGenerationLayout::LegacyKeys,
		.installationId = manifest.installationId,
	};
	for (const auto &entry : manifest.entries) {
		auto bytes = ReadBounded(
			ArtifactPath(directory, entry.artifact),
			MaximumArtifactSize(entry.artifact),
			true);
		if (!bytes || quint64(bytes->size()) != entry.size
			|| Digest(*bytes) != entry.digest
			|| !ValidRevocableArtifact(manifest, entry.artifact, *bytes)) {
			SetError(error, MigrationError::ReadbackFailed);
			return std::nullopt;
		}
		if (entry.artifact == MigrationArtifact::ProfileVault) {
			result.profileVault = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::AccountKeyring) {
			result.accountKeyring = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::LegacyRetirement) {
			result.legacyRetirement = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::EmergencyRules) {
			result.emergencyRules = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::EmergencyRecovery) {
			result.emergencyRecovery = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::AccountGateTable) {
			result.accountGateTable = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::RevocableEmergencyRules) {
			result.revocableEmergencyRules = std::move(*bytes);
		} else if (entry.artifact == MigrationArtifact::RevocableEmergencyRecovery) {
			result.revocableEmergencyRecovery = std::move(*bytes);
		} else {
			SetError(error, MigrationError::InvalidManifest);
			return std::nullopt;
		}
	}
	const auto vault = QByteArrayView(result.profileVault);
	const auto gates = QByteArrayView(result.accountGateTable);
	const auto typed = (result.layout == MigrationGenerationLayout::RevocableGates);
	const auto bound = [&](QByteArrayView bytes, QByteArrayView prefix) {
		return bytes.startsWith(prefix)
			&& bytes.size() >= prefix.size() + kInstallationIdSize
			&& bytes.sliced(prefix.size(), kInstallationIdSize) == result.installationId;
	};
	if (typed
			? (!bound(vault, kRevocableVaultMagic) || !bound(gates, kAccountGateTableMagic))
			: (vault.isEmpty() || result.accountKeyring.isEmpty()
				|| vault.startsWith(kRevocableVaultMagic))) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	if (!result.legacyRetirement.isEmpty()
		&& (!result.emergencyRules.isEmpty() || !result.emergencyRecovery.isEmpty())) {
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
	if (!manifest) {
		return std::nullopt;
	}
	auto result = ReadArtifacts(root, *manifest, error);
	if (!result) {
		return std::nullopt;
	}
	result->manifestDigest = Digest(*manifestBytes);
	if (committed && !CheckRevocableHead(
			root, *manifest, result->proof(), result->retirementPending)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	return result;
}

std::optional<Manifest> ReadExpectedGeneration(
		const QString &root,
		const QByteArray &manifestBytes,
		const MigrationGenerationProof &expected,
		bool profile,
		MigrationError *error,
		bool *retirementPending = nullptr) {
	if (expected.transactionId.size() != kTransactionIdSize
		|| (!expected.manifestDigest.isEmpty()
			&& expected.manifestDigest.size() != kManifestDigestSize)) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	auto manifest = ReadManifest(manifestBytes, true, error);
	if (!manifest) {
		return std::nullopt;
	} else if (profile && !ActiveMatchesProfilePhase(root, *manifest)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	const auto proof = MigrationGenerationProof{ manifest->transactionId, Digest(manifestBytes) };
	auto retiring = false;
	if (!CheckRevocableHead(root, *manifest, proof, retiring)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	} else if (proof.transactionId != expected.transactionId
		|| (!expected.manifestDigest.isEmpty() && proof.manifestDigest != expected.manifestDigest)) {
		SetError(error, MigrationError::StaleGeneration);
		return std::nullopt;
	}
	if (retirementPending) {
		*retirementPending = retiring;
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
		const auto name = entry.fileName();
		const auto artifact = name.endsWith(u".bin"_q)
			? ParseArtifactName(name.chopped(4))
			: std::nullopt;
		if (entry.isSymLink() || entry.isJunction() || !entry.isFile()
			|| !artifact || name != ArtifactFileName(*artifact)
			|| !SingleRegularLink(entry.absoluteFilePath())) {
			return false;
		}
	}
	for (const auto &entry : entries) {
		if (!SingleRegularLink(entry.absoluteFilePath()) || !QFile::remove(entry.absoluteFilePath())) {
			return false;
		}
	}
	return QDir().rmdir(directory);
}

bool RollbackUnpublishedRevocable(
		const QString &root,
		const Manifest &active,
		const QByteArray &activeBytes) {
	const auto head = ReadRevocableHead(root);
	const auto parent = ManifestPath(root, kGenerationsDirectoryName);
	if (active.version == kRevocableManifestVersion
		|| PathPresent(ManifestPath(root, kRevocableFloorName))
		|| !head || head->state != RevocableHeadState::Pending
		|| head->current != MigrationGenerationProof{ active.transactionId, Digest(activeBytes) }
		|| CanonicalDirectory(parent) != parent) {
		return false;
	}
	const auto directory = QDir(parent).filePath(Hex(head->candidate.transactionId));
	const auto temporary = TemporaryManifestPath(root, head->candidate.transactionId);
	const auto hasTemporary = PathPresent(temporary);
	if (hasTemporary) {
		const auto bytes = ReadBounded(temporary, kMaximumManifestSize, true);
		const auto manifest = bytes && Digest(*bytes) == head->candidate.manifestDigest
			? ReadManifest(*bytes, true, nullptr) : std::nullopt;
		if (!manifest || manifest->version != kRevocableManifestVersion
			|| manifest->transactionId != head->candidate.transactionId
			|| manifest->installationId != head->installationId) {
			return false;
		}
		if (PathPresent(directory)) {
			if (CanonicalDirectory(directory) != directory) {
				return false;
			}
			const auto entries = QDir(directory).entryInfoList(
				QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
			for (const auto &entry : entries) {
				const auto name = entry.fileName();
				const auto artifact = name.endsWith(u".bin"_q)
					? ParseArtifactName(name.chopped(4)) : std::nullopt;
				const auto expected = artifact ? FindEntry(*manifest, *artifact) : nullptr;
				const auto contents = expected
					? ReadBounded(entry.absoluteFilePath(), MaximumArtifactSize(*artifact), true)
					: std::nullopt;
				if (!contents || quint64(contents->size()) != expected->size
					|| Digest(*contents) != expected->digest) {
					return false;
				}
			}
		}
	} else if (PathPresent(directory)) {
		return false;
	}
	return RemoveGenerationDirectory(directory)
		&& (!hasTemporary || QFile::remove(temporary))
		&& SyncDirectory(parent)
		&& ReadBounded(ManifestPath(root, kCommittedManifestName), kMaximumManifestSize) == activeBytes
		&& QFile::remove(ManifestPath(root, kRevocableHeadName))
		&& SyncDirectory(root);
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
		if (active.version != kStageManifestVersion && name == activeName) {
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
		MigrationError *error,
		QByteArray transactionId) const {
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
	if ((PathPresent(ManifestPath(_root, kGenerationsDirectoryName))
		|| HasRevocableState(_root))
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
	const auto manifest = PrepareManifest(
		inputs, kStageManifestVersion, std::move(transactionId), error);
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
		MigrationError *error,
		QByteArray transactionId) const {
	return replaceCommitted({ expectedTransactionId, {} }, {},
		inputs, verify, error, std::move(transactionId));
}

std::optional<CommittedMigration> MigrationController::ReplaceRevocableCommitted(
		const MigrationGenerationProof &expected,
		const QByteArray &installationId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error,
		QByteArray transactionId) const {
	if (!ValidProof(expected) || !ValidInstallationId(installationId)) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	return replaceCommitted(expected, installationId, inputs, verify, error,
		std::move(transactionId));
}

std::optional<CommittedMigration> MigrationController::replaceCommitted(
		const MigrationGenerationProof &expected,
		const QByteArray &installationId,
		const std::vector<MigrationInput> &inputs,
		const Verifier &verify,
		MigrationError *error,
		QByteArray transactionId) const {
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
	const auto typed = !installationId.isEmpty();
	const auto headPath = ManifestPath(_root, kRevocableHeadName);
	const auto existingHead = ReadBounded(headPath, kMaximumHeadSize);
	auto retiring = false;
	const auto active = ReadExpectedGeneration(
		_root,
		existing.value_or(QByteArray()),
		expected,
		!isIsolatedFixture(),
		error,
		&retiring);
	if (!active) {
		return std::nullopt;
	}
	const auto head = ReadRevocableHead(_root);
	if (retiring) {
		SetError(error, MigrationError::RevocableRetirementRequired);
		return std::nullopt;
	}
	if ((typed && head && head->installationId != installationId)
		|| (!typed && HasRevocableState(_root))) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	if (typed && active->version != kRevocableManifestVersion
		&& std::ranges::any_of(active->entries, [](const Entry &entry) {
			return entry.artifact == MigrationArtifact::EmergencyRules
				|| entry.artifact == MigrationArtifact::EmergencyRecovery
				|| entry.artifact == MigrationArtifact::LegacyRetirement;
		})) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	const auto manifest = PrepareManifest(
		inputs,
		typed ? kRevocableManifestVersion : kGenerationManifestVersion,
		std::move(transactionId),
		error,
		installationId);
	if (!manifest) {
		return std::nullopt;
	}
	if (FindEntry(*active, MigrationArtifact::RevocableEmergencyRecovery)
		&& (FindEntry(*manifest, MigrationArtifact::RevocableEmergencyRecovery)
			|| !MatchesEntry(*active, *manifest, MigrationArtifact::ProfileVault)
			|| !MatchesEntry(*active, *manifest, MigrationArtifact::AccountGateTable)
			|| !MatchesEntry(*active, *manifest, MigrationArtifact::RevocableEmergencyRules))) {
		SetError(error, MigrationError::RevocableRecoveryRequired);
		return std::nullopt;
	}
	const auto next = SerializeManifest(*manifest);
	const auto nextProof = MigrationGenerationProof{ manifest->transactionId, Digest(next) };
	const auto parent = ManifestPath(_root, kGenerationsDirectoryName);
	const auto directory = ArtifactsDirectory(_root, *manifest);
	const auto temporary = TemporaryManifestPath(_root, manifest->transactionId);
	SetError(error, MigrationError::WorkspaceIo);
	if (manifest->transactionId == expected.transactionId
		|| (!PathPresent(parent)
			&& !QDir(_root).mkdir(QString::fromLatin1(kGenerationsDirectoryName)))
		|| CanonicalDirectory(parent) != parent) {
		return std::nullopt;
	}
	const auto retry = typed && head && head->state == RevocableHeadState::Pending
		&& head->current == expected && head->candidate == nextProof;
	if (retry) {
		const auto tempInfo = QFileInfo(temporary);
		if (!RemoveGenerationDirectory(directory)
			|| (PathPresent(temporary) && (!tempInfo.isFile() || tempInfo.isSymLink()
				|| tempInfo.isJunction() || !QFile::remove(temporary)))) {
			return std::nullopt;
		}
	}
	if (!QDir(parent).mkdir(Hex(manifest->transactionId))) {
		return std::nullopt;
	}
	auto published = false;
	const auto cleanup = gsl::finally([&] {
		if (!published && CanonicalDirectory(parent) == parent
			&& ReadBounded(activePath, kMaximumManifestSize) == existing
			&& RemoveGenerationDirectory(directory)) {
			QFile::remove(temporary);
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
		auto staged = ReadArtifacts(_root, *manifest, error);
		if (!staged) {
			return std::nullopt;
		}
		staged->manifestDigest = nextProof.manifestDigest;
		staged->retirementPending = typed;
		if (!verify(*staged)) {
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
	if (existing != stillActive || ReadBounded(headPath, kMaximumHeadSize) != existingHead) {
		SetError(error, MigrationError::StaleGeneration);
		return std::nullopt;
	}
	if (typed && !ReadExpectedGeneration(
			_root, *existing, expected, !isIsolatedFixture(), error)) {
		return std::nullopt;
	}
	if (next.isEmpty() || next.size() > kMaximumManifestSize
		|| !WriteNewFile(temporary, next)
		|| !SyncDirectory(directory)
		|| !SyncDirectory(parent)
		|| !SyncDirectory(_root)) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	if (typed && !PublishRevocableHead(_root, {
			.state = RevocableHeadState::Pending,
			.installationId = installationId,
			.current = expected,
			.candidate = nextProof,
		})) {
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
	if (!SyncDirectory(_root)
		|| (typed && !AnchorRevocableGeneration(_root, {
			.state = RevocableHeadState::Retiring,
			.installationId = installationId,
			.current = nextProof,
		}))) {
		SetError(error, MigrationError::PublicationUncertain);
		return std::nullopt;
	}
	checked->manifestDigest = nextProof.manifestDigest;
	checked->retirementPending = typed;
	SetError(error, MigrationError::None);
	return checked;
}

bool MigrationController::RetireInactiveGenerations(
		const QByteArray &expectedTransactionId,
		MigrationError *error) const {
	return retireInactiveGenerations({ expectedTransactionId, {} }, false, error);
}

bool MigrationController::RetireRevocableGenerations(
		const MigrationGenerationProof &expected,
		MigrationError *error) const {
	if (!ValidProof(expected)) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	}
	return retireInactiveGenerations(expected, true, error);
}

bool MigrationController::retireInactiveGenerations(
		const MigrationGenerationProof &expected,
		bool revocable,
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
		expected,
		!isIsolatedFixture(),
		error);
	if (!active) {
		return false;
	}
	const auto typed = (active->version == kRevocableManifestVersion);
	if (typed != revocable) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	}
	if (!typed && HasRevocableState(_root)) {
		const auto restored = RollbackUnpublishedRevocable(_root, *active, *activeBytes);
		SetError(error, restored ? MigrationError::None : MigrationError::RetirementFailed);
		return restored;
	}
	auto head = RevocableHead{
		.state = RevocableHeadState::Retiring,
		.installationId = active->installationId,
		.current = expected,
	};
	if (typed && !AnchorRevocableGeneration(_root, head)) {
		SetError(error, MigrationError::RetirementFailed);
		return false;
	}
	if (!SyncDirectory(_root) || !RemoveInactiveGenerations(_root, *active)) {
		SetError(error, MigrationError::RetirementFailed);
		return false;
	}
	if (active->version != kStageManifestVersion) {
		const auto stage = ManifestPath(_root, kStageDirectoryName);
		const auto pending = ManifestPath(_root, kPendingManifestName);
		const auto draft = ManifestPath(_root, kSetupDraftName);
		if (!RemoveGenerationDirectory(stage)
			|| (PathPresent(pending) && !QFile::remove(pending))
			|| (!isIsolatedFixture() && PathPresent(draft)
				&& (!SingleRegularLink(draft) || !QFile::remove(draft)))
			|| !SyncDirectory(_root)) {
			SetError(error, MigrationError::RetirementFailed);
			return false;
		}
		if (typed) {
			if (!RetiredArtifactInventory(_root, *active)
				|| ReadBounded(activePath, kMaximumManifestSize) != activeBytes
				|| !ReadExpectedGeneration(
					_root, *activeBytes, expected, !isIsolatedFixture(), error)) {
				SetError(error, MigrationError::RetirementFailed);
				return false;
			}
		}
	}
	if (typed) {
		head.state = RevocableHeadState::Retired;
		if (!PublishRevocableHead(_root, head)) {
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
	if (PathPresent(ManifestPath(_root, kGenerationsDirectoryName))
		|| HasRevocableState(_root)) {
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
		|| checked->legacyRetirement != staged->legacyRetirement
		|| checked->emergencyRules != staged->emergencyRules
		|| checked->emergencyRecovery != staged->emergencyRecovery
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
	if (PathPresent(ManifestPath(_root, kGenerationsDirectoryName))
		|| HasRevocableState(_root)) {
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
			|| HasRevocableState(_root)
			|| (profile && (!phase || phase->phase != ProfilePhase::Preparing
				|| PathPresent(ManifestPath(_root, kCutoverDirectoryName))));
		SetError(error, unavailable
			? MigrationError::InvalidManifest
			: MigrationError::NotStaged);
		return std::nullopt;
	}
	return readManifest(kCommittedManifestName, error);
}

std::optional<CommittedMigration> MigrationController::LoadStaged(
		MigrationError *error) const {
	if (isIsolatedFixture() || !validateWorkspace()
		|| PathPresent(ManifestPath(_root, kCommittedManifestName))
		|| HasRevocableState(_root)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	const auto phase = ReadProfilePhase(_root);
	auto staged = readManifest(kPendingManifestName, error);
	if (!phase || !staged
		|| phase->phase == ProfilePhase::LegacyFormat
		|| (phase->phase == ProfilePhase::CutoverStarted
			&& phase->initialTransactionId != staged->transactionId)) {
		return std::nullopt;
	}
	return staged;
}

bool MigrationController::StoreSetupDraft(const CommittedMigration &draft) const {
	const auto vaultSize = draft.profileVault.size();
	const auto keyringSize = draft.accountKeyring.size();
	if (draft.transactionId.size() != kTransactionIdSize
		|| draft.layout != MigrationGenerationLayout::LegacyKeys
		|| !draft.installationId.isEmpty() || !draft.accountGateTable.isEmpty()
		|| !draft.revocableEmergencyRules.isEmpty() || !draft.revocableEmergencyRecovery.isEmpty()
		|| vaultSize <= 0 || vaultSize > kMaximumArtifactSize
		|| keyringSize <= 0 || keyringSize > kMaximumArtifactSize
		|| vaultSize + keyringSize > kMaximumSidecarSize
		|| !draft.legacyRetirement.isEmpty() || !draft.emergencyRules.isEmpty()
		|| !draft.emergencyRecovery.isEmpty()) {
		return false;
	}
	return WithPreparingWorkspace([&] {
		const auto path = ManifestPath(_root, kSetupDraftName);
		if (PathPresent(path)) {
			return false;
		}
		auto data = QByteArray(kSetupDraftMagic) + draft.transactionId;
		auto size = qToBigEndian(quint32(vaultSize));
		data.append(reinterpret_cast<const char*>(&size), sizeof(size));
		data.append(draft.profileVault);
		data.append(draft.accountKeyring);
		return WriteAtomic(path, data) && SyncDirectory(_root);
	});
}

std::optional<CommittedMigration> MigrationController::LoadSetupDraft() const {
	if (isIsolatedFixture() || !validateWorkspace()
		|| PathPresent(ManifestPath(_root, kCommittedManifestName))
		|| HasRevocableState(_root)) {
		return std::nullopt;
	}
	const auto magic = QByteArrayView(kSetupDraftMagic);
	const auto boundary = magic.size() + kTransactionIdSize;
	const auto payload = boundary + qsizetype(sizeof(quint32));
	const auto data = ReadBounded(
		ManifestPath(_root, kSetupDraftName), kMaximumSidecarSize + payload, true);
	if (!data || data->size() <= payload || !data->startsWith(magic)) {
		return std::nullopt;
	}
	const auto vault = qsizetype(qFromBigEndian<quint32>(data->constData() + boundary));
	const auto keyring = data->size() - payload - vault;
	if (vault <= 0 || vault > kMaximumArtifactSize
		|| keyring <= 0 || keyring > kMaximumArtifactSize) {
		return std::nullopt;
	}
	return CommittedMigration{
		.transactionId = data->mid(magic.size(), kTransactionIdSize),
		.profileVault = data->mid(payload, vault),
		.accountKeyring = data->right(keyring),
	};
}

QByteArray MigrationController::NewTransactionId() {
	auto id = QByteArray(kTransactionIdSize, Qt::Uninitialized);
	return (RAND_bytes(reinterpret_cast<unsigned char*>(id.data()), int(id.size())) == 1)
		? id
		: QByteArray();
}

bool MigrationController::WithCurrentGeneration(
		const QByteArray &expectedTransactionId,
		const std::function<bool()> &callback,
		MigrationError *error) const {
	if (!callback) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	}
	return withCurrentGeneration({ expectedTransactionId, {} }, LeaseKind::Legacy,
		[&](const CommittedMigration &) { return callback(); }, error);
}

bool MigrationController::WithCurrentRevocableGeneration(
		const MigrationGenerationProof &expected,
		const Verifier &callback,
		MigrationError *error) const {
	return withCurrentGeneration(expected, LeaseKind::Revocable, callback, error);
}

bool MigrationController::WithCurrentRevocableRecovery(
		const MigrationGenerationProof &expected,
		const Verifier &callback,
		MigrationError *error) const {
	return withCurrentGeneration(expected, LeaseKind::RevocableRecovery, callback, error);
}

bool MigrationController::withCurrentGeneration(
		const MigrationGenerationProof &expected,
		LeaseKind kind,
		const Verifier &callback,
		MigrationError *error) const {
	const auto revocable = (kind != LeaseKind::Legacy);
	if (expected.transactionId.size() != kTransactionIdSize
		|| (revocable && !ValidProof(expected)) || !callback) {
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
	const auto committed = LoadCommitted(error);
	if (!committed) {
		return false;
	} else if (committed->transactionId != expected.transactionId
		|| (revocable && committed->manifestDigest != expected.manifestDigest)) {
		SetError(error, MigrationError::StaleGeneration);
		return false;
	} else if ((committed->layout == MigrationGenerationLayout::RevocableGates) != revocable) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	} else if (!committed->revocableEmergencyRecovery.isEmpty()
		&& kind != LeaseKind::RevocableRecovery) {
		SetError(error, MigrationError::RevocableRecoveryRequired);
		return false;
	} else if (kind == LeaseKind::RevocableRecovery && committed->revocableEmergencyRecovery.isEmpty()) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	} else if (committed->retirementPending) {
		SetError(error, MigrationError::RevocableRetirementRequired);
		return false;
	}
	const auto result = callback(*committed);
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

bool MigrationController::WithStagedSetup(
		const QByteArray &expectedTransactionId,
		const std::function<bool()> &callback,
		MigrationError *error) const {
	if (!callback || !validateWorkspace()) {
		SetError(error, MigrationError::UnsafeWorkspace);
		return false;
	}
	const auto lock = LockWorkspace(_root);
	if (!lock) {
		SetError(error, MigrationError::WorkspaceBusy);
		return false;
	}
	const auto staged = LoadStaged(error);
	if (!staged || staged->transactionId != expectedTransactionId) {
		SetError(error, MigrationError::StaleGeneration);
		return false;
	}
	const auto ok = callback();
	SetError(error, ok ? MigrationError::None : MigrationError::CallbackFailed);
	return ok;
}

std::optional<QString> MigrationController::PrepareScopedSettingsDirectory(
		const QByteArray &expectedTransactionId,
		SetId setId,
		MigrationError *error) const {
	if (isIsolatedFixture() || !setId) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	auto settings = std::optional<QString>();
	return WithCurrentGeneration(expectedTransactionId, [&] {
		settings = ensureScopedSettingsDirectory(setId);
		return settings.has_value();
	}, error) ? settings : std::nullopt;
}

std::optional<QString> MigrationController::PrepareRevocableScopedSettingsDirectory(
		const MigrationGenerationProof &expected,
		SetId setId,
		MigrationError *error) const {
	if (isIsolatedFixture() || !setId) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	}
	auto settings = std::optional<QString>();
	return WithCurrentRevocableGeneration(expected, [&](const CommittedMigration &) {
		settings = ensureScopedSettingsDirectory(setId);
		return settings.has_value();
	}, error) ? std::move(settings) : std::nullopt;
}

std::optional<QString> MigrationController::PrepareInitialSettingsDirectory(
		const QByteArray &expectedTransactionId,
		SetId setId) const {
	if (isIsolatedFixture() || !setId || expectedTransactionId.isEmpty()) {
		return std::nullopt;
	}
	auto settings = std::optional<QString>();
	const auto prepare = [&] {
		const auto draft = LoadSetupDraft();
		if (!draft || draft->transactionId != expectedTransactionId) {
			return false;
		}
		settings = ensureScopedSettingsDirectory(setId);
		return settings.has_value();
	};
	const auto ready = LoadStaged()
		? WithStagedSetup(expectedTransactionId, prepare)
		: WithPreparingWorkspace(prepare);
	return ready ? settings : std::nullopt;
}

std::optional<QString> MigrationController::ensureScopedSettingsDirectory(SetId setId) const {
	const auto root = ManifestPath(_root, kSettingsDirectoryName);
	const auto setName = u"%1%2"_q
		.arg(qulonglong(setId.high), 16, 16, QChar('0'))
		.arg(qulonglong(setId.low), 16, 16, QChar('0'));
	const auto path = QDir(root).filePath(setName);
	if (!PathPresent(root) && !QDir(_root).mkdir(
			QString::fromLatin1(kSettingsDirectoryName))) {
		return std::nullopt;
	} else if (CanonicalDirectory(root) != root) {
		return std::nullopt;
	}
	if (!PathPresent(path) && !QDir(root).mkdir(setName)) {
		return std::nullopt;
	}
	return (CanonicalDirectory(path) == path && SyncDirectory(root) && SyncDirectory(_root))
		? std::optional(path)
		: std::nullopt;
}

QString MigrationController::workspacePath() const {
	return _root;
}

QString MigrationController::accountStorageRoot() const {
	return (!_profileDataDirectory.isEmpty() && validateWorkspace())
		? ManifestPath(_root, kAccountsDirectoryName)
		: QString();
}

bool MigrationController::SyncScopedAccount(QStringView locator) const {
	const auto accounts = accountStorageRoot();
	if (accounts.isEmpty() || !ValidGenerationName(locator)) {
		return false;
	}
	const auto account = QDir(accounts).filePath(locator.toString());
	const auto data = QDir(account).filePath(u"data"_q);
	const auto user = QDir(account).filePath(u"user"_q);
	return CanonicalDirectory(account) == account
		&& CanonicalDirectory(data) == data && CanonicalDirectory(user) == user
		&& SyncDirectory(data) && SyncDirectory(user)
		&& SyncDirectory(account) && SyncDirectory(accounts);
}

QString MigrationController::emergencyJournalDirectory() const {
	return (!_profileDataDirectory.isEmpty() && validateWorkspace())
		? ManifestPath(_root, kEmergencyJournalName)
		: QString();
}

bool MigrationController::isIsolatedFixture() const {
	return _profileDataDirectory.isEmpty();
}

} // namespace Ayu::ProfileSets
