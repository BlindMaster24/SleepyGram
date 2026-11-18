/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_migration.h"

#include "base/basic_types.h"

#include <openssl/crypto.h>
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
#include <map>
#include <memory>
#include <set>
#include <utility>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kManifestVersion = 1;
constexpr auto kWorkspaceMarkerName = ".migration-workspace";
constexpr auto kWorkspaceMarker = "sleepygram-isolated-migration-workspace-v1\n";
constexpr auto kWorkspacePrefix = "sleepygram-migration-fixture-";
constexpr auto kProfileDirectoryName = "profile-sets";
constexpr auto kProfileMarker = "sleepygram-profile-migration-workspace-v1\n";
constexpr auto kAccountsDirectoryName = "accounts";
constexpr auto kWorkspaceLockName = "migration.lock";
constexpr auto kPendingManifestName = "migration.manifest.pending";
constexpr auto kCommittedManifestName = "migration.manifest.committed";
constexpr auto kStageDirectoryName = "stage";
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
	QByteArray transactionId;
	std::vector<Entry> entries;
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

QString ArtifactPath(const QString &root, MigrationArtifact artifact) {
	const auto directory = QDir(root).filePath(
		QString::fromLatin1(kStageDirectoryName));
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

bool PathPresent(const QString &path) {
	const auto info = QFileInfo(path);
	return info.exists() || info.isSymLink() || info.isJunction();
}

QString Hex(const QByteArray &bytes) {
	return QString::fromLatin1(bytes.toHex());
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
		{ u"version"_q, kManifestVersion },
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
	if (version != kManifestVersion) {
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
	auto parsed = Manifest{ .transactionId = id };
	auto seen = std::set<MigrationArtifact>();
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
	}
	std::sort(parsed.entries.begin(), parsed.entries.end(), [](
			const Entry &a,
			const Entry &b) {
		return a.artifact < b.artifact;
	});
	manifest->transactionId = std::move(parsed.transactionId);
	manifest->entries = std::move(parsed.entries);
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

std::optional<QByteArray> ReadBounded(
		const QString &path,
		qsizetype maximum) {
	const auto info = QFileInfo(path);
	if (!info.exists() || !info.isFile() || info.isSymLink()
		|| info.size() < 1 || info.size() > maximum) {
		return std::nullopt;
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	const auto bytes = file.read(maximum + 1);
	return (file.error() == QFileDevice::NoError
			&& file.atEnd()
			&& bytes.size() == info.size())
		? std::optional<QByteArray>(bytes)
		: std::nullopt;
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
	const auto marker = ReadBounded(
		ManifestPath(root, kWorkspaceMarkerName),
		128);
	const auto expectedMarker = profile ? kProfileMarker : kWorkspaceMarker;
	if (!marker || *marker != QByteArray(expectedMarker)) {
		return false;
	}
	const auto entries = QDir(root).entryInfoList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden);
	auto allowed = std::set<QString>{
		QString::fromLatin1(kWorkspaceMarkerName),
		QString::fromLatin1(kStageDirectoryName),
		QString::fromLatin1(kPendingManifestName),
		QString::fromLatin1(kCommittedManifestName),
		QString::fromLatin1(kWorkspaceLockName),
	};
	if (profile) {
		const auto accounts = ManifestPath(root, kAccountsDirectoryName);
		if (CanonicalDirectory(accounts) != accounts) {
			return false;
		}
		allowed.emplace(QString::fromLatin1(kAccountsDirectoryName));
	}
	for (const auto &entry : entries) {
		if (entry.isSymLink() || entry.isJunction()
			|| !allowed.contains(entry.fileName())) {
			return false;
		}
	}
	return true;
}

bool ValidateStageFiles(const QString &root) {
	const auto stagePath = QDir(root).filePath(
		QString::fromLatin1(kStageDirectoryName));
	if (CanonicalDirectory(stagePath) != stagePath) {
		return false;
	}
	const auto entries = QDir(stagePath).entryInfoList(
		QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden);
	auto names = QStringList();
	for (const auto &entry : entries) {
		if (entry.isSymLink() || !entry.isFile()) {
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

std::optional<CommittedMigration> ReadAndVerify(
		const QString &root,
		const char *manifestName,
		MigrationError *error) {
	if (!ValidateStageFiles(root)) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	const auto manifestBytes = ReadBounded(
		ManifestPath(root, manifestName),
		kMaximumManifestSize);
	if (!manifestBytes) {
		SetError(error, MigrationError::InvalidManifest);
		return std::nullopt;
	}
	auto manifest = Manifest();
	if (!ParseManifest(*manifestBytes, &manifest, error)) {
		return std::nullopt;
	}
	auto result = CommittedMigration{
		.transactionId = manifest.transactionId,
	};
	auto totalSize = qsizetype(0);
	for (const auto &entry : manifest.entries) {
		const auto bytes = ReadBounded(
			ArtifactPath(root, entry.artifact),
			kMaximumArtifactSize);
		if (!bytes || quint64(bytes->size()) != entry.size
			|| Digest(*bytes) != entry.digest) {
			SetError(error, MigrationError::ReadbackFailed);
			return std::nullopt;
		}
		totalSize += bytes->size();
		if (totalSize > kMaximumSidecarSize) {
			SetError(error, MigrationError::TooLarge);
			return std::nullopt;
		}
		if (entry.artifact == MigrationArtifact::ProfileVault) {
			result.profileVault = *bytes;
		} else if (entry.artifact == MigrationArtifact::AccountKeyring) {
			result.accountKeyring = *bytes;
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

} // namespace

MigrationController::MigrationController(QString root, QString profileDataDirectory)
: _root(std::move(root))
, _profileDataDirectory(std::move(profileDataDirectory)) {
}

std::optional<MigrationController> MigrationController::CreateProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto parent = CanonicalDirectory(dataDirectory);
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
		|| !WriteAtomic(
			ManifestPath(root, kWorkspaceMarkerName),
			QByteArray(kProfileMarker))) {
		SetError(error, MigrationError::WorkspaceIo);
		return std::nullopt;
	}
	return OpenProfileWorkspace(parent, error);
}

std::optional<MigrationController> MigrationController::OpenProfileWorkspace(
		const QString &dataDirectory,
		MigrationError *error) {
	SetError(error, MigrationError::UnsafeWorkspace);
	const auto parent = CanonicalDirectory(dataDirectory);
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
	const auto parent = CanonicalDirectory(dataDirectory);
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
	return ReadAndVerify(_root, name, error);
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
	if (QFileInfo::exists(ManifestPath(_root, kCommittedManifestName))
		|| QFileInfo::exists(ManifestPath(_root, kPendingManifestName))
		|| QFileInfo::exists(QDir(_root).filePath(
			QString::fromLatin1(kStageDirectoryName)))) {
		SetError(error, MigrationError::AlreadyStaged);
		return false;
	}
	if (inputs.size() != 2) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	}
	auto byArtifact = std::map<MigrationArtifact, QByteArray>();
	auto totalSize = qsizetype(0);
	for (const auto &input : inputs) {
		if (ArtifactName(input.artifact).isEmpty()
			|| input.encryptedBytes.isEmpty()
			|| input.encryptedBytes.size() > kMaximumArtifactSize
			|| !byArtifact.emplace(input.artifact, input.encryptedBytes).second) {
			SetError(error, MigrationError::InvalidInput);
			return false;
		}
		totalSize += input.encryptedBytes.size();
	}
	if (byArtifact.size() != 2 || totalSize > kMaximumSidecarSize) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	}
	if (!QDir(_root).mkdir(QString::fromLatin1(kStageDirectoryName))) {
		SetError(error, MigrationError::WorkspaceIo);
		return false;
	}
	auto manifest = Manifest();
	manifest.transactionId = QByteArray(kTransactionIdSize, Qt::Uninitialized);
	if (RAND_bytes(
		reinterpret_cast<unsigned char*>(manifest.transactionId.data()),
		int(manifest.transactionId.size())) != 1) {
		OPENSSL_cleanse(manifest.transactionId.data(), manifest.transactionId.size());
		SetError(error, MigrationError::WorkspaceIo);
		return false;
	}
	for (const auto artifact : {
			MigrationArtifact::ProfileVault,
			MigrationArtifact::AccountKeyring,
		}) {
		const auto &bytes = byArtifact.at(artifact);
		manifest.entries.push_back({
			.artifact = artifact,
			.size = quint64(bytes.size()),
			.digest = Digest(bytes),
		});
		if (!WriteAtomic(ArtifactPath(_root, artifact), bytes)) {
			SetError(error, MigrationError::WorkspaceIo);
			return false;
		}
	}
	const auto pending = SerializeManifest(manifest);
	if (pending.isEmpty() || pending.size() > kMaximumManifestSize
		|| !WriteAtomic(ManifestPath(_root, kPendingManifestName), pending)) {
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
	if (QFileInfo::exists(ManifestPath(_root, kCommittedManifestName))) {
		return LoadCommitted(error);
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
	if (verify && !verify(*staged)) {
		SetError(error, MigrationError::VerificationFailed);
		return std::nullopt;
	}
	const auto checked = readManifest(kPendingManifestName, error);
	if (!pending || !checked || checked->transactionId != staged->transactionId
		|| checked->profileVault != staged->profileVault
		|| checked->accountKeyring != staged->accountKeyring
		|| pending != ReadBounded(pendingPath, kMaximumManifestSize)) {
		SetError(error, MigrationError::ReadbackFailed);
		return std::nullopt;
	}
	if (!WriteAtomic(
			ManifestPath(_root, kCommittedManifestName),
			*pending)) {
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
	if (QFileInfo::exists(ManifestPath(_root, kCommittedManifestName))) {
		return LoadCommitted(error)
			? MigrationState::Committed
			: MigrationState::Invalid;
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
	if (!QFileInfo::exists(ManifestPath(_root, kCommittedManifestName))) {
		SetError(error, MigrationError::NotStaged);
		return std::nullopt;
	}
	return readManifest(kCommittedManifestName, error);
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
