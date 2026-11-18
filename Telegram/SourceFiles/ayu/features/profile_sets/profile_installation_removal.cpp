// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_installation_removal.h"

#include "ayu/features/emergency_actions/emergency_recovery_record.h"
#include "ayu/features/emergency_actions/installation_data_cleanup.h"
#include "ayu/features/profile_sets/profile_migration.h"
#include "base/basic_types.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcess>

#include <algorithm>
#include <cstring>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;
constexpr auto kMaxArtifactBytes = qint64(2) * 1024 * 1024 * 1024;

bool IsRegularOwnedPath(const QFileInfo &info) {
	return info.isFile() && !info.isSymLink() && !info.isJunction()
		&& info.canonicalFilePath() == info.absoluteFilePath();
}

std::optional<EA::InstallationArtifactDigest> Fingerprint(const QString &fileName) {
	const auto info = QFileInfo(fileName);
	if (!IsRegularOwnedPath(info) || info.size() <= 0 || info.size() > kMaxArtifactBytes) {
		return std::nullopt;
	}
	auto file = QFile(fileName);
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	if (!file.open(QIODevice::ReadOnly) || !hash.addData(&file) || file.size() != info.size()) {
		return std::nullopt;
	}
	const auto output = hash.result();
	auto digest = EA::InstallationArtifactDigest();
	std::memcpy(digest.data(), output.data(), digest.size());
	return digest;
}

QJsonObject ReadManifest(const QString &path, QStringView platform) {
	const auto info = QFileInfo(path);
	constexpr auto kManifestLimit = qint64(1024 * 1024);
	if (!IsRegularOwnedPath(info) || info.size() > kManifestLimit) {
		return {};
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return {};
	}
	const auto json = QJsonDocument::fromJson(file.read(kManifestLimit)).object();
	return (json.value(u"schema_version"_q).toInt() == 1
		&& json.value(u"platform"_q).toString() == platform) ? json : QJsonObject();
}

struct Layout final {
	EA::InstallationPackageKind kind = EA::InstallationPackageKind::Unknown;
	QString root;
	QString helper;
	QStringList files;
};

std::optional<Layout> InspectLayout(const QString &executable) {
	const auto file = QFileInfo(executable);
	if (!IsRegularOwnedPath(file)) {
		return std::nullopt;
	}
	auto layout = Layout();
#if defined Q_OS_MACOS
	layout = {
		.kind = EA::InstallationPackageKind::MacBundle,
		.root = QDir::cleanPath(file.absolutePath() + u"/../.."_q),
		.helper = u"Contents/Helpers/SleepyGramRemovalHelper"_q,
	};
	const auto manifest = ReadManifest(layout.root + u"/Contents/Resources/BuildManifest.json"_q, u"macos-arm64");
	const auto inventory = manifest.value(u"package"_q).toObject().value(u"removal_inventory"_q).toArray();
	if (executable != layout.root + u"/Contents/MacOS/SleepyGram"_q || inventory.isEmpty()) {
		return std::nullopt;
	}
	auto signature = QProcess();
	signature.start(u"/usr/bin/codesign"_q, { u"--verify"_q, u"--deep"_q, u"--strict"_q, layout.root });
	if (!signature.waitForFinished(30000) || signature.exitStatus() != QProcess::NormalExit
		|| signature.exitCode() != 0) {
		return std::nullopt;
	}
	for (const auto &file : inventory) {
		const auto path = file.toString();
		if (!path.startsWith(u"Contents/"_q) || QDir::cleanPath(path) != path
			|| layout.files.contains(path)) {
			return std::nullopt;
		}
		layout.files.push_back(path);
	}
	auto scan = QDirIterator(layout.root,
		QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
		QDirIterator::Subdirectories);
	while (scan.hasNext()) {
		scan.next();
		const auto entry = scan.fileInfo();
		if (entry.isSymLink() || entry.isJunction()
			|| entry.canonicalFilePath() != entry.absoluteFilePath()
			|| (!entry.isDir() && !entry.isFile())) {
			return std::nullopt;
		}
		if (entry.isFile() && !layout.files.contains(entry.absoluteFilePath().sliced(layout.root.size() + 1))) {
			return std::nullopt;
		}
	}
#elif defined Q_OS_WIN
	layout = {
		.kind = EA::InstallationPackageKind::WindowsPortable,
		.root = file.absolutePath(),
		.helper = u"SleepyGramRemovalHelper.exe"_q,
		.files = { u"SleepyGram.exe"_q, u"build-manifest.json"_q, u"LICENSE-SQLCipher.txt"_q },
	};
	if (file.fileName() != layout.files.front()
		|| ReadManifest(layout.root + u"/build-manifest.json"_q, u"windows-x64").isEmpty()) {
		return std::nullopt;
	}
	for (const auto &path : { u"Updater.exe"_q, u"modules/x64/d3d/d3dcompiler_47.dll"_q }) {
		const auto info = QFileInfo(QDir(layout.root).filePath(path));
		if (info.exists() || info.isSymLink() || info.isJunction()) {
			layout.files.push_back(path);
		}
	}
	layout.files.push_back(layout.helper);
#else
	layout = {
		.kind = EA::InstallationPackageKind::LinuxPortable,
		.root = file.absolutePath(),
		.helper = u"SleepyGramRemovalHelper"_q,
		.files = { u"SleepyGram"_q, u"build-manifest.json"_q, u"LICENSE-SQLCipher.txt"_q },
	};
	if (file.fileName() != layout.files.front()
		|| ReadManifest(layout.root + u"/build-manifest.json"_q, u"linux-x64").isEmpty()) {
		return std::nullopt;
	}
	const auto updater = QFileInfo(layout.root + u"/Updater"_q);
	if (updater.exists() || updater.isSymLink()) {
		layout.files.push_back(u"Updater"_q);
	}
	layout.files.push_back(layout.helper);
#endif
	std::ranges::sort(layout.files);
	return layout;
}

} // namespace

std::optional<ApprovedRemovalPackage> ReadRemovalPackage(
		const MigrationController &workspace,
		const EA::InstallationId &installation) {
	const auto layout = InspectLayout(QCoreApplication::applicationFilePath());
	const auto dataDirectory = QFileInfo(workspace.workspacePath()).absolutePath();
	if (workspace.isIsolatedFixture() || !layout || layout->files.size() > 2048
		|| (layout->kind == EA::InstallationPackageKind::MacBundle
			&& (dataDirectory == layout->root || dataDirectory.startsWith(layout->root + u'/')))) {
		return std::nullopt;
	}
	auto result = ApprovedRemovalPackage();
	result.receipt.installationId = installation;
	result.receipt.kind = layout->kind;
	result.receipt.packageRoot = QFileInfo(layout->root).filesystemFilePath();
	result.receipt.packageRoot.make_preferred();
	auto binding = QCryptographicHash(QCryptographicHash::Sha256);
	binding.addData(layout->root.toUtf8());
	binding.addData(QByteArrayView("\0", 1));
	for (const auto &relative : layout->files) {
		const auto path = QDir(layout->root).filePath(relative);
		const auto sha = Fingerprint(path);
		if (!sha) {
			return std::nullopt;
		}
		const auto utf8 = relative.toUtf8();
		const auto native = std::filesystem::path(std::u8string(
			reinterpret_cast<const char8_t*>(utf8.constData()), size_t(utf8.size())));
		result.receipt.artifacts.push_back({ .relativePath = native, .digest = *sha });
		binding.addData(utf8);
		binding.addData(QByteArrayView("\0", 1));
		binding.addData(QByteArrayView(reinterpret_cast<const char*>(sha->data()), sha->size()));
		if (relative == layout->helper) {
			result.helper = { .source = QFileInfo(path).filesystemFilePath(), .digest = *sha };
		}
	}
	if (result.helper.source.empty() || EA::InspectInstallationRemoval(result.receipt)
		!= EA::InstallationRemovalCapability::Automatic) {
		return std::nullopt;
	}
	result.digest = binding.result();
	return result;
}

bool LaunchProfileInstallationRemoval(
		const MigrationController &workspace,
		const EA::EmergencyRecoveryRecord &record,
		ApprovedRemovalPackage package,
		const EA::EmergencyActionJournal &journal) {
	const auto committed = workspace.LoadCommitted();
	if (workspace.isIsolatedFixture() || !committed || committed->emergencyRecovery.isEmpty()
		|| committed->transactionId.toHex().toStdString() != record.successorGeneration
		|| !EA::MatchesEmergencyRecoveryJournal(record, journal)) {
		return false;
	}
	const auto root = QFileInfo(workspace.workspacePath());
	const auto setSettings = QFileInfo(QDir(root.absoluteFilePath()).filePath(u"set-settings"_q));
	if (setSettings.isSymLink() || setSettings.isJunction()
		|| (setSettings.exists() && !setSettings.isDir())) {
		return false;
	}
	auto scope = EA::InstallationDataCleanupScope{
		.installationId = record.journal.installationId,
		.dataDirectory = QFileInfo(root.absolutePath()).filesystemFilePath().make_preferred(),
		.generationIds = { record.successorGeneration },
		.journalIds = { record.journal.operationId },
	};
	const auto folders = QDir(setSettings.absoluteFilePath()).entryInfoList(
		QDir::Dirs | QDir::NoDotAndDotDot | QDir::System | QDir::Hidden);
	for (const auto &folder : folders) {
		const auto id = folder.fileName().toLatin1();
		const auto decoded = QByteArray::fromHex(id);
		if (decoded.size() == 16 && decoded.toHex() == id && decoded != QByteArray(16, 0)) {
			if (folder.isSymLink() || folder.isJunction()) {
				return false;
			}
			scope.setIds.push_back(id.toStdString());
		}
	}
	const auto data = EA::CaptureInstallationDataCleanupPlan(scope);
	if (!data) {
		return false;
	}
	package.receipt.dataCleanup = EA::EncodeInstallationDataCleanupPlan(*data);
	return !package.receipt.dataCleanup.empty() && EA::LaunchInstallationRemoval(
		std::move(package.helper), std::move(package.receipt), journal).get()
		== EA::InstallationRemovalLaunchResult::ReadyToExit;
}

} // namespace Ayu::ProfileSets
