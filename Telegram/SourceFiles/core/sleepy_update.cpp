#include "core/sleepy_update.h"

#include "core/application.h"
#include "core/sleepy_update_install.h"
#include "core/update_checker.h"
#include "core/version.h"
#include "storage/localstorage.h"

#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QSaveFile>
#include <QtCore/QThread>
#include <QtWidgets/QApplication>

namespace Core {
namespace {

constexpr auto kProbeTimeout = 120000;
constexpr auto kProbeWait = 50;
constexpr auto kHandoffTimeout = 3000;

struct UpdateRequest {
	QString package;
	QString executable;
	QString workdir;
	QStringList arguments;
	QByteArray heldManifest;
	quint32 version = 0;
};

std::optional<UpdateRequest> PendingUpdate;

[[nodiscard]] QString HelperSource(const QString &executable) {
	const auto directory = QFileInfo(executable).absolutePath();
#ifdef Q_OS_MACOS
	return QDir::cleanPath(directory + u"/../Frameworks/Updater"_q);
#elif defined Q_OS_WIN
	return directory + u"/Updater.exe"_q;
#else
	return directory + u"/Updater"_q;
#endif // Q_OS_MACOS || Q_OS_WIN
}

[[nodiscard]] bool SaveMarker(const QString &path, QByteArrayView bytes) {
	auto file = QSaveFile(path);
	return file.open(QIODevice::WriteOnly)
		&& file.write(bytes.data(), bytes.size()) == bytes.size()
		&& file.commit();
}

[[nodiscard]] bool LaunchHelper(
		const QString &executable,
		const QStringList &arguments,
		const QByteArray &heldManifest = {}) {
	const auto source = QFileInfo(HelperSource(executable));
	if (!source.isFile() || !source.isExecutable() || source.isSymLink()
		|| source.canonicalFilePath() != source.absoluteFilePath()) {
		return false;
	}
	const auto staging = Updates::CreateSleepyUpdateHelperDirectory();
	if (staging.isEmpty()) {
		return false;
	}
	const auto program = QDir(staging).filePath(source.fileName());
	if (!QFile::copy(source.absoluteFilePath(), program)
		|| (!heldManifest.isEmpty() && !SaveMarker(
			QDir(staging).filePath(u"held-manifest"_q),
			heldManifest))
		|| !QProcess::startDetached(program, arguments, staging)) {
		if (!Updates::RemoveSleepyUpdateHelperDirectory(staging)) {
			LOG(("Update Error: could not clean up the inactive updater."));
		}
		return false;
	}
	return true;
}

[[nodiscard]] bool Probe(const QString &directory, int argc, char **argv) {
	auto gui = QApplication(argc, argv);
	const auto platform = QGuiApplication::platformName();
#ifdef Q_OS_MACOS
	const auto native = (platform == u"cocoa"_q);
#elif defined Q_OS_WIN
	const auto native = (platform == u"windows"_q);
#else
	const auto native = (platform == u"xcb"_q || platform.startsWith(u"wayland"_q));
#endif // Q_OS_MACOS || Q_OS_WIN
	const auto aborted = directory + u"/abort"_q;
	if (!native || QFileInfo::exists(aborted)
		|| !SaveMarker(directory + u"/ready"_q, QByteArrayView("1"))) {
		return false;
	}
	const auto committed = directory + u"/commit"_q;
	auto elapsed = QElapsedTimer();
	elapsed.start();
	while (!elapsed.hasExpired(kProbeTimeout)) {
		if (QFileInfo::exists(aborted)) {
			return false;
		} else if (QFileInfo::exists(committed)) {
			return SaveMarker(directory + u"/released"_q, QByteArrayView("1"));
		}
		QThread::msleep(kProbeWait);
	}
	return false;
}

[[nodiscard]] QStringList RestartArguments() {
	return (cDataFile() == u"data"_q)
		? QStringList()
		: QStringList{ u"-key"_q, cDataFile() };
}

} // namespace

bool CanInstallSleepyUpdate() {
	const auto executable = QCoreApplication::applicationFilePath();
	return !UpdaterDisabled() && !cManyInstance()
		&& cDataFile().size() <= 255
		&& QFileInfo(HelperSource(executable)).isExecutable()
		&& Updates::SleepyUpdateInstallationSupported(executable, cWorkingDir());
}

bool IsSleepyUpdateBusy() {
	return Quitting() || !IsAppLaunched() || !App().canInstallReleaseUpdate();
}

bool RequestSleepyUpdate(const QString &package, quint32 version) {
	if (!CanInstallSleepyUpdate() || IsSleepyUpdateBusy()
		|| PendingUpdate || version <= AppVersion
		|| cRestarting() || cRestartingUpdate()) {
		return false;
	}
	auto signature = QByteArray();
	auto manifest = QByteArray();
	const auto hasManifest = Local::readUpdateManifest(&manifest, &signature);
	const auto info = QFileInfo(package);
	if (!info.isFile() || info.isSymLink() || !info.isAbsolute()
		|| info.canonicalFilePath() != info.absoluteFilePath()) {
		return false;
	}
	PendingUpdate = UpdateRequest{
		.package = info.absoluteFilePath(),
		.executable = QCoreApplication::applicationFilePath(),
		.workdir = QDir::cleanPath(cWorkingDir()),
		.arguments = RestartArguments(),
		.heldManifest = hasManifest ? (signature + manifest) : QByteArray(),
		.version = version,
	};
	Quit();
	if (!Quitting()) {
		PendingUpdate.reset();
		return false;
	}
	return true;
}

std::optional<int> CheckSleepyUpdateStartup(
		const QString &executable,
		const QStringList &arguments,
		int argc,
		char **argv) {
	const auto probe = arguments.indexOf(u"-sleepy-update-probe"_q);
	if (probe > 0) {
		const auto version = arguments.indexOf(u"--sleepy-update-expected-version"_q);
		const auto directory = arguments.value(probe + 1);
		if (version <= 0 || arguments.value(version + 1) != QString::number(AppVersion)
			|| !Updates::SleepyUpdateProbeDirectoryValid(executable, directory)) {
			return 1;
		}
		return Probe(directory, argc, argv) ? 0 : 1;
	}
#ifdef Q_OS_WIN
	if (const auto cleanup = arguments.indexOf(u"-sleepy-update-cleanup"_q); cleanup > 0) {
		const auto directory = arguments.value(cleanup + 1);
		for (auto retry = 0; retry != 10; ++retry) {
			if (Updates::RemoveSleepyUpdateHelperDirectory(directory)) {
				break;
			}
			QThread::msleep(kProbeWait);
		}
	}
#endif // Q_OS_WIN
	const auto transaction = QFileInfo(Updates::SleepyUpdateTransactionPath(executable));
	if (!transaction.exists() && !transaction.isSymLink()) {
		return std::nullopt;
	}
	auto command = QStringList{
		u"--recover"_q,
		executable,
		QString(),
		QString::number(QCoreApplication::applicationPid()),
	};
	command.append(RestartArguments());
	return LaunchHelper(executable, command) ? 0 : 1;
}

std::optional<bool> LaunchRequestedSleepyUpdate() {
	if (!PendingUpdate) {
		return std::nullopt;
	}
	auto request = std::move(*PendingUpdate);
	PendingUpdate.reset();
	auto command = QStringList{
		u"--apply"_q,
		request.package,
		request.executable,
		request.workdir,
		QString::number(AppVersion),
		QString::number(request.version),
		QString::number(QCoreApplication::applicationPid()),
	};
	command.append(request.arguments);
	if (!LaunchHelper(request.executable, command, request.heldManifest)) {
		return false;
	}
	const auto intent = QDir(Updates::SleepyUpdateTransactionPath(request.executable))
		.filePath(u"journal"_q);
	auto elapsed = QElapsedTimer();
	elapsed.start();
	while (!QFileInfo::exists(intent) && !elapsed.hasExpired(kHandoffTimeout)) {
		QThread::msleep(kProbeWait);
	}
	return QFileInfo::exists(intent);
}

bool RestartSleepyGram(
		const QString &executable,
		const QString &workdir,
		const QStringList &flags) {
	auto arguments = QStringList{
		u"--restart"_q,
		executable,
		workdir,
		QString::number(QCoreApplication::applicationPid()),
		(cDataFile() == u"data"_q) ? QString() : cDataFile(),
	};
	arguments.append(flags);
	return LaunchHelper(executable, arguments);
}

} // namespace Core
