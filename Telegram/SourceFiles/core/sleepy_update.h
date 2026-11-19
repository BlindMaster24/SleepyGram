#pragma once

#include <QtCore/QStringList>

#include <optional>

namespace Core {

[[nodiscard]] bool CanInstallSleepyUpdate();
[[nodiscard]] bool IsSleepyUpdateBusy();
[[nodiscard]] bool RequestSleepyUpdate(const QString &package, quint32 version);
[[nodiscard]] std::optional<int> CheckSleepyUpdateStartup(
	const QString &executable,
	const QStringList &arguments,
	int argc,
	char **argv);
[[nodiscard]] std::optional<bool> LaunchRequestedSleepyUpdate();
[[nodiscard]] bool RestartSleepyGram(
	const QString &executable,
	const QString &workdir,
	const QStringList &flags);

} // namespace Core
