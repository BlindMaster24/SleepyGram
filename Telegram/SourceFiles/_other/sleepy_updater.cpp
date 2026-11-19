/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/sleepy_update_install.h"

#include <QtCore/QCoreApplication>

#include <cstdio>

int main(int argc, char *argv[]) {
	const auto app = QCoreApplication(argc, argv);
	auto error = QString();
	const auto result = Core::Updates::RunSleepyUpdater(
		app.arguments().mid(1),
		error);
	if (!error.isEmpty()) {
		fprintf(stderr, "SleepyGram update: %s\n", error.toUtf8().constData());
	}
	return result;
}
