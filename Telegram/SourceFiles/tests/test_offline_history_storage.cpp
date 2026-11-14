/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/offline_history/offline_history_storage.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

#include <cstdio>

namespace {

using namespace Ayu::OfflineHistory::Storage;

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
		std::printf("FAIL temporary-directory\n");
		return 2;
	}
	const auto paths = PathsFor(temporary.path(), 1001, PeerId(77));
	auto snapshot = Snapshot{
		.from = 1700000000,
		.to = 1700600000,
		.nextOffset = 1234,
		.pages = 3,
		.messages = {
			{ .id = MsgId(8), .date = TimeId(1700000001), .sender = QStringLiteral("A"), .text = QStringLiteral("first") },
			{ .id = MsgId(9), .date = TimeId(1700000002), .sender = QStringLiteral("B"), .text = QStringLiteral("second") },
		},
	};
	const auto bytes = Serialize(snapshot, 1001, PeerId(77));
	check("atomic-write", WriteAtomic(
		paths.partial,
		bytes,
		paths.root,
		1024 * 1024));

	auto restored = Snapshot();
	check("round-trip", ReadSnapshot(
		paths.partial,
		1001,
		PeerId(77),
		&restored)
		&& restored.from == snapshot.from
		&& restored.to == snapshot.to
		&& restored.nextOffset == snapshot.nextOffset
		&& restored.pages == snapshot.pages
		&& restored.messages.size() == 2
		&& restored.messages[1].text == QStringLiteral("second"));
	check("account-isolation", !ReadSnapshot(
		paths.partial,
		1002,
		PeerId(77),
		&restored));
	check("peer-isolation", !ReadSnapshot(
		paths.partial,
		1001,
		PeerId(78),
		&restored));

	auto file = QFile(paths.partial);
	const auto original = [&] {
		return file.open(QIODevice::ReadOnly)
			? file.readAll()
			: QByteArray();
	}();
	file.close();
	check("quota-rejects-before-replace", !WriteAtomic(
		paths.partial,
		QByteArray(original.size() + 1, 'x'),
		paths.root,
		original.size()));
	check("quota-keeps-old-file", ReadSnapshot(
		paths.partial,
		1001,
		PeerId(77),
		&restored)
		&& restored.messages.size() == 2);

	snapshot.pages = 101;
	const auto invalid = Serialize(snapshot, 1001, PeerId(77));
	check("invalid-page-count-rejected", invalid.isEmpty());
	snapshot.pages = 3;
	snapshot.messages[0].text = QString(16 * 1024 + 1, QChar('x'));
	check("oversized-message-rejected",
		Serialize(snapshot, 1001, PeerId(77)).isEmpty());

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	return RunChecks();
}
