// This is the source code of AyuGram for Desktop.
#pragma once

#include <QtCore/QStringList>

#include <algorithm>

namespace Storage::details {

enum class CacheMigrationPathKind : uchar {
	Invalid,
	Directory,
	Version,
	Encrypted,
};

[[nodiscard]] inline CacheMigrationPathKind ClassifyCacheMigrationPath(
		QStringView relativePath) {
	using Kind = CacheMigrationPathKind;
	const auto parts = relativePath.split('/');
	if (parts.isEmpty() || (parts[0] != u"cache" && parts[0] != u"media_cache")) {
		return Kind::Invalid;
	} else if (parts.size() == 1) {
		return Kind::Directory;
	} else if (parts.size() == 2 && parts[1] == u"version") {
		return Kind::Version;
	}
	auto ok = false;
	const auto generation = parts[1].toInt(&ok);
	if (!ok || generation < 0 || QString::number(generation) != parts[1]) {
		return Kind::Invalid;
	} else if (parts.size() == 2) {
		return Kind::Directory;
	}
	const auto hex = [](QStringView name, qsizetype size) {
		return (name.size() == size) && std::ranges::all_of(name, [](QChar ch) {
			return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F');
		});
	};
	if (parts.size() == 3) {
		if (parts[2] == u"binlog" || parts[2] == u"binlog-ready"
			|| parts[2] == u"binlog-temp") {
			return Kind::Encrypted;
		}
		return hex(parts[2], 2) ? Kind::Directory : Kind::Invalid;
	}
	return (parts.size() == 4 && hex(parts[2], 2) && hex(parts[3], 12))
		? Kind::Encrypted
		: Kind::Invalid;
}

} // namespace Storage::details
