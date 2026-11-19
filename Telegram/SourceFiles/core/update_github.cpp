/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/update_github.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>

namespace Core::Updates {

std::optional<GithubRelease> ParseGithubRelease(
		const QByteArray &json,
		const QByteArray &platformKey,
		quint32 currentVersion) {
	auto error = QJsonParseError();
	const auto document = QJsonDocument::fromJson(json, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		return std::nullopt;
	}
	const auto object = document.object();
	if (!object.value(QStringLiteral("draft")).isBool()
		|| object.value(QStringLiteral("draft")).toBool()
		|| !object.value(QStringLiteral("prerelease")).isBool()
		|| object.value(QStringLiteral("prerelease")).toBool()) {
		return std::nullopt;
	}
	const auto tag = object.value(QStringLiteral("tag_name")).toString();
	const auto match = QRegularExpression(
		QStringLiteral("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\z")
	).match(tag);
	if (!match.hasMatch()) {
		return std::nullopt;
	}
	auto ok = false;
	const auto major = match.captured(1).toULongLong(&ok);
	if (!ok || major > 4294) {
		return std::nullopt;
	}
	const auto minor = match.captured(2).toULongLong(&ok);
	if (!ok || minor > 999) {
		return std::nullopt;
	}
	const auto patch = match.captured(3).toULongLong(&ok);
	if (!ok || patch > 999) {
		return std::nullopt;
	}
	const auto version = major * 1000000 + minor * 1000 + patch;
	if (version > 0xFFFFFFFFULL) {
		return std::nullopt;
	}
	if (version <= currentVersion) {
		return GithubRelease{ quint32(version), {} };
	}
	const auto suffix = (platformKey == "win64")
		? "windows-x64"
		: (platformKey == "armac")
		? "macos-arm64"
		: (platformKey == "linux")
		? "linux-x64"
		: nullptr;
	if (!object.value(QStringLiteral("assets")).isArray()) {
		return std::nullopt;
	}
	if (!suffix) {
		return GithubRelease{ quint32(version), {} };
	}
	const auto name = QStringLiteral("SleepyGram-update-") + QString::fromLatin1(suffix)
		+ QStringLiteral(".tdup");
	auto found = QUrl();
	for (const auto &entry : object.value(QStringLiteral("assets")).toArray()) {
		if (!entry.isObject()) {
			return std::nullopt;
		}
		const auto asset = entry.toObject();
		if (asset.value(QStringLiteral("name")).toString() != name) {
			continue;
		}
		const auto url = QUrl(asset.value(QStringLiteral("browser_download_url")).toString());
		const auto path = QStringLiteral("/slpkbt/SleepyGram/releases/download/")
			+ tag + '/' + name;
		if (!found.isEmpty()
			|| !url.isValid()
			|| url.scheme() != QStringLiteral("https")
			|| url.host() != QStringLiteral("github.com")
			|| url.port() != -1
			|| !url.userInfo().isEmpty()
			|| url.path() != path
			|| url.hasQuery()
			|| url.hasFragment()) {
			return std::nullopt;
		}
		found = url;
	}
	return GithubRelease{ quint32(version), found };
}

} // namespace Core::Updates
