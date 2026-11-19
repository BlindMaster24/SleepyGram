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

#include <iostream>

namespace {

QByteArray Release(const QString &tag, const QString &name, const QString &url) {
	return QJsonDocument(QJsonObject{
		{ QStringLiteral("tag_name"), tag },
		{ QStringLiteral("draft"), false },
		{ QStringLiteral("prerelease"), false },
		{ QStringLiteral("assets"), QJsonArray{ QJsonObject{
			{ QStringLiteral("name"), name },
			{ QStringLiteral("browser_download_url"), url },
		} } },
	}).toJson();
}

} // namespace

int main() {
	const auto name = QStringLiteral("SleepyGram-update-linux-x64.tdup");
	const auto tag = QStringLiteral("v7.4.4");
	const auto url = QStringLiteral(
		"https://github.com/slpkbt/SleepyGram/releases/download/"
		"v7.4.4/SleepyGram-update-linux-x64.tdup");
	const auto parse = [&](const QString &version, const QString &asset,
			const QString &address, quint32 current = 7004003) {
		return Core::Updates::ParseGithubRelease(
			Release(version, asset, address), "linux", current);
	};
	const auto valid = parse(tag, name, url);
	const auto old = parse(tag, name, url, 7004004);
	const auto missing = parse(tag, name + 'x', url);
	const auto unsupported = Core::Updates::ParseGithubRelease(
		Release(tag, name, url), "winarm", 7004003);
	auto prerelease = QJsonDocument::fromJson(Release(tag, name, url)).object();
	prerelease.insert(QStringLiteral("prerelease"), true);
	auto duplicate = QJsonDocument::fromJson(Release(tag, name, url)).object();
	auto assets = duplicate.value(QStringLiteral("assets")).toArray();
	assets.append(assets.at(0));
	duplicate.insert(QStringLiteral("assets"), assets);
	const auto passed = valid && valid->version == 7004004
		&& valid->download.toString() == url
		&& old && old->download.isEmpty()
		&& missing && missing->version == 7004004 && missing->download.isEmpty()
		&& unsupported && unsupported->download.isEmpty()
		&& !parse(QStringLiteral("v7.4.4-rc1"), name, url)
		&& !parse(QStringLiteral("v07.4.4"), name, url)
		&& !parse(QStringLiteral("v4295.0.0"), name, url)
		&& !Core::Updates::ParseGithubRelease(
			QJsonDocument(prerelease).toJson(), "linux", 7004003)
		&& !Core::Updates::ParseGithubRelease(
			QJsonDocument(duplicate).toJson(), "linux", 7004003)
		&& !parse(tag, name, QStringLiteral("http://github.com/evil"))
		&& !parse(tag, name, url + QStringLiteral("?other=1"));
	if (!passed) {
		std::cerr << "GitHub release parser test failed\n";
	}
	return passed ? 0 : 1;
}
