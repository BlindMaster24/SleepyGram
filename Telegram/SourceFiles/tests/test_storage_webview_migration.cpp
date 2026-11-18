// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_webview_policy.h"
#include "storage/details/storage_webview_migration.h"

#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

#include <cstdio>

int main() {
	using Storage::details::ClassifyLegacyWebviewTokens;
	using Backend = Storage::details::LegacyWebviewBackend;
	using Proof = Storage::details::LegacyWebviewStorageProof;
	constexpr auto paths = Backend::SuppliedPaths;
	constexpr auto native = Backend::SharedOrNativeStorage;
	const auto token = QByteArray(16, '\0');
	const auto legacy = QByteArray("<legacy>");
	const auto malformed = QByteArray(15, 'x');
	auto failures = 0;
	const auto check = [&](bool pass, const char *name) {
		std::printf("%s %s\n", pass ? "PASS" : "FAIL", name);
		failures += !pass;
	};
	check(ClassifyLegacyWebviewTokens({}, {}, paths) == Proof::NoToken
		&& ClassifyLegacyWebviewTokens({}, {}, native) == Proof::NoToken,
		"an empty record has no stored token on either backend");
	check(ClassifyLegacyWebviewTokens(token, {}, paths) == Proof::FilePaths
		&& ClassifyLegacyWebviewTokens({}, token, paths) == Proof::FilePaths
		&& ClassifyLegacyWebviewTokens(token, token, paths) == Proof::FilePaths,
		"modern tokens can be checked by their exact paths on GTK");
	check(ClassifyLegacyWebviewTokens(token, {}, native) == Proof::Unsupported
		&& ClassifyLegacyWebviewTokens({}, token, native) == Proof::Unsupported,
		"an empty installation path cannot prove native tokens are unused");
	check(ClassifyLegacyWebviewTokens(legacy, token, paths) == Proof::Unsupported
		&& ClassifyLegacyWebviewTokens(token, legacy, paths) == Proof::Unsupported,
		"legacy shared tokens are rejected in either field");
	check(ClassifyLegacyWebviewTokens(malformed, token, paths) == Proof::Unsupported
		&& ClassifyLegacyWebviewTokens(token, malformed, paths) == Proof::Unsupported,
		"malformed tokens are rejected in either field");
#if defined Q_OS_WIN || defined Q_OS_MAC
	constexpr auto platformProof = Proof::Unsupported;
#else
	constexpr auto platformProof = Proof::FilePaths;
#endif
	check(ClassifyLegacyWebviewTokens(token, {}) == platformProof,
		"production selects the platform-specific proof");

	using Ayu::ProfileSets::details::CanUsePersistentWebview;
	using OS = QOperatingSystemVersion;
	const auto temporary = QTemporaryDir();
	const auto root = QDir(temporary.path()).canonicalPath();
	const auto account = QDir(root).filePath(QString(32, QChar('a')));
	const auto user = account + QLatin1String("/user");
	const auto bots = user + QLatin1String("/wvbots");
	const auto other = user + QLatin1String("/wvother");
	const auto uuid = QByteArray(16, 'n');
	const auto ready = temporary.isValid() && QDir().mkpath(account);
	check(ready, "construct canonical temporary account directory");
	check(CanUsePersistentWebview(true, OS::Windows, 11, {}, {}, legacy)
		&& CanUsePersistentWebview(true, OS::MacOS, 13, {}, {}, {}),
		"legacy callers keep their existing default storage on Windows and old macOS");
	check(ready && CanUsePersistentWebview(false, OS::Unknown, -1, root, bots, token)
		&& CanUsePersistentWebview(false, OS::MacOS, 14, root, other, uuid)
		&& CanUsePersistentWebview(false, OS::Windows, 11, root, bots, uuid)
		&& !QFileInfo::exists(user),
		"GTK, macOS named storage and Windows policy accept exact paths without writes");
	check(!CanUsePersistentWebview(false, OS::MacOS, 13, root, other, uuid),
		"macOS without named stores rejects scoped persistent views");
	check(!CanUsePersistentWebview(false, OS::MacOS, 14, root, other, token)
		&& !CanUsePersistentWebview(false, OS::MacOS, 14, root, other, legacy)
		&& !CanUsePersistentWebview(false, OS::Windows, 11, root, bots, legacy)
		&& !CanUsePersistentWebview(false, OS::Windows, 11, root, root, uuid)
		&& !CanUsePersistentWebview(false, OS::Unknown, -1, root, {}, uuid)
		&& !CanUsePersistentWebview(false, OS::Unknown, -1, root, root, uuid)
		&& !CanUsePersistentWebview(false, OS::Unknown, -1, root, user, uuid),
		"shared identifiers, the null UUID and paths without a scoped suffix are refused");
#ifndef Q_OS_WIN
	check(ready && QFile::link(root, user)
		&& !CanUsePersistentWebview(false, OS::Unknown, -1, root, bots, uuid),
		"shadowing the expected account path with a symlink fails closed");
#endif
	return failures ? 1 : 0;
}
