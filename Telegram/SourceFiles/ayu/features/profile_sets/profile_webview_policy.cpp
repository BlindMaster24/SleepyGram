// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_webview_policy.h"

#include "core/application.h"
#include "settings.h"
#include "webview/webview_embed.h"

namespace Ayu::ProfileSets {

bool CanUsePersistentWebview(const Webview::StorageId &id) {
	if (Core::App().legacyProfileAccessAllowed()) {
		return true;
	}
	const auto dataRoot = QDir(cWorkingDir() + u"tdata"_q).canonicalPath();
	return !dataRoot.isEmpty() && details::CanUsePersistentWebview(
		false,
		QOperatingSystemVersion::currentType(),
		QOperatingSystemVersion::current().majorVersion(),
		dataRoot + u"/profile-sets/accounts"_q,
		id.path,
		id.token);
}

Webview::WindowConfig PersistentWebviewConfig(Webview::WindowConfig config) {
#ifdef Q_OS_WIN
	config.requireIsolatedStorage = !Core::App().legacyProfileAccessAllowed();
#endif
	return config;
}

} // namespace Ayu::ProfileSets
