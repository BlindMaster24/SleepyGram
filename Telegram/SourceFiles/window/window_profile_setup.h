// This is the source code of AyuGram for Desktop.
#pragma once

#include "base/basic_types.h"

#include <memory>

class PreLaunchWindow;

namespace Window {

[[nodiscard]] std::unique_ptr<PreLaunchWindow> CreateProfileSetupWindow(
	QString dataDirectory,
	QString dataName,
	bool canContinueLegacy,
	Fn<void()> continueLegacy,
	Fn<void()> restartProtected);

[[nodiscard]] bool ProfileSetupInProgress(const PreLaunchWindow *window);

} // namespace Window
