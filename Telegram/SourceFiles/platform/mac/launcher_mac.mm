/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "platform/mac/launcher_mac.h"

#include "core/crash_reports.h"
#include "core/update_checker.h"
#include "base/base_file_utilities.h"
#include "base/platform/base_platform_file_utilities.h"
#include "base/platform/mac/base_utilities_mac.h"

#include <Cocoa/Cocoa.h>
#include <CoreFoundation/CFURL.h>
#include <sys/sysctl.h>

// AyuGram includes
#ifdef SLEEPYGRAM_RELEASE_UPDATE
#include "core/sleepy_update.h"
#endif // SLEEPYGRAM_RELEASE_UPDATE


namespace Platform {

Launcher::Launcher(int argc, char *argv[])
: Core::Launcher(argc, argv) {
}

void Launcher::initHook() {
	base::RegisterBundledResources(u"Telegram.rcc"_q);
}

bool Launcher::launchUpdater(UpdaterLaunch action) {
	if (cExeName().isEmpty()) {
		return false;
	}
#ifdef SLEEPYGRAM_RELEASE_UPDATE
	if (action != UpdaterLaunch::JustRelaunch) {
		return false;
	}
	auto flags = QStringList();
	if (cRestartingToSettings()) {
		flags.push_back(u"-tosettings"_q);
	}
	if (cLaunchMode() == LaunchModeAutoStart) {
		flags.push_back(u"-autostart"_q);
	}
	if (Logs::DebugEnabled()) {
		flags.push_back(u"-debug"_q);
	}
	if (cStartInTray()) {
		flags.push_back(u"-startintray"_q);
	}
	Logs::closeMain();
	CrashReports::Finish();
	return Core::RestartSleepyGram(
		cExeDir() + cExeName() + u"/Contents/MacOS/SleepyGram"_q,
		customWorkingDir() ? cWorkingDir() : QString(),
		flags);
#else // SLEEPYGRAM_RELEASE_UPDATE
	@autoreleasepool {

	if (action == UpdaterLaunch::JustRelaunch) {
#ifdef OS_MAC_STORE
		const auto updaterDisabled = true;
#else
		const auto updaterDisabled = Core::UpdaterDisabled();
#endif
		if (updaterDisabled) {
			NSDictionary *conf = [NSDictionary dictionaryWithObject:[NSArray array] forKey:NSWorkspaceLaunchConfigurationArguments];
			[[NSWorkspace sharedWorkspace] launchApplicationAtURL:[NSURL fileURLWithPath:Q2NSString(cExeDir() + cExeName())] options:NSWorkspaceLaunchAsync | NSWorkspaceLaunchNewInstance configuration:conf error:0];
			return true;
		}
	}

	NSString *path = @"", *args = @"";
	@try {
		path = [[NSBundle mainBundle] bundlePath];
		if (!path) {
			LOG(("Could not get bundle path!!"));
			return false;
		}
		path = [path stringByAppendingString:@"/Contents/Frameworks/Updater"];
		base::Platform::RemoveQuarantine(QFile::decodeName([path fileSystemRepresentation]));

		NSMutableArray *args = [[NSMutableArray alloc] initWithObjects:@"-workpath", Q2NSString(cWorkingDir()), @"-procid", nil];
		[args addObject:[NSString stringWithFormat:@"%d", [[NSProcessInfo processInfo] processIdentifier]]];
		if (cRestartingToSettings()) [args addObject:@"-tosettings"];
		if (action == UpdaterLaunch::JustRelaunch) [args addObject:@"-noupdate"];
		if (cLaunchMode() == LaunchModeAutoStart) [args addObject:@"-autostart"];
		if (Logs::DebugEnabled()) [args addObject:@"-debug"];
		if (cStartInTray()) [args addObject:@"-startintray"];
		if (cDataFile() != u"data"_q) {
			[args addObject:@"-key"];
			[args addObject:Q2NSString(cDataFile())];
		}
		if (customWorkingDir()) {
			[args addObject:@"-workdir_custom"];
		}

		DEBUG_LOG(("Application Info: executing %1 %2").arg(NS2QString(path)).arg(NS2QString([args componentsJoinedByString:@" "])));
		Logs::closeMain();
		CrashReports::Finish();
		if (![NSTask launchedTaskWithLaunchPath:path arguments:args]) {
			DEBUG_LOG(("Task not launched while executing %1 %2").arg(NS2QString(path)).arg(NS2QString([args componentsJoinedByString:@" "])));
			return false;
		}
	}
	@catch (NSException *exception) {
		LOG(("Exception caught while executing %1 %2").arg(NS2QString(path)).arg(NS2QString(args)));
		return false;
	}
	@finally {
	}

	}
	return true;
#endif // SLEEPYGRAM_RELEASE_UPDATE
}

} // namespace Platform
