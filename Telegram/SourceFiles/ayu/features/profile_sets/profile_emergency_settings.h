// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_migration.h"
#include "window/window_emergency_rules.h"

namespace Ayu::ProfileSets {

void LoadProfileEmergencySettings(
	MigrationController workspace,
	QByteArray expectedTransactionId,
	QString masterPasscode,
	Window::EmergencyRulesLoadDone done);

void SaveProfileEmergencySettings(
	MigrationController workspace,
	Window::EmergencyRulesSaveRequest request,
	Window::EmergencyRulesSaveDone done);

} // namespace Ayu::ProfileSets
