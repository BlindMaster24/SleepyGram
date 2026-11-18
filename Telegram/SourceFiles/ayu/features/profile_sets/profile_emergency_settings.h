// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_migration.h"
#include "ayu/features/profile_sets/profile_vault.h"
#include "window/window_emergency_rules.h"

namespace Ayu::ProfileSets {

[[nodiscard]] std::optional<QByteArray> RebindProfileEmergencyRulesOnWorker(
	const MigrationController &workspace,
	const CommittedMigration &previous,
	const ProfileVault &nextVault,
	const QByteArray &nextTransaction,
	const DerivedCredential &master,
	std::span<const SetGrantCredential> replacements = {});

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
