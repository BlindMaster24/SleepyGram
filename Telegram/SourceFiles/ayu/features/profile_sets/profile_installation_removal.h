// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/installation_removal_launcher.h"

#include <QtCore/QByteArray>

namespace Ayu::EmergencyActions {
struct EmergencyRecoveryRecord;
} // namespace Ayu::EmergencyActions

namespace Ayu::ProfileSets {

class MigrationController;

struct ApprovedRemovalPackage final {
	EmergencyActions::VerifiedInstallationReceipt receipt;
	EmergencyActions::VerifiedInstallationRemovalHelper helper;
	QByteArray digest;
};

[[nodiscard]] std::optional<ApprovedRemovalPackage> ReadRemovalPackage(
	const MigrationController &workspace,
	const EmergencyActions::InstallationId &installation);

[[nodiscard]] bool LaunchProfileInstallationRemoval(
	const MigrationController &workspace,
	const EmergencyActions::EmergencyRecoveryRecord &record,
	ApprovedRemovalPackage package,
	const EmergencyActions::EmergencyActionJournal &journal);

} // namespace Ayu::ProfileSets
