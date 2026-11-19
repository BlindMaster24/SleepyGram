// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_revocable_emergency_admission.h"
#include "ayu/features/profile_sets/profile_revocable_vault.h"

namespace Ayu::ProfileSets {

[[nodiscard]] std::optional<QByteArray> RebindRevocableEmergencyRulesForEnrollment(
	QByteArrayView currentRules,
	const DerivedCredential &master,
	const RevocableAdminVaultAccess &before,
	const Metadata &after,
	const AccountGateTable &currentGates,
	const CreatedAccountGate &added,
	EmergencyActions::EmergencyScopedRemoteIdentity enrolledIdentity,
	const ResolveRevocableEmergencyPackage &resolvePackage = {});

} // namespace Ayu::ProfileSets
