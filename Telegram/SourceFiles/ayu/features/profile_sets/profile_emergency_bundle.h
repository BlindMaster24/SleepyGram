// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_rule_vault.h"
#include "ayu/features/profile_sets/profile_migration.h"

#include <map>

namespace Ayu::ProfileSets {

struct ProfileEmergencyBundle final {
	EmergencyActions::EmergencyRuleAuthority authority;
	QByteArray rules;
	std::map<QByteArray, QByteArray> capsules;
};

[[nodiscard]] std::optional<ProfileEmergencyBundle> ReadProfileEmergencyBundle(
	const CommittedMigration &committed);
[[nodiscard]] QByteArray SerializeProfileEmergencyBundle(
	const QByteArray &rules,
	const std::map<QByteArray, QByteArray> &capsules);

} // namespace Ayu::ProfileSets
