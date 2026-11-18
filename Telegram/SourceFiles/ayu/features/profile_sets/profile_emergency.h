// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_generation.h"

namespace Ayu::ProfileSets {

[[nodiscard]] std::optional<OpenedProfileGeneration> SubmitProfileEmergencyOnWorker(
	const MigrationController &workspace,
	const CommittedMigration &committed,
	const DerivedCredential &credential,
	ProfileGenerationError &error);

[[nodiscard]] bool FinishProfileEmergencyRecovery(const QString &dataDirectory);

} // namespace Ayu::ProfileSets
