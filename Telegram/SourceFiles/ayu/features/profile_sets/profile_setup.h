// This is the source code of AyuGram for Desktop.
#pragma once

#include "base/basic_types.h"

namespace Ayu::ProfileSets {

enum class ProfileSetupResult : uchar {
	Complete,
	InvalidInput,
	LegacyPasscodeRejected,
	UnsupportedLegacyData,
	SetupPasscodeRejected,
	StorageFailed,
	VerificationFailed,
	RetirementPending,
};

struct ProfileSetupRequest final {
	QString dataDirectory;
	QString dataName;
	QString legacyPasscode;
	QString masterPasscode;
	QString firstSetName;
	QString firstSetPasscode;
	bool preserveLegacyWebviewStorage = false;
};

void SetupProfileFromLegacy(
	ProfileSetupRequest request,
	Fn<void(ProfileSetupResult)> done);

[[nodiscard]] bool FinishProfileRetirement(const QString &dataDirectory);

} // namespace Ayu::ProfileSets
