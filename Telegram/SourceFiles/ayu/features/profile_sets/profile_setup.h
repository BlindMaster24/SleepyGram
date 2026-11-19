// This is the source code of AyuGram for Desktop.
#pragma once

#include "base/basic_types.h"

namespace Ayu::ProfileSets {

enum class ProfileSetupResult : uchar {
	Complete,
	InvalidInput,
	LegacyPasscodeRejected,
	LegacyWalletPasscodeRequired,
	LegacyWalletPasscodeRejected,
	UnsupportedLegacyData,
	SetupPasscodeRejected,
	StorageFailed,
	VerificationFailed,
	RetirementPending,
	RevocablePromotionDeferred,
};

enum class ProfileSetupLayout : uchar {
	LegacyKeys,
	RevocableGates,
};

struct ProfileSetupRequest final {
	QString dataDirectory;
	QString dataName;
	QString legacyPasscode;
	QString masterPasscode;
	QString firstSetName;
	QString firstSetPasscode;
	bool preserveLegacyWebviewStorage = false;
	QString legacyWalletPasscode;
	ProfileSetupLayout layout = ProfileSetupLayout::LegacyKeys;
};

void SetupProfileFromLegacy(
	ProfileSetupRequest request,
	Fn<void(ProfileSetupResult)> done);

[[nodiscard]] bool FinishProfileRetirement(const QString &dataDirectory);

} // namespace Ayu::ProfileSets
