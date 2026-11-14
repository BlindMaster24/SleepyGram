// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_rule_dispatch.h"

#include <functional>
#include <string>
#include <string_view>
#include <variant>

namespace Ayu::EmergencyActions {

struct EmergencyCredentialMatch final {
	EmergencyActionId actionId;
};

struct NoEmergencyCredentialMatch final {
};

struct EmergencyVaultUnavailable final {
};

struct EmergencyVaultNotConfigured final {
};

using EmergencyVaultResult = std::variant<
	EmergencyVaultNotConfigured,
	NoEmergencyCredentialMatch,
	EmergencyVaultUnavailable,
	EmergencyCredentialMatch>;

class LockScreenCredentialVault {
public:
	using Done = std::function<void(EmergencyVaultResult)>;
	virtual ~LockScreenCredentialVault() = default;
	virtual void Probe(std::string_view passcode, Done done) = 0;
};

class EmergencyActionActivation {
public:
	using Done = std::function<void(bool activated)>;
	virtual ~EmergencyActionActivation() = default;
	virtual void Activate(EmergencyActionId id, Done done) = 0;
};

enum class LockSubmissionPath {
	LegacyPasscode,
	EmergencyAction,
	Rejected,
};

struct LockSubmissionResult final {
	LockSubmissionPath path = LockSubmissionPath::Rejected;
	bool accepted = false;
};

using LockSubmissionDone = std::function<void(LockSubmissionResult)>;
using LegacyLockPasscodeSubmit = std::function<void(
	std::string passcode,
	std::function<void(bool accepted)> done)>;

// A missing vault preserves legacy behavior. An unavailable configured vault
// fails closed; a matched emergency credential is never passed to legacy auth.
void SubmitLockScreenPasscode(
	LockScreenSubmit,
	std::string passcode,
	LockScreenCredentialVault *vault,
	EmergencyActionActivation *activation,
	LegacyLockPasscodeSubmit legacySubmit,
	LockSubmissionDone done);

} // namespace Ayu::EmergencyActions
