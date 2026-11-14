#include "ayu/features/emergency_actions/lock_screen_submission.h"

#include <cstdio>
#include <string>
#include <utility>

namespace {

using namespace Ayu::EmergencyActions;

class FakeVault final : public LockScreenCredentialVault {
public:
	EmergencyVaultResult result;
	std::string observedPasscode;
	int probes = 0;
	bool defer = false;
	Done pending;

	void Probe(std::string_view passcode, Done done) override {
		++probes;
		observedPasscode.assign(passcode);
		if (defer) {
			pending = std::move(done);
		} else {
			done(result);
		}
	}
};

class FakeActivation final : public EmergencyActionActivation {
public:
	bool outcome = true;
	int activations = 0;
	EmergencyActionId observedId;
	bool defer = false;
	Done pending;

	void Activate(EmergencyActionId id, Done done) override {
		++activations;
		observedId = std::move(id);
		if (defer) {
			pending = std::move(done);
		} else {
			done(outcome);
		}
	}
};

int failures = 0;

void Check(const char *name, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	failures += !condition;
}

LockSubmissionResult Submit(
		std::string passcode,
		LockScreenCredentialVault *vault,
		EmergencyActionActivation *activation,
		int &legacyCalls) {
	auto result = LockSubmissionResult();
	SubmitLockScreenPasscode(
		LockScreenSubmit(),
		std::move(passcode),
		vault,
		activation,
		[&](std::string, std::function<void(bool)> done) {
			++legacyCalls;
		done(true);
		},
		[&](LockSubmissionResult value) {
			result = value;
		});
	return result;
}

void LegacyBehaviorAndVaultFallback() {
	auto legacyCalls = 0;
	const auto noVault = Submit("normal", nullptr, nullptr, legacyCalls);
	Check("missing-vault-uses-legacy", legacyCalls == 1
		&& noVault.path == LockSubmissionPath::LegacyPasscode
		&& noVault.accepted);

	auto vault = FakeVault();
	vault.result = NoEmergencyCredentialMatch();
	const auto noMatch = Submit("normal", &vault, nullptr, legacyCalls);
	Check("unmatched-emergency-probe-uses-legacy", legacyCalls == 2
		&& noMatch.path == LockSubmissionPath::LegacyPasscode
		&& noMatch.accepted && vault.observedPasscode == "normal");

	vault.result = EmergencyVaultNotConfigured();
	const auto unconfigured = Submit("normal", &vault, nullptr, legacyCalls);
	Check("unconfigured-vault-uses-legacy", legacyCalls == 3
		&& unconfigured.path == LockSubmissionPath::LegacyPasscode);
}

void OptionalVaultFailsClosedAndActionNeverFallsBack() {
	auto legacyCalls = 0;
	auto vault = FakeVault();
	vault.result = EmergencyVaultUnavailable();
	const auto unavailable = Submit("candidate", &vault, nullptr, legacyCalls);
	Check("unavailable-configured-vault-fails-closed", legacyCalls == 0
		&& unavailable.path == LockSubmissionPath::Rejected
		&& !unavailable.accepted);

	vault.result = EmergencyCredentialMatch{
		.actionId = EmergencyActionId("action-1"),
	};
	auto activation = FakeActivation();
	const auto matched = Submit("emergency", &vault, &activation, legacyCalls);
	Check("typed-emergency-match-routes-to-activation", legacyCalls == 0
		&& activation.activations == 1
		&& activation.observedId == EmergencyActionId("action-1")
		&& matched.path == LockSubmissionPath::EmergencyAction
		&& matched.accepted);

	const auto missingAdapter = Submit("emergency", &vault, nullptr, legacyCalls);
	Check("missing-activation-adapter-rejects-without-legacy", legacyCalls == 0
		&& missingAdapter.path == LockSubmissionPath::Rejected
		&& !missingAdapter.accepted);

	activation.outcome = false;
	const auto failedActivation = Submit(
		"emergency", &vault, &activation, legacyCalls);
	Check("failed-activation-does-not-fall-back", legacyCalls == 0
		&& failedActivation.path == LockSubmissionPath::Rejected
		&& !failedActivation.accepted);
}

void AsynchronousAdaptersRetainSubmissionState() {
	auto vault = FakeVault();
	vault.result = EmergencyCredentialMatch{
		.actionId = EmergencyActionId("delayed-action"),
	};
	vault.defer = true;
	auto activation = FakeActivation();
	activation.defer = true;
	auto legacyCalls = 0;
	auto completed = false;
	auto result = LockSubmissionResult();
	SubmitLockScreenPasscode(
		LockScreenSubmit(),
		"async-passcode",
		&vault,
		&activation,
		[&](std::string, std::function<void(bool)> done) {
			++legacyCalls;
			done(true);
		},
		[&](LockSubmissionResult value) {
			completed = true;
			result = value;
		});
	Check("vault-probe-can-complete-asynchronously", !completed
		&& vault.probes == 1 && vault.observedPasscode == "async-passcode");
	vault.pending(std::move(vault.result));
	Check("activation-can-complete-asynchronously", !completed
		&& activation.activations == 1
		&& activation.observedId == EmergencyActionId("delayed-action"));
	activation.pending(true);
	Check("async-route-completes-once-without-legacy", completed
		&& legacyCalls == 0
		&& result.path == LockSubmissionPath::EmergencyAction
		&& result.accepted);
}

} // namespace

int main() {
	LegacyBehaviorAndVaultFallback();
	OptionalVaultFailsClosedAndActionNeverFallsBack();
	AsynchronousAdaptersRetainSubmissionState();
	return failures ? 1 : 0;
}
