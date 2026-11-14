// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/lock_screen_submission.h"

#include <atomic>
#include <memory>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

void Clear(std::string &value) {
	volatile char *data = value.empty() ? nullptr : value.data();
	for (auto i = size_t(0); i != value.size(); ++i) {
		data[i] = 0;
	}
	value.clear();
}

struct Submission final : std::enable_shared_from_this<Submission> {
	std::string passcode;
	EmergencyActionActivation *activation = nullptr;
	LegacyLockPasscodeSubmit legacySubmit;
	LockSubmissionDone done;
	std::atomic_bool completed = false;
	std::atomic_bool probeHandled = false;

	void Finish(LockSubmissionPath path, bool accepted) {
		if (completed.exchange(true)) {
			return;
		}
		Clear(passcode);
		auto callback = std::move(done);
		if (callback) {
			callback({ path, accepted });
		}
	}

	void Legacy() {
		if (!legacySubmit) {
			Finish(LockSubmissionPath::Rejected, false);
			return;
		}
		auto self = shared_from_this();
		legacySubmit(std::move(passcode), [self](bool accepted) {
			self->Finish(LockSubmissionPath::LegacyPasscode, accepted);
		});
	}

	void ProbeResult(EmergencyVaultResult result) {
		if (completed.load() || probeHandled.exchange(true)) {
			return;
		}
		if (std::holds_alternative<EmergencyVaultNotConfigured>(result)
			|| std::holds_alternative<NoEmergencyCredentialMatch>(result)) {
			Legacy();
			return;
		}
		if (std::holds_alternative<EmergencyVaultUnavailable>(result)) {
			Finish(LockSubmissionPath::Rejected, false);
			return;
		}
		const auto match = std::get<EmergencyCredentialMatch>(std::move(result));
		if (!activation) {
			Finish(LockSubmissionPath::Rejected, false);
			return;
		}
		auto self = shared_from_this();
		activation->Activate(match.actionId, [self](bool activated) {
			self->Finish(
				activated
					? LockSubmissionPath::EmergencyAction
					: LockSubmissionPath::Rejected,
				activated);
		});
	}

};

} // namespace

void SubmitLockScreenPasscode(
		LockScreenSubmit,
		std::string passcode,
		LockScreenCredentialVault *vault,
		EmergencyActionActivation *activation,
		LegacyLockPasscodeSubmit legacySubmit,
		LockSubmissionDone done) {
	auto submission = std::make_shared<Submission>();
	submission->passcode = std::move(passcode);
	submission->activation = activation;
	submission->legacySubmit = std::move(legacySubmit);
	submission->done = std::move(done);
	if (!vault) {
		submission->Legacy();
		return;
	}
	vault->Probe(submission->passcode, [submission](EmergencyVaultResult result) {
		submission->ProbeResult(std::move(result));
	});
}

} // namespace Ayu::EmergencyActions
