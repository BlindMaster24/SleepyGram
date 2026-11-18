// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/mtproto_session_effect.h"

#include <cstdlib>
#include <iostream>
#include <limits>

namespace {

using namespace Ayu::EmergencyActions;
using namespace Ayu::EmergencyActions::details;
using TimePoint = CoordinatorClock::TimePoint;

const auto kInstallation = InstallationId("installation");
const auto kSelected = AccountId("selected");
const auto kAll = AccountId("all");

void Check(bool condition, const char *description) {
	if (!condition) {
		std::cerr << "FAIL " << description << '\n';
		std::exit(1);
	}
	std::cout << "PASS " << description << '\n';
}

struct Sent final {
	AccountId accountId;
	std::vector<SessionRequest> requests;
	TimePoint deadline;
};

class RecordingTransport final : public SessionRequestTransport {
public:
	EffectResult send(
		const AccountId &accountId,
		std::span<const SessionRequest> requests,
		TimePoint deadline) override {
		sent.push_back({ accountId, { requests.begin(), requests.end() }, deadline });
		return result;
	}

	std::vector<Sent> sent;
	EffectResult result = EffectResult::ConfirmedSuccess;

};

EmergencyActionJournal Journal(std::vector<SessionId> sessions) {
	return {
		.operationId = OperationId("operation"),
		.installationId = kInstallation,
		.action = EmergencyAction::ResetAccountData,
		.accounts = {
			{
				.accountId = kSelected,
				.remoteSessionTarget = RemoteSessionTargetKind::SelectedSessions,
				.remoteSessionRevoke = { .state = EffectState::Pending },
				.sessionIdsForRevoke = std::move(sessions),
				.currentSessionLogout = { .state = EffectState::Pending },
			},
			{
				.accountId = kAll,
				.remoteSessionTarget = RemoteSessionTargetKind::AllOtherSessions,
				.remoteSessionRevoke = { .state = EffectState::Pending },
			},
		},
	};
}

void CheckRejectedHashes(TimePoint deadline) {
	for (const auto *hash : { "0", "", "+1", "01", "-1", " 1", "18446744073709551616" }) {
		const auto targets = std::vector{ SessionId(hash) };
		const auto journal = Journal(targets);
		auto transport = std::make_unique<RecordingTransport>();
		const auto recording = transport.get();
		const auto effect = MakeBoundSessionEffect(
			kInstallation, journal, std::move(transport));
		Check(effect
			&& effect->revoke(
				kSelected,
				RemoteSessionTargetKind::SelectedSessions,
				targets,
				deadline) == EffectResult::Unconfirmed
			&& recording->sent.empty(),
			"invalid Telegram hash does not reach transport");
	}
}

} // namespace

int main() {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
	const auto high = std::numeric_limits<uint64_t>::max();
	const auto targets = std::vector{
		TelegramRemoteSessionId(42),
		TelegramRemoteSessionId(high),
	};
	const auto journal = Journal(targets);
	auto transport = std::make_unique<RecordingTransport>();
	const auto recording = transport.get();
	const auto effect = MakeBoundSessionEffect(
		kInstallation, journal, std::move(transport));
	Check(bool(effect), "approved account policy binds");
	Check(!MakeBoundSessionEffect(
		InstallationId("another"),
		journal,
		std::make_unique<RecordingTransport>()),
		"journal from another installation rejected");
	Check(effect->logoutCurrent(AccountId("unknown"), deadline)
		== EffectResult::Unconfirmed && recording->sent.empty(),
		"unapproved account cannot send");
	Check(effect->logoutCurrent(kSelected, deadline)
		== EffectResult::Unconfirmed && recording->sent.empty(),
		"current logout waits for authorized revocation attempt");
	Check(effect->revoke(kSelected, RemoteSessionTargetKind::AllOtherSessions, {}, deadline)
		== EffectResult::Unconfirmed && recording->sent.empty(),
		"selected sessions cannot be escalated to all others");
	Check(effect->revoke(
		kSelected,
		RemoteSessionTargetKind::SelectedSessions,
		std::span(targets).first(1),
		deadline) == EffectResult::Unconfirmed && recording->sent.empty(),
		"substituted selected session policy rejected");
	recording->result = EffectResult::ConfirmedFailure;
	Check(effect->revoke(
		kSelected,
		RemoteSessionTargetKind::SelectedSessions,
		targets,
		deadline) == EffectResult::ConfirmedFailure
		&& recording->sent.size() == 1
		&& recording->sent.front().requests == std::vector<SessionRequest>{
			{ SessionRequestKind::RevokeSelected, 42 },
			{ SessionRequestKind::RevokeSelected, high },
		},
		"selected hash batch is exact and preserves all 64 bits");
	Check(effect->logoutCurrent(kSelected, deadline + std::chrono::milliseconds(1))
		== EffectResult::Unconfirmed && recording->sent.size() == 1,
		"subsequent request cannot change shared deadline");
	recording->result = EffectResult::ConfirmedSuccess;
	Check(effect->logoutCurrent(kSelected, deadline) == EffectResult::ConfirmedSuccess
		&& recording->sent.size() == 2
		&& recording->sent.back().deadline == recording->sent.front().deadline
		&& recording->sent.back().requests == std::vector<SessionRequest>{
			{ SessionRequestKind::LogoutCurrent },
		},
		"failed revocation does not suppress current logout");
	Check(effect->logoutCurrent(kSelected, deadline) == EffectResult::Unconfirmed
		&& recording->sent.size() == 2,
		"same authorized request is attempted only once");
	Check(effect->revoke(
		kAll, RemoteSessionTargetKind::AllOtherSessions, {},
		std::chrono::steady_clock::now()) == EffectResult::Unconfirmed
		&& recording->sent.size() == 2,
		"expired deadline refuses dispatch");
	Check(effect->revoke(
		kAll, RemoteSessionTargetKind::AllOtherSessions, {}, deadline)
			== EffectResult::ConfirmedSuccess
		&& recording->sent.size() == 3
		&& recording->sent.back().requests == std::vector<SessionRequest>{
			{ SessionRequestKind::RevokeAllOther },
		},
		"explicit all-other policy emits one dedicated request");
	CheckRejectedHashes(deadline);
}
