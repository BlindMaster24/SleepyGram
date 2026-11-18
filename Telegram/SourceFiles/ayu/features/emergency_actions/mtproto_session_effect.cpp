// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/mtproto_session_effect.h"

#include <algorithm>
#include <charconv>
#include <map>
#include <set>

namespace Ayu::EmergencyActions {
namespace details {
namespace {

struct ApprovedAccount final {
	RemoteSessionTargetKind target = RemoteSessionTargetKind::None;
	std::vector<SessionId> sessions;
	bool revoke = false;
	bool logout = false;
	bool revokeAttempted = false;
};

class BoundSessionEffect final : public RemoteSessionEffect {
public:
	BoundSessionEffect(
		std::map<AccountId, ApprovedAccount> accounts,
		std::unique_ptr<SessionRequestTransport> transport);

	EffectResult revoke(
		const AccountId &accountId,
		RemoteSessionTargetKind target,
		std::span<const SessionId> sessionIds,
		CoordinatorClock::TimePoint deadline) override;
	EffectResult logoutCurrent(
		const AccountId &accountId,
		CoordinatorClock::TimePoint deadline) override;

private:
	[[nodiscard]] bool acceptDeadline(CoordinatorClock::TimePoint deadline);

	std::map<AccountId, ApprovedAccount> _accounts;
	std::unique_ptr<SessionRequestTransport> _transport;
	std::optional<CoordinatorClock::TimePoint> _deadline;

};

BoundSessionEffect::BoundSessionEffect(
	std::map<AccountId, ApprovedAccount> accounts,
	std::unique_ptr<SessionRequestTransport> transport)
: _accounts(std::move(accounts))
, _transport(std::move(transport)) {
}

bool BoundSessionEffect::acceptDeadline(CoordinatorClock::TimePoint deadline) {
	const auto now = std::chrono::steady_clock::now();
	if (now >= deadline || deadline - now > std::chrono::seconds(5)
		|| (_deadline && *_deadline != deadline)) {
		return false;
	}
	_deadline = deadline;
	return true;
}

EffectResult BoundSessionEffect::revoke(
		const AccountId &accountId,
		RemoteSessionTargetKind target,
		std::span<const SessionId> sessionIds,
		CoordinatorClock::TimePoint deadline) {
	const auto found = _accounts.find(accountId);
	if (found == _accounts.end()
		|| !found->second.revoke
		|| found->second.revokeAttempted
		|| target != found->second.target
		|| !std::ranges::equal(sessionIds, found->second.sessions)
		|| !acceptDeadline(deadline)) {
		return EffectResult::Unconfirmed;
	}
	found->second.revokeAttempted = true;
	auto requests = std::vector<SessionRequest>();
	if (target == RemoteSessionTargetKind::AllOtherSessions && sessionIds.empty()) {
		requests.push_back({ .kind = SessionRequestKind::RevokeAllOther });
	} else if (target == RemoteSessionTargetKind::SelectedSessions) {
		auto seen = std::set<uint64_t>();
		for (const auto &session : sessionIds) {
			auto hash = uint64_t();
			const auto begin = session.value.data();
			const auto end = begin + session.value.size();
			const auto [tail, error] = std::from_chars(begin, end, hash);
			if (error != std::errc()
				|| tail != end
				|| !hash
				|| TelegramRemoteSessionId(hash) != session
				|| !seen.insert(hash).second) {
				return EffectResult::Unconfirmed;
			}
			requests.push_back({
				.kind = SessionRequestKind::RevokeSelected,
				.hash = hash,
			});
		}
	}
	return requests.empty()
		? EffectResult::Unconfirmed
		: _transport->send(accountId, requests, deadline);
}

EffectResult BoundSessionEffect::logoutCurrent(
		const AccountId &accountId,
		CoordinatorClock::TimePoint deadline) {
	const auto found = _accounts.find(accountId);
	if (found == _accounts.end()
		|| !found->second.logout
		|| (found->second.revoke && !found->second.revokeAttempted)
		|| !acceptDeadline(deadline)) {
		return EffectResult::Unconfirmed;
	}
	found->second.logout = false;
	const auto request = SessionRequest{ .kind = SessionRequestKind::LogoutCurrent };
	return _transport->send(accountId, std::span(&request, 1), deadline);
}

} // namespace

std::unique_ptr<RemoteSessionEffect> MakeBoundSessionEffect(
		const InstallationId &currentInstallation,
		const EmergencyActionJournal &approved,
		std::unique_ptr<SessionRequestTransport> transport) {
	if (!currentInstallation.valid()
		|| currentInstallation != approved.installationId
		|| !approved.operationId.valid()
		|| approved.action != EmergencyAction::ResetAccountData
		|| !transport) {
		return nullptr;
	}
	auto accounts = std::map<AccountId, ApprovedAccount>();
	for (const auto &account : approved.accounts) {
		if (!account.accountId.valid()
			|| !accounts.emplace(account.accountId, ApprovedAccount{
				.target = account.remoteSessionTarget,
				.sessions = account.sessionIdsForRevoke,
				.revoke = (account.remoteSessionRevoke.state == EffectState::Pending),
				.logout = (account.currentSessionLogout.state == EffectState::Pending),
			}).second) {
			return nullptr;
		}
	}
	return std::make_unique<BoundSessionEffect>(
		std::move(accounts),
		std::move(transport));
}

} // namespace details

SessionId TelegramRemoteSessionId(uint64_t hash) {
	return hash ? SessionId(std::to_string(hash)) : SessionId();
}

} // namespace Ayu::EmergencyActions
