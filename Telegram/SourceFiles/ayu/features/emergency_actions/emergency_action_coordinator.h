// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <chrono>
#include <cstddef>
#include <span>

namespace Ayu::EmergencyActions {

enum class CoordinatorResult : uint8_t {
	Complete,
	Partial,
	Rejected,
	UnsupportedAction,
	CheckpointFailed,
};

struct CoordinatorReport final {
	CoordinatorResult result = CoordinatorResult::Rejected;
	JournalStatus journalStatus = JournalStatus::NeedsAttention;
	size_t remoteAttempts = 0;
	size_t localAttempts = 0;
	bool safeDestinationAttempted = false;
	bool remoteDeadlineReached = false;
	bool localCleanupComplete = false;
	bool safeDestinationReady = false;
};

class CoordinatorClock {
public:
	using TimePoint = std::chrono::steady_clock::time_point;
	virtual ~CoordinatorClock() = default;
	[[nodiscard]] virtual TimePoint now() const = 0;
};

class RemoteSessionEffect {
public:
	virtual ~RemoteSessionEffect() = default;
	// The coordinator passes one five-second deadline; adapters must enforce it.
	[[nodiscard]] virtual EffectResult revoke(
		const AccountId &accountId,
		RemoteSessionTargetKind target,
		std::span<const SessionId> sessionIds,
		CoordinatorClock::TimePoint deadline) = 0;
	[[nodiscard]] virtual EffectResult logoutCurrent(
		const AccountId &accountId,
		CoordinatorClock::TimePoint deadline) = 0;
};

class LocalAccountEffect {
public:
	virtual ~LocalAccountEffect() = default;
	// Success means all target data is durably cleared, including on a retry.
	[[nodiscard]] virtual EffectResult clear(const AccountId &accountId) = 0;
};

class SafeDestinationEffect {
public:
	virtual ~SafeDestinationEffect() = default;
	// Recovery may repeat activation if its outcome could not be checkpointed.
	[[nodiscard]] virtual EffectResult activate(
		SafeDestinationKind kind,
		const ProfileId &profileId) = 0;
};

[[nodiscard]] CoordinatorReport RunResetCoordinator(
	EmergencyActionJournal &journal,
	const JournalStore::ExecutionLease &lease,
	RemoteSessionEffect &remote,
	LocalAccountEffect &local,
	SafeDestinationEffect &destination,
	const CoordinatorClock &clock);

[[nodiscard]] CoordinatorReport ResumeResetCoordinator(
	EmergencyActionJournal &journal,
	const JournalStore::ExecutionLease &lease,
	LocalAccountEffect &local,
	SafeDestinationEffect &destination);

} // namespace Ayu::EmergencyActions
