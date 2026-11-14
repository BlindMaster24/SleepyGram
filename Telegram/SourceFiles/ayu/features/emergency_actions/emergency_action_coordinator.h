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
};

class LocalAccountEffect {
public:
	virtual ~LocalAccountEffect() = default;
	[[nodiscard]] virtual EffectResult clear(const AccountId &accountId) = 0;
};

class SafeDestinationEffect {
public:
	virtual ~SafeDestinationEffect() = default;
	[[nodiscard]] virtual EffectResult activate(
		SafeDestinationKind kind,
		const ProfileId &profileId) = 0;
};

// This coordinator is fixture-only and has no production side-effect adapters.
[[nodiscard]] CoordinatorReport RunResetCoordinator(
	EmergencyActionJournal &journal,
	JournalStore &store,
	RemoteSessionEffect &remote,
	LocalAccountEffect &local,
	SafeDestinationEffect &destination,
	const CoordinatorClock &clock,
	RetryMode retryMode = RetryMode::SafeOnly);

} // namespace Ayu::EmergencyActions
