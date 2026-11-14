// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <algorithm>
#include <array>
#include <limits>
#include <ranges>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kMagic = std::array<uint8_t, 4>{ 'A', 'E', 'J', '1' };
constexpr auto kVersion = uint16_t(2);
constexpr auto kMaxIdBytes = size_t(128);
constexpr auto kMaxAccounts = size_t(64);
constexpr auto kMaxSessionsPerAccount = size_t(128);

bool ValidId(const std::string &value) {
	return !value.empty()
		&& value.size() <= kMaxIdBytes
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return (ch >= 'a' && ch <= 'z')
				|| (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9')
				|| ch == '-' || ch == '_' || ch == '.' || ch == ':';
		});
}

template <typename Value>
bool HasDuplicates(const std::vector<Value> &values) {
	auto sorted = values;
	std::ranges::sort(sorted);
	return std::ranges::adjacent_find(sorted) != sorted.end();
}

bool ValidState(const JournalEffectState &value, bool network) {
	switch (value.state) {
	case EffectState::NotRequested:
	case EffectState::Pending:
	case EffectState::InProgress:
		return value.networkOutcome == NetworkOutcome::NotAttempted;
	case EffectState::Succeeded:
		return value.networkOutcome == (network
			? NetworkOutcome::SuccessConfirmed
			: NetworkOutcome::NotAttempted);
	case EffectState::FailedRetryable:
		return value.networkOutcome == (network
			? NetworkOutcome::FailureConfirmed
			: NetworkOutcome::NotAttempted);
	case EffectState::Unconfirmed:
		return value.networkOutcome == (network
			? NetworkOutcome::Unconfirmed
			: NetworkOutcome::NotAttempted);
	}
	return false;
}

bool ValidJournal(const EmergencyActionJournal &journal) {
	if (!ValidId(journal.operationId.value)
		|| !ValidId(journal.ruleId.value)
		|| !ValidId(journal.installationId.value)
		|| journal.accounts.size() > kMaxAccounts
		|| (journal.action == EmergencyAction::ResetAccountData
			&& journal.targetScope == TargetScope::CurrentInstallation)
		|| (journal.action == EmergencyAction::RemoveInstallation
			&& (journal.targetScope != TargetScope::CurrentInstallation
				|| journal.safeDestination != SafeDestinationKind::None))
		|| uint8_t(journal.action) > uint8_t(EmergencyAction::RemoveInstallation)
		|| uint8_t(journal.targetScope) > uint8_t(TargetScope::CurrentInstallation)
		|| uint8_t(journal.safeDestination) > uint8_t(SafeDestinationKind::AddAccount)) {
		return false;
	}
	if ((journal.safeDestination == SafeDestinationKind::Profile)
		!= journal.safeProfileId.valid()) {
		return false;
	}
	auto ids = std::vector<AccountId>();
	ids.reserve(journal.accounts.size());
	for (const auto &account : journal.accounts) {
		const auto target = account.remoteSessionTarget;
		const auto targetState = account.remoteSessionRevoke.state;
		if (!ValidId(account.accountId.value)
			|| account.sessionIdsForRevoke.size() > kMaxSessionsPerAccount
			|| uint8_t(target) > uint8_t(RemoteSessionTargetKind::AllOtherSessions)
			|| !ValidState(account.localDataClear, false)
			|| !ValidState(account.remoteSessionRevoke, true)
			|| (target == RemoteSessionTargetKind::None
				&& (targetState != EffectState::NotRequested
					|| !account.sessionIdsForRevoke.empty()))
			|| (target == RemoteSessionTargetKind::SelectedSessions
				&& ((targetState == EffectState::NotRequested)
					!= account.sessionIdsForRevoke.empty()))
			|| (target == RemoteSessionTargetKind::AllOtherSessions
				&& (targetState == EffectState::NotRequested
					|| !account.sessionIdsForRevoke.empty()))) {
			return false;
		}
		ids.push_back(account.accountId);
		if (!std::ranges::all_of(account.sessionIdsForRevoke, [](const auto &id) {
			return ValidId(id.value);
		}) || HasDuplicates(account.sessionIdsForRevoke)) {
			return false;
		}
	}
	std::ranges::sort(ids);
	if (std::ranges::adjacent_find(ids) != ids.end()) {
		return false;
	}
	if (!ValidState(journal.installationRemoval, false)
		|| !ValidState(journal.safeDestinationActivation, false)) {
		return false;
	}
	if ((journal.action == EmergencyAction::RemoveInstallation)
		!= (journal.installationRemoval.state != EffectState::NotRequested)) {
		return false;
	}
	if ((journal.safeDestination == SafeDestinationKind::None)
		!= (journal.safeDestinationActivation.state == EffectState::NotRequested)) {
		return false;
	}
	return true;
}

JournalEffectState *FindEffect(
		EmergencyActionJournal &journal,
		JournalEffect effect,
		const std::optional<AccountId> &accountId) {
	if (effect == JournalEffect::LocalDataClear
		|| effect == JournalEffect::RemoteSessionRevoke) {
		if (!accountId) {
			return nullptr;
		}
		const auto i = std::ranges::find(
			journal.accounts,
			*accountId,
			&JournalAccount::accountId);
		if (i == journal.accounts.end()) {
			return nullptr;
		}
		return (effect == JournalEffect::LocalDataClear)
			? &i->localDataClear
			: &i->remoteSessionRevoke;
	}
	if (accountId) {
		return nullptr;
	}
	if (effect == JournalEffect::InstallationRemoval) {
		return &journal.installationRemoval;
	}
	if (effect == JournalEffect::SafeDestinationActivation) {
		return &journal.safeDestinationActivation;
	}
	return nullptr;
}

bool IsNetworkEffect(JournalEffect effect) {
	return effect == JournalEffect::RemoteSessionRevoke;
}

class Writer final {
public:
	void byte(uint8_t value) {
		_bytes.push_back(std::byte(value));
	}

	void u16(uint16_t value) {
		byte(uint8_t(value));
		byte(uint8_t(value >> 8));
	}

	void string(const std::string &value) {
		u16(uint16_t(value.size()));
		for (const auto ch : value) {
			byte(uint8_t(ch));
		}
	}

	[[nodiscard]] const std::vector<std::byte> &bytes() const {
		return _bytes;
	}

private:
	std::vector<std::byte> _bytes;
};

class Reader final {
public:
	explicit Reader(std::span<const std::byte> bytes) : _bytes(bytes) {
	}

	bool byte(uint8_t *value) {
		if (!value || _offset == _bytes.size()) {
			return false;
		}
		*value = std::to_integer<uint8_t>(_bytes[_offset++]);
		return true;
	}

	bool u16(uint16_t *value) {
		uint8_t lo = 0;
		uint8_t hi = 0;
		if (!byte(&lo) || !byte(&hi)) {
			return false;
		}
		*value = uint16_t(lo) | (uint16_t(hi) << 8);
		return true;
	}

	bool string(std::string *value) {
		uint16_t size = 0;
		if (!u16(&size) || size > kMaxIdBytes
			|| size > _bytes.size() - _offset) {
			return false;
		}
		value->clear();
		value->reserve(size);
		for (auto i = uint16_t(0); i != size; ++i) {
			uint8_t ch = 0;
			if (!byte(&ch)) {
				return false;
			}
			value->push_back(char(ch));
		}
		return ValidId(*value);
	}

	[[nodiscard]] bool done() const {
		return _offset == _bytes.size();
	}

private:
	std::span<const std::byte> _bytes;
	size_t _offset = 0;
};

void WriteState(Writer &writer, const JournalEffectState &state) {
	writer.byte(uint8_t(state.state));
	writer.byte(uint8_t(state.networkOutcome));
}

bool ReadState(Reader &reader, JournalEffectState *state) {
	uint8_t value = 0;
	if (!reader.byte(&value) || value > uint8_t(EffectState::Unconfirmed)) {
		return false;
	}
	state->state = EffectState(value);
	if (!reader.byte(&value) || value > uint8_t(NetworkOutcome::Unconfirmed)) {
		return false;
	}
	state->networkOutcome = NetworkOutcome(value);
	return true;
}

} // namespace

std::optional<EmergencyActionJournal> MakeJournal(const DryRunPlan &plan) {
	if (plan.status != DryRunStatus::Ready
		|| !ValidId(plan.operationId.value)
		|| !ValidId(plan.ruleId.value)
		|| !ValidId(plan.installationId.value)
		|| plan.accounts.size() > kMaxAccounts) {
		return std::nullopt;
	}
	auto result = EmergencyActionJournal{
		.operationId = plan.operationId,
		.ruleId = plan.ruleId,
		.installationId = plan.installationId,
		.action = plan.action,
		.targetScope = plan.targetScope,
		.safeDestination = plan.safeDestination,
		.safeProfileId = plan.safeProfileId,
	};
	for (const auto &account : plan.accounts) {
		if (!ValidId(account.accountId.value)) {
			return std::nullopt;
		}
		auto sessionTargets = account.sessionIdsForRevokeRequest;
		if (account.remoteTarget == RemoteSessionTargetKind::AllOtherSessions) {
			sessionTargets.clear();
		} else if (account.remoteTarget == RemoteSessionTargetKind::None
			&& !sessionTargets.empty()) {
			return std::nullopt;
		}
		if (sessionTargets.size() > kMaxSessionsPerAccount) {
			return std::nullopt;
		}
		auto entry = JournalAccount{
			.accountId = account.accountId,
			.localDataClear = { .state = account.wouldClearLocalData
				? EffectState::Pending
				: EffectState::NotRequested },
			.remoteSessionTarget = account.remoteTarget,
			.remoteSessionRevoke = { .state = (account.remoteTarget
				== RemoteSessionTargetKind::AllOtherSessions
				|| !sessionTargets.empty())
				? EffectState::Pending
				: EffectState::NotRequested },
			.sessionIdsForRevoke = std::move(sessionTargets),
		};
		std::ranges::sort(entry.sessionIdsForRevoke);
		result.accounts.push_back(std::move(entry));
	}
	result.installationRemoval.state = plan.wouldRemoveInstallation
		? EffectState::Pending
		: EffectState::NotRequested;
	result.safeDestinationActivation.state = (plan.safeDestination
		== SafeDestinationKind::None)
		? EffectState::NotRequested
		: EffectState::Pending;
	return ValidJournal(result)
		? std::optional<EmergencyActionJournal>(std::move(result))
		: std::nullopt;
}

JournalStatus Status(const EmergencyActionJournal &journal) {
	if (!ValidJournal(journal)) {
		return JournalStatus::NeedsAttention;
	}
	auto states = std::vector<EffectState>();
	for (const auto &account : journal.accounts) {
		states.push_back(account.localDataClear.state);
		states.push_back(account.remoteSessionRevoke.state);
	}
	states.push_back(journal.installationRemoval.state);
	states.push_back(journal.safeDestinationActivation.state);
	if (std::ranges::any_of(states, [](EffectState state) {
		return state == EffectState::Unconfirmed
			|| state == EffectState::FailedRetryable;
	})) {
		return JournalStatus::NeedsAttention;
	}
	if (std::ranges::any_of(states, [](EffectState state) {
		return state == EffectState::InProgress;
	})) {
		return JournalStatus::InProgress;
	}
	if (std::ranges::any_of(states, [](EffectState state) {
		return state == EffectState::Pending;
	})) {
		return JournalStatus::Ready;
	}
	return JournalStatus::Complete;
}

std::vector<PendingEffect> ResumeEffects(
		const EmergencyActionJournal &journal,
		RetryMode retryMode) {
	auto result = std::vector<PendingEffect>();
	if (!ValidJournal(journal)) {
		return result;
	}
	const auto add = [&](const JournalEffectState &state,
			JournalEffect effect,
			std::optional<AccountId> accountId = std::nullopt) {
		if (state.state == EffectState::Pending
			|| state.state == EffectState::FailedRetryable
			|| (state.state == EffectState::Unconfirmed
				&& retryMode == RetryMode::ExplicitlyRetryUnconfirmed)) {
			result.push_back({ .accountId = std::move(accountId), .effect = effect });
		}
	};
	for (const auto &account : journal.accounts) {
		add(account.localDataClear, JournalEffect::LocalDataClear, account.accountId);
		add(account.remoteSessionRevoke, JournalEffect::RemoteSessionRevoke, account.accountId);
	}
	add(journal.installationRemoval, JournalEffect::InstallationRemoval);
	add(journal.safeDestinationActivation, JournalEffect::SafeDestinationActivation);
	return result;
}

size_t RecoverInterruptedEffects(EmergencyActionJournal &journal) {
	if (!ValidJournal(journal)) {
		return 0;
	}
	auto recovered = size_t(0);
	const auto recover = [&](JournalEffectState &state, bool network) {
		if (state.state == EffectState::InProgress) {
			state.state = EffectState::Unconfirmed;
			state.networkOutcome = network
				? NetworkOutcome::Unconfirmed
				: NetworkOutcome::NotAttempted;
			++recovered;
		}
	};
	for (auto &account : journal.accounts) {
		recover(account.localDataClear, false);
		recover(account.remoteSessionRevoke, true);
	}
	recover(journal.installationRemoval, false);
	recover(journal.safeDestinationActivation, false);
	return recovered;
}

TransitionResult BeginEffect(
		EmergencyActionJournal &journal,
		JournalEffect effect,
		std::optional<AccountId> accountId,
		RetryMode retryMode) {
	if (!ValidJournal(journal)) {
		return TransitionResult::Rejected;
	}
	const auto state = FindEffect(journal, effect, accountId);
	if (!state) {
		return TransitionResult::Rejected;
	}
	if (effect == JournalEffect::RemoteSessionRevoke) {
		const auto account = std::ranges::find(
			journal.accounts,
			*accountId,
			&JournalAccount::accountId);
		if (account->localDataClear.state == EffectState::Succeeded) {
			return TransitionResult::Rejected;
		}
	}
	if (state->state == EffectState::InProgress
		|| state->state == EffectState::Succeeded) {
		return TransitionResult::AlreadyApplied;
	}
	if (state->state == EffectState::Unconfirmed
		&& retryMode != RetryMode::ExplicitlyRetryUnconfirmed) {
		return TransitionResult::Rejected;
	}
	if (state->state != EffectState::Pending
		&& state->state != EffectState::FailedRetryable
		&& state->state != EffectState::Unconfirmed) {
		return TransitionResult::Rejected;
	}
	state->state = EffectState::InProgress;
	state->networkOutcome = NetworkOutcome::NotAttempted;
	return TransitionResult::Applied;
}

TransitionResult ResolveEffect(
		EmergencyActionJournal &journal,
		JournalEffect effect,
		EffectResult result,
		std::optional<AccountId> accountId) {
	if (!ValidJournal(journal)
		|| uint8_t(result) > uint8_t(EffectResult::Unconfirmed)) {
		return TransitionResult::Rejected;
	}
	const auto state = FindEffect(journal, effect, accountId);
	if (!state) {
		return TransitionResult::Rejected;
	}
	auto next = *state;
	if (IsNetworkEffect(effect)) {
		switch (result) {
		case EffectResult::ConfirmedSuccess:
			next = { EffectState::Succeeded, NetworkOutcome::SuccessConfirmed };
			break;
		case EffectResult::ConfirmedFailure:
			next = { EffectState::FailedRetryable, NetworkOutcome::FailureConfirmed };
			break;
		case EffectResult::Unconfirmed:
			next = { EffectState::Unconfirmed, NetworkOutcome::Unconfirmed };
			break;
		}
	} else {
		switch (result) {
		case EffectResult::ConfirmedSuccess:
			next = { EffectState::Succeeded, NetworkOutcome::NotAttempted };
			break;
		case EffectResult::ConfirmedFailure:
			next = { EffectState::FailedRetryable, NetworkOutcome::NotAttempted };
			break;
		case EffectResult::Unconfirmed:
			next = { EffectState::Unconfirmed, NetworkOutcome::NotAttempted };
			break;
		}
	}
	if (*state == next) {
		return TransitionResult::AlreadyApplied;
	}
	if (state->state != EffectState::InProgress) {
		return TransitionResult::Rejected;
	}
	*state = next;
	return TransitionResult::Applied;
}

std::vector<std::byte> EncodeJournal(const EmergencyActionJournal &journal) {
	if (!ValidJournal(journal)) {
		return {};
	}
	auto writer = Writer();
	for (const auto ch : kMagic) writer.byte(ch);
	writer.u16(kVersion);
	writer.string(journal.operationId.value);
	writer.string(journal.ruleId.value);
	writer.string(journal.installationId.value);
	writer.byte(uint8_t(journal.action));
	writer.byte(uint8_t(journal.targetScope));
	writer.byte(uint8_t(journal.safeDestination));
	writer.string(journal.safeProfileId.value);
	writer.u16(uint16_t(journal.accounts.size()));
	for (const auto &account : journal.accounts) {
		writer.string(account.accountId.value);
		writer.byte(uint8_t(account.remoteSessionTarget));
		WriteState(writer, account.localDataClear);
		WriteState(writer, account.remoteSessionRevoke);
		writer.u16(uint16_t(account.sessionIdsForRevoke.size()));
		for (const auto &sessionId : account.sessionIdsForRevoke) {
			writer.string(sessionId.value);
		}
	}
	WriteState(writer, journal.installationRemoval);
	WriteState(writer, journal.safeDestinationActivation);
	return (writer.bytes().size() <= kMaxJournalBytes)
		? writer.bytes()
		: std::vector<std::byte>();
}

std::optional<EmergencyActionJournal> DecodeJournal(
		std::span<const std::byte> bytes) {
	if (bytes.size() > kMaxJournalBytes || bytes.size() < 6) {
		return std::nullopt;
	}
	auto reader = Reader(bytes);
	for (const auto expected : kMagic) {
		uint8_t actual = 0;
		if (!reader.byte(&actual) || actual != expected) {
			return std::nullopt;
		}
	}
	uint16_t version = 0;
	if (!reader.u16(&version) || (version != 1 && version != kVersion)) {
		return std::nullopt;
	}
	auto result = EmergencyActionJournal();
	if (!reader.string(&result.operationId.value)
		|| !reader.string(&result.ruleId.value)
		|| !reader.string(&result.installationId.value)) {
		return std::nullopt;
	}
	uint8_t value = 0;
	if (!reader.byte(&value) || value > uint8_t(EmergencyAction::RemoveInstallation)) {
		return std::nullopt;
	}
	result.action = EmergencyAction(value);
	if (!reader.byte(&value) || value > uint8_t(TargetScope::CurrentInstallation)) {
		return std::nullopt;
	}
	result.targetScope = TargetScope(value);
	if (!reader.byte(&value) || value > uint8_t(SafeDestinationKind::AddAccount)) {
		return std::nullopt;
	}
	result.safeDestination = SafeDestinationKind(value);
	if (!reader.string(&result.safeProfileId.value)
		&& result.safeDestination == SafeDestinationKind::Profile) {
		return std::nullopt;
	}
	uint16_t count = 0;
	if (!reader.u16(&count) || count > kMaxAccounts) {
		return std::nullopt;
	}
	result.accounts.reserve(count);
	for (auto i = uint16_t(0); i != count; ++i) {
		auto account = JournalAccount();
		if (!reader.string(&account.accountId.value)) {
			return std::nullopt;
		}
		if (version >= 2) {
			if (!reader.byte(&value)
				|| value > uint8_t(RemoteSessionTargetKind::AllOtherSessions)) {
				return std::nullopt;
			}
			account.remoteSessionTarget = RemoteSessionTargetKind(value);
		}
		if (!ReadState(reader, &account.localDataClear)
			|| !ReadState(reader, &account.remoteSessionRevoke)) {
			return std::nullopt;
		}
		uint16_t sessionCount = 0;
		if (!reader.u16(&sessionCount)
			|| sessionCount > kMaxSessionsPerAccount) {
			return std::nullopt;
		}
		account.sessionIdsForRevoke.reserve(sessionCount);
		for (auto j = uint16_t(0); j != sessionCount; ++j) {
			auto id = SessionId();
			if (!reader.string(&id.value)) {
				return std::nullopt;
			}
			account.sessionIdsForRevoke.push_back(std::move(id));
		}
		if (version == 1) {
			// Version 1 stored resolved IDs, so legacy retries stay exact-only.
			account.remoteSessionTarget = account.sessionIdsForRevoke.empty()
				? RemoteSessionTargetKind::None
				: RemoteSessionTargetKind::SelectedSessions;
		}
		result.accounts.push_back(std::move(account));
	}
	if (!ReadState(reader, &result.installationRemoval)
		|| !ReadState(reader, &result.safeDestinationActivation)
		|| !reader.done()
		|| !ValidJournal(result)) {
		return std::nullopt;
	}
	return result;
}

bool SaveJournal(
		JournalStore &store,
		const EmergencyActionJournal &journal) {
	const auto bytes = EncodeJournal(journal);
	return !bytes.empty()
		&& store.writeAtomically(journal.operationId, bytes);
}

std::optional<EmergencyActionJournal> LoadJournal(
		JournalStore &store,
		const OperationId &operationId) {
	if (!ValidId(operationId.value)) {
		return std::nullopt;
	}
	const auto bytes = store.read(operationId, kMaxJournalBytes);
	const auto result = DecodeJournal(bytes);
	return (result && result->operationId == operationId)
		? result
		: std::nullopt;
}

} // namespace Ayu::EmergencyActions
