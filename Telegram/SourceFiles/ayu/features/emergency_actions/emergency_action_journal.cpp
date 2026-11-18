// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <ranges>
#include <string_view>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kMagic = std::array<uint8_t, 4>{ 'A', 'E', 'J', '1' };
constexpr auto kVersion = uint16_t(4);
constexpr auto kMaxIdBytes = size_t(128);
constexpr auto kMaxAccounts = size_t(64);
constexpr auto kMaxSessionsPerAccount = size_t(128);
constexpr auto kJournalExtension = ".journal";

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
	case EffectState::Skipped:
		return network && value.networkOutcome == NetworkOutcome::NotAttempted;
	}
	return false;
}

bool LocalPhaseStarted(const EmergencyActionJournal &journal) {
	return std::ranges::any_of(journal.accounts, [](const JournalAccount &account) {
		const auto state = account.localDataClear.state;
		return state != EffectState::NotRequested && state != EffectState::Pending;
	});
}

bool RemoteInProgress(const JournalAccount &account) {
	return account.remoteSessionRevoke.state == EffectState::InProgress
		|| account.currentSessionLogout.state == EffectState::InProgress;
}

bool RevokeOutstanding(const JournalAccount &account) {
	return account.remoteSessionRevoke.state == EffectState::Pending
		|| account.remoteSessionRevoke.state == EffectState::InProgress;
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
		? !ValidId(journal.safeProfileId.value)
		: journal.safeProfileId.valid()) {
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
			|| !ValidState(account.currentSessionLogout, true)
			|| (RevokeOutstanding(account)
				&& account.currentSessionLogout.state != EffectState::Pending
				&& account.currentSessionLogout.state != EffectState::NotRequested)
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
	const auto activation = journal.safeDestinationActivation.state;
	if (activation != EffectState::NotRequested
		&& activation != EffectState::Pending
		&& !LocalCleanupComplete(journal)) {
		return false;
	}
	return !LocalPhaseStarted(journal)
		|| std::ranges::none_of(journal.accounts, RemoteInProgress);
}

JournalEffectState *FindEffect(
		EmergencyActionJournal &journal,
		JournalEffect effect,
		const std::optional<AccountId> &accountId) {
	if (effect == JournalEffect::LocalDataClear
		|| effect == JournalEffect::RemoteSessionRevoke
		|| effect == JournalEffect::CurrentSessionLogout) {
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
		if (effect == JournalEffect::LocalDataClear) {
			return &i->localDataClear;
		}
		return (effect == JournalEffect::RemoteSessionRevoke)
			? &i->remoteSessionRevoke
			: &i->currentSessionLogout;
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
	return effect == JournalEffect::RemoteSessionRevoke
		|| effect == JournalEffect::CurrentSessionLogout;
}

bool IsIdempotentEffect(JournalEffect effect) {
	return effect == JournalEffect::LocalDataClear
		|| effect == JournalEffect::SafeDestinationActivation
		|| effect == JournalEffect::InstallationRemoval;
}

bool CanBeginEffect(EffectState state, JournalEffect effect) {
	return state == EffectState::Pending
		|| (state == EffectState::FailedRetryable && !IsNetworkEffect(effect))
		|| (state == EffectState::Unconfirmed && IsIdempotentEffect(effect));
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

	bool string(std::string *value, bool allowEmpty = false) {
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
		return (allowEmpty && value->empty()) || ValidId(*value);
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

bool ReadState(
		Reader &reader,
		JournalEffectState *state,
		uint16_t version) {
	const auto maxState = (version < 3)
		? EffectState::Unconfirmed
		: EffectState::Skipped;
	uint8_t value = 0;
	if (!reader.byte(&value) || value > uint8_t(maxState)) {
		return false;
	}
	state->state = EffectState(value);
	if (!reader.byte(&value) || value > uint8_t(NetworkOutcome::Unconfirmed)) {
		return false;
	}
	state->networkOutcome = NetworkOutcome(value);
	return true;
}

std::filesystem::path JournalFilename(const OperationId &id) {
	constexpr auto digits = std::string_view("abcdefghijklmnopqrstuvwxyz234567");
	auto result = std::string();
	auto buffer = uint32_t(0);
	auto bits = 0;
	for (const auto ch : id.value) {
		buffer = (buffer << 8) | uint8_t(ch);
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			result += digits[(buffer >> bits) & 31];
		}
	}
	if (bits) {
		result += digits[(buffer << (5 - bits)) & 31];
	}
	return result + kJournalExtension;
}

std::vector<std::byte> ReadBytes(
		const std::filesystem::path &path,
		size_t maximumBytes) {
	auto error = std::error_code();
	if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path, error))) {
		return {};
	}
	const auto size = std::filesystem::file_size(path, error);
	if (error || !size || size > std::min(maximumBytes, kMaxJournalBytes)) {
		return {};
	}
	auto input = std::ifstream(path, std::ios::binary);
	auto bytes = std::vector<std::byte>(size);
	if (!input.read(reinterpret_cast<char *>(bytes.data()), bytes.size())
		|| input.peek() != std::char_traits<char>::eof()
		|| input.bad()) {
		return {};
	}
	return bytes;
}

#ifdef _WIN32
using NativeHandle = HANDLE;
const auto kInvalidHandle = INVALID_HANDLE_VALUE;

void CloseHandleIfValid(NativeHandle handle) {
	CloseHandle(handle);
}

bool SyncDirectory(const std::filesystem::path &) {
	return true;
}

bool MakePrivateDirectory(const std::filesystem::path &path) {
	return CreateDirectoryW(path.c_str(), nullptr)
		|| GetLastError() == ERROR_ALREADY_EXISTS;
}

NativeHandle OpenExecutionLock(const std::filesystem::path &path) {
	return CreateFileW(
		path.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		OPEN_ALWAYS,
		FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr);
}

NativeHandle OpenTemporaryFile(const std::filesystem::path &path) {
	return CreateFileW(
		path.c_str(),
		GENERIC_WRITE,
		0,
		nullptr,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
}

bool WriteAndSync(NativeHandle file, std::span<const std::byte> bytes) {
	auto written = DWORD(0);
	return WriteFile(file, bytes.data(), DWORD(bytes.size()), &written, nullptr)
		&& written == bytes.size()
		&& FlushFileBuffers(file);
}

JournalCreateResult Publish(
		const std::filesystem::path &source,
		const std::filesystem::path &target,
		bool replace) {
	const auto flags = MOVEFILE_WRITE_THROUGH
		| (replace ? MOVEFILE_REPLACE_EXISTING : 0);
	if (MoveFileExW(source.c_str(), target.c_str(), flags)) {
		return JournalCreateResult::Created;
	}
	const auto error = GetLastError();
	return (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
		? JournalCreateResult::AlreadyExists
		: JournalCreateResult::Failed;
}

auto NativeProcessId() {
	return GetCurrentProcessId();
}
#else
using NativeHandle = int;
constexpr auto kInvalidHandle = -1;

void CloseHandleIfValid(NativeHandle handle) {
	close(handle);
}

bool MakePrivateDirectory(const std::filesystem::path &path) {
	return mkdir(path.c_str(), S_IRWXU) == 0 || errno == EEXIST;
}

bool SyncDirectory(const std::filesystem::path &path) {
	const auto fd = open(path.empty() ? "." : path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == kInvalidHandle) {
		return false;
	}
	const auto synced = fsync(fd) == 0;
	close(fd);
	return synced;
}

NativeHandle OpenExecutionLock(const std::filesystem::path &path) {
	const auto fd = open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
		S_IRUSR | S_IWUSR);
	if (fd == kInvalidHandle) {
		return kInvalidHandle;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		close(fd);
		return kInvalidHandle;
	}
	return fd;
}

NativeHandle OpenTemporaryFile(const std::filesystem::path &path) {
	return open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
		S_IRUSR | S_IWUSR);
}

bool WriteAndSync(NativeHandle file, std::span<const std::byte> bytes) {
	while (!bytes.empty()) {
		const auto written = write(file, bytes.data(), bytes.size());
		if (written < 0 && errno == EINTR) {
			continue;
		}
		if (written <= 0) {
			return false;
		}
		bytes = bytes.subspan(written);
	}
	return fsync(file) == 0;
}

JournalCreateResult Publish(
		const std::filesystem::path &source,
		const std::filesystem::path &target,
		bool replace) {
	const auto result = replace
		? rename(source.c_str(), target.c_str())
		: link(source.c_str(), target.c_str());
	if (result != 0) {
		return (errno == EEXIST)
			? JournalCreateResult::AlreadyExists
			: JournalCreateResult::Failed;
	}
	return SyncDirectory(target.parent_path())
		? JournalCreateResult::Created
		: JournalCreateResult::Failed;
}

auto NativeProcessId() {
	return getpid();
}
#endif

class NativeFile final {
public:
	explicit NativeFile(NativeHandle handle) : _handle(handle) {
	}
	NativeFile(const NativeFile &) = delete;
	NativeFile &operator=(const NativeFile &) = delete;

	~NativeFile() {
		close();
	}

	void close() {
		if (_handle != kInvalidHandle) {
			CloseHandleIfValid(std::exchange(_handle, kInvalidHandle));
		}
	}

private:
	NativeHandle _handle;

};

class FileExecutionLease final : public JournalStore::ExecutionLease {
public:
	FileExecutionLease(JournalStore &store, NativeHandle file)
	: ExecutionLease(store)
	, _file(file) {
	}

private:
	NativeFile _file;

};

bool PrepareDirectory(const std::filesystem::path &path) {
	auto error = std::error_code();
	return MakePrivateDirectory(path)
		&& std::filesystem::is_directory(std::filesystem::symlink_status(path, error))
		&& SyncDirectory(path.parent_path());
}

JournalCreateResult WriteAtomically(
		const std::filesystem::path &target,
		std::span<const std::byte> bytes,
		bool replace) {
	static auto counter = std::atomic<uint64_t>();
	const auto process = std::to_string(NativeProcessId());
	const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
	const auto temp = target.parent_path() / (process
		+ "-" + std::to_string(now)
		+ "-" + std::to_string(counter.fetch_add(1, std::memory_order_relaxed))
		+ ".tmp");
	const auto handle = OpenTemporaryFile(temp);
	if (handle == kInvalidHandle) {
		return JournalCreateResult::Failed;
	}
	auto file = NativeFile(handle);
	const auto written = WriteAndSync(handle, bytes);
	file.close();
	const auto result = written
		? Publish(temp, target, replace)
		: JournalCreateResult::Failed;
	auto error = std::error_code();
	std::filesystem::remove(temp, error);
	return result;
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
			.currentSessionLogout = { .state = account.wouldClearLocalData
				? EffectState::Pending
				: EffectState::NotRequested },
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
		states.push_back(account.currentSessionLogout.state);
	}
	states.push_back(journal.installationRemoval.state);
	states.push_back(journal.safeDestinationActivation.state);
	if (std::ranges::any_of(states, [](EffectState state) {
		return state == EffectState::Unconfirmed
			|| state == EffectState::FailedRetryable
			|| state == EffectState::Skipped;
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
		const EmergencyActionJournal &journal) {
	auto result = std::vector<PendingEffect>();
	if (!ValidJournal(journal)) {
		return result;
	}
	const auto add = [&](const JournalEffectState &state,
			JournalEffect effect,
			std::optional<AccountId> accountId = std::nullopt) {
		if (effect == JournalEffect::SafeDestinationActivation
			&& !LocalCleanupComplete(journal)) {
			return;
		}
		if (CanBeginEffect(state.state, effect)) {
			result.push_back({ .accountId = std::move(accountId), .effect = effect });
		}
	};
	const auto localStarted = LocalPhaseStarted(journal);
	for (const auto &account : journal.accounts) {
		add(account.localDataClear, JournalEffect::LocalDataClear, account.accountId);
		if (!localStarted) {
			add(account.remoteSessionRevoke, JournalEffect::RemoteSessionRevoke, account.accountId);
			if (!RevokeOutstanding(account)) {
				add(account.currentSessionLogout, JournalEffect::CurrentSessionLogout, account.accountId);
			}
		}
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
	const auto recover = [&](JournalEffectState &state, JournalEffect effect) {
		if (state.state == EffectState::InProgress) {
			state.state = IsIdempotentEffect(effect)
				? EffectState::FailedRetryable
				: EffectState::Unconfirmed;
			state.networkOutcome = IsNetworkEffect(effect)
				? NetworkOutcome::Unconfirmed
				: NetworkOutcome::NotAttempted;
			++recovered;
		}
	};
	for (auto &account : journal.accounts) {
		recover(account.localDataClear, JournalEffect::LocalDataClear);
		recover(account.remoteSessionRevoke, JournalEffect::RemoteSessionRevoke);
		recover(account.currentSessionLogout, JournalEffect::CurrentSessionLogout);
	}
	recover(journal.installationRemoval, JournalEffect::InstallationRemoval);
	recover(journal.safeDestinationActivation, JournalEffect::SafeDestinationActivation);
	return recovered;
}

bool FinishRemotePhase(EmergencyActionJournal &journal) {
	if (!ValidJournal(journal) || std::ranges::any_of(journal.accounts, RemoteInProgress)) {
		return false;
	}
	auto changed = false;
	for (auto &account : journal.accounts) {
		if (account.remoteSessionRevoke.state == EffectState::Pending) {
			account.remoteSessionRevoke.state = EffectState::Skipped;
			changed = true;
		}
		if (account.currentSessionLogout.state == EffectState::Pending) {
			account.currentSessionLogout.state = EffectState::Skipped;
			changed = true;
		}
	}
	return changed;
}

bool LocalCleanupComplete(const EmergencyActionJournal &journal) {
	return std::ranges::all_of(journal.accounts, [](const JournalAccount &account) {
		const auto state = account.localDataClear.state;
		return state == EffectState::Succeeded || state == EffectState::NotRequested;
	});
}

TransitionResult BeginEffect(
		EmergencyActionJournal &journal,
		JournalEffect effect,
		std::optional<AccountId> accountId) {
	if (!ValidJournal(journal)) {
		return TransitionResult::Rejected;
	}
	const auto state = FindEffect(journal, effect, accountId);
	if (!state) {
		return TransitionResult::Rejected;
	}
	if ((IsNetworkEffect(effect) && LocalPhaseStarted(journal))
		|| (effect == JournalEffect::LocalDataClear
			&& std::ranges::any_of(journal.accounts, RemoteInProgress))
		|| ((effect == JournalEffect::SafeDestinationActivation || effect == JournalEffect::InstallationRemoval)
			&& !LocalCleanupComplete(journal))) {
		return TransitionResult::Rejected;
	}
	if (effect == JournalEffect::CurrentSessionLogout) {
		const auto revoke = FindEffect(journal, JournalEffect::RemoteSessionRevoke, accountId);
		if (revoke->state == EffectState::Pending
			|| revoke->state == EffectState::InProgress) {
			return TransitionResult::Rejected;
		}
	}
	if (state->state == EffectState::InProgress
		|| state->state == EffectState::Succeeded) {
		return TransitionResult::AlreadyApplied;
	}
	if (!CanBeginEffect(state->state, effect)) {
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
		WriteState(writer, account.currentSessionLogout);
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
	if (!reader.u16(&version) || version < 1 || version > kVersion) {
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
	if (!reader.string(&result.safeProfileId.value, true)) {
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
		if (!ReadState(reader, &account.localDataClear, version)
			|| !ReadState(reader, &account.remoteSessionRevoke, version)
			|| (version >= 4
				&& !ReadState(reader, &account.currentSessionLogout, version))) {
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
	if (!ReadState(reader, &result.installationRemoval, version)
		|| !ReadState(reader, &result.safeDestinationActivation, version)
		|| !reader.done()
		|| !ValidJournal(result)) {
		return std::nullopt;
	}
	return result;
}

FileJournalStore::FileJournalStore(std::filesystem::path directory)
: _directory(std::move(directory)) {
}

std::unique_ptr<JournalStore::ExecutionLease> FileJournalStore::tryAcquireExecution() {
	if (!PrepareDirectory(_directory)) {
		return nullptr;
	}
	const auto handle = OpenExecutionLock(_directory / "execution.lock");
	return (handle == kInvalidHandle)
		? nullptr
		: std::make_unique<FileExecutionLease>(*this, handle);
}

std::optional<std::vector<OperationId>> FileJournalStore::operationIds() {
	auto result = std::vector<OperationId>();
	auto error = std::error_code();
	auto i = std::filesystem::directory_iterator(_directory, error);
	const auto end = std::filesystem::directory_iterator();
	while (!error && i != end) {
		const auto &path = i->path();
		if (path.extension() == kJournalExtension) {
			const auto bytes = ReadBytes(path, kMaxJournalBytes);
			const auto journal = DecodeJournal(bytes);
			if (!journal || path.filename() != JournalFilename(journal->operationId)) {
				return std::nullopt;
			}
			result.push_back(journal->operationId);
		}
		i.increment(error);
	}
	if (error) {
		return std::nullopt;
	}
	std::ranges::sort(result);
	return result;
}

JournalCreateResult FileJournalStore::createAtomically(
		const OperationId &operationId,
		std::span<const std::byte> bytes) {
	const auto journal = DecodeJournal(bytes);
	if (!journal || journal->operationId != operationId || !PrepareDirectory(_directory)) {
		return JournalCreateResult::Failed;
	}
	return WriteAtomically(_directory / JournalFilename(operationId), bytes, false);
}

std::vector<std::byte> FileJournalStore::read(
		const OperationId &operationId,
		size_t maximumBytes) {
	return ValidId(operationId.value)
		? ReadBytes(_directory / JournalFilename(operationId), maximumBytes)
		: std::vector<std::byte>();
}

bool FileJournalStore::writeAtomically(
		const OperationId &operationId,
		std::span<const std::byte> bytes) {
	const auto journal = DecodeJournal(bytes);
	if (!journal || journal->operationId != operationId) {
		return false;
	}
	const auto path = _directory / JournalFilename(operationId);
	auto error = std::error_code();
	return std::filesystem::is_regular_file(std::filesystem::symlink_status(path, error))
		&& WriteAtomically(path, bytes, true) == JournalCreateResult::Created;
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
