// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_recovery_record.h"

#include <algorithm>
#include <array>
#include <ranges>
#include <set>

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kMagic = std::array<uint8_t, 8>{ 'S', 'G', 'R', 'C', 0, 0, 0, 1 };
constexpr auto kOpaqueIdBytes = size_t(32);
constexpr auto kSizeBytes = size_t(4);

bool CanonicalOpaqueId(std::string_view value) {
	return value.size() == kOpaqueIdBytes
		&& value.find_first_not_of('0') != std::string_view::npos
		&& std::ranges::all_of(value, [](unsigned char byte) {
			return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
		});
}

bool DistinctGenerations(
		std::string_view source,
		std::string_view admission,
		std::string_view successor) {
	return CanonicalOpaqueId(source) && CanonicalOpaqueId(admission)
		&& CanonicalOpaqueId(successor) && source != admission
		&& source != successor && admission != successor;
}

class Writer final {
public:
	explicit Writer(std::vector<uint8_t> &bytes) : _bytes(bytes) {
	}

	void bytes(std::span<const uint8_t> data) {
		_bytes.insert(_bytes.end(), data.begin(), data.end());
	}

	void string(std::string_view text) {
		bytes({ reinterpret_cast<const uint8_t*>(text.data()), text.size() });
	}

	void number(size_t size, size_t width = kSizeBytes) {
		for (auto i = size_t(0); i != width; ++i) {
			_bytes.push_back(uint8_t(size >> (i * 8)));
		}
	}

	void blob(std::span<const uint8_t> data) {
		number(data.size());
		bytes(data);
	}

private:
	std::vector<uint8_t> &_bytes;

};

class Reader final {
public:
	explicit Reader(std::span<const uint8_t> data) : _available(data) {
	}

	[[nodiscard]] std::span<const uint8_t> take(size_t size) {
		if (size > _available.size()) {
			return {};
		}
		const auto result = _available.first(size);
		_available = _available.subspan(size);
		return result;
	}

	[[nodiscard]] std::optional<size_t> number(size_t width = kSizeBytes) {
		const auto encoded = take(width);
		if (encoded.empty()) {
			return std::nullopt;
		}
		auto result = size_t(0);
		for (auto i = size_t(0); i != width; ++i) {
			result |= size_t(encoded[i]) << (i * 8);
		}
		return result;
	}

	[[nodiscard]] std::string opaqueId() {
		const auto value = take(kOpaqueIdBytes);
		return value.empty()
			? std::string()
			: std::string(reinterpret_cast<const char*>(value.data()), value.size());
	}

	[[nodiscard]] std::span<const uint8_t> blob(size_t maximum) {
		const auto size = number();
		return (size && *size && *size <= maximum) ? take(*size) : std::span<const uint8_t>();
	}

	[[nodiscard]] bool done() const {
		return _available.empty();
	}

private:
	std::span<const uint8_t> _available;

};

bool InitialJournal(const EmergencyActionJournal &journal) {
	constexpr auto pending = JournalEffectState{ .state = EffectState::Pending };
	constexpr auto absent = JournalEffectState{ .state = EffectState::NotRequested };
	return journal.accounts.size() <= kMaxEmergencyExecutionAccounts
		&& std::ranges::is_sorted(journal.accounts, {}, &JournalAccount::accountId)
		&& journal.installationRemoval == (journal.action == EmergencyAction::RemoveInstallation
			? pending : absent)
		&& journal.safeDestinationActivation == (journal.safeDestination != SafeDestinationKind::None
			? pending : absent)
		&& std::ranges::all_of(journal.accounts, [&](const auto &account) {
			const auto revoke = account.remoteSessionTarget == RemoteSessionTargetKind::AllOtherSessions
				|| !account.sessionIdsForRevoke.empty();
			return account.localDataClear == pending && account.currentSessionLogout == pending
				&& account.remoteSessionRevoke == (revoke ? pending : absent)
				&& std::ranges::is_sorted(account.sessionIdsForRevoke);
		});
}

std::optional<std::vector<uint8_t>> EncodeRecoveryRecord(
		const EmergencyActionJournal &journal,
		std::span<const EmergencyExecutionAccount> accounts,
		std::string_view source,
		std::string_view admission,
		const EmergencyExecutionSuccessor &successor) {
	const auto encodedJournal = EncodeJournal(journal);
	if (!DistinctGenerations(source, admission, successor.transactionId)
		|| encodedJournal.empty() || !InitialJournal(journal)
		|| accounts.size() != journal.accounts.size()) {
		return std::nullopt;
	}
	const auto sealedVault = successor.sealedProfileVault;
	const auto sealedKeyring = successor.sealedAccountKeyring;
	const auto size = kMagic.size() + 3 * kOpaqueIdBytes + 3 * kSizeBytes + 2
		+ encodedJournal.size() + accounts.size() * kOpaqueIdBytes
		+ sealedVault.size() + sealedKeyring.size();
	if (size > kMaxEmergencyRecoveryRecordBytes || sealedVault.empty() || sealedKeyring.empty()
		|| sealedVault.size() > kMaxEmergencyExecutionSuccessorVaultBytes
		|| sealedKeyring.size() > kMaxEmergencyExecutionSuccessorKeyringBytes) {
		return std::nullopt;
	}
	auto locators = std::vector<std::string_view>();
	auto seen = std::set<std::string_view>();
	for (const auto &target : journal.accounts) {
		const auto account = std::ranges::find(accounts, target.accountId, &EmergencyExecutionAccount::accountId);
		if (account == accounts.end() || !CanonicalOpaqueId(account->locator)
			|| !seen.insert(account->locator).second) {
			return std::nullopt;
		}
		locators.push_back(account->locator);
	}
	auto result = std::vector<uint8_t>();
	result.reserve(size);
	auto writer = Writer(result);
	writer.bytes(kMagic);
	writer.string(source);
	writer.string(admission);
	writer.string(successor.transactionId);
	writer.blob({ reinterpret_cast<const uint8_t*>(encodedJournal.data()), encodedJournal.size() });
	writer.number(locators.size(), 2);
	for (const auto locator : locators) {
		writer.string(locator);
	}
	writer.blob(sealedVault);
	writer.blob(sealedKeyring);
	return result;
}

bool Requested(const JournalEffectState &state) {
	return state.state != EffectState::NotRequested;
}

} // namespace

std::optional<PreparedEmergencyRecoveryRecord> PrepareEmergencyRecoveryRecord(
		const EmergencyRuleTicket &ticket,
		std::span<const uint8_t> sealedCapsule,
		std::span<const uint8_t> emergencyDerivedKey,
		std::string_view admissionGeneration) {
	const auto &details = ticket.details();
	const auto &source = ticket.authority().generation.transactionId;
	const auto live = ticket.reviewedLive();
	if (!live || !CanonicalOpaqueId(admissionGeneration) || source == admissionGeneration) {
		return std::nullopt;
	}
	const auto plan = BuildDryRunPlan(details.operationId, details.rule, *live);
	const auto journal = MakeJournal(plan);
	if (!journal) {
		return std::nullopt;
	}
	auto capsule = OpenEmergencyExecutionCapsule(ticket, plan, sealedCapsule, emergencyDerivedKey);
	if (!capsule) {
		return std::nullopt;
	}
	auto bytes = EncodeRecoveryRecord(
		*journal,
		capsule->accounts(),
		source,
		admissionGeneration,
		capsule->successor());
	if (!bytes) {
		return std::nullopt;
	}
	return PreparedEmergencyRecoveryRecord{ std::move(*bytes), std::move(*capsule) };
}

std::optional<EmergencyRecoveryRecord> DecodeEmergencyRecoveryRecord(
		std::span<const uint8_t> bytes,
		const InstallationId &expectedInstallation,
		std::string_view activeGeneration) {
	if (bytes.size() > kMaxEmergencyRecoveryRecordBytes || !expectedInstallation.valid()
		|| !CanonicalOpaqueId(activeGeneration)) {
		return std::nullopt;
	}
	auto reader = Reader(bytes);
	if (!std::ranges::equal(reader.take(kMagic.size()), kMagic)) {
		return std::nullopt;
	}
	auto result = EmergencyRecoveryRecord{
		.sourceGeneration = reader.opaqueId(),
		.admissionGeneration = reader.opaqueId(),
		.successorGeneration = reader.opaqueId(),
	};
	if (!DistinctGenerations(
			result.sourceGeneration,
			result.admissionGeneration,
			result.successorGeneration)
		|| (activeGeneration != result.admissionGeneration
			&& activeGeneration != result.successorGeneration)) {
		return std::nullopt;
	}
	const auto encodedJournal = reader.blob(kMaxJournalBytes);
	if (encodedJournal.empty()) {
		return std::nullopt;
	}
	auto journal = DecodeJournal(std::as_bytes(encodedJournal));
	if (!journal || journal->installationId != expectedInstallation || !InitialJournal(*journal)) {
		return std::nullopt;
	}
	const auto count = reader.number(2);
	if (!count || *count != journal->accounts.size()) {
		return std::nullopt;
	}
	auto locators = std::set<std::string>();
	for (const auto &target : journal->accounts) {
		auto locator = reader.opaqueId();
		if (!CanonicalOpaqueId(locator) || !locators.insert(locator).second) {
			return std::nullopt;
		}
		result.accounts.push_back({ .accountId = target.accountId, .locator = std::move(locator) });
	}
	const auto vault = reader.blob(kMaxEmergencyExecutionSuccessorVaultBytes);
	const auto keyring = reader.blob(kMaxEmergencyExecutionSuccessorKeyringBytes);
	if (vault.empty() || keyring.empty() || !reader.done()) {
		return std::nullopt;
	}
	result.phase = (activeGeneration == result.admissionGeneration)
		? EmergencyRecoveryPhase::Admission
		: EmergencyRecoveryPhase::Successor;
	result.journal = std::move(*journal);
	result.sealedProfileVault.assign(vault.begin(), vault.end());
	result.sealedAccountKeyring.assign(keyring.begin(), keyring.end());
	return result;
}

bool MatchesEmergencyRecoveryJournal(
		const EmergencyRecoveryRecord &record,
		const EmergencyActionJournal &checkpoint) {
	const auto &planned = record.journal;
	return !EncodeJournal(checkpoint).empty()
		&& checkpoint.operationId == planned.operationId
		&& checkpoint.ruleId == planned.ruleId
		&& checkpoint.installationId == planned.installationId
		&& checkpoint.action == planned.action
		&& checkpoint.targetScope == planned.targetScope
		&& checkpoint.safeDestination == planned.safeDestination
		&& checkpoint.safeProfileId == planned.safeProfileId
		&& Requested(checkpoint.installationRemoval) == Requested(planned.installationRemoval)
		&& Requested(checkpoint.safeDestinationActivation) == Requested(planned.safeDestinationActivation)
		&& std::ranges::equal(checkpoint.accounts, planned.accounts, [](const auto &current, const auto &initial) {
			return current.accountId == initial.accountId
				&& current.remoteSessionTarget == initial.remoteSessionTarget
				&& current.sessionIdsForRevoke == initial.sessionIdsForRevoke
				&& Requested(current.localDataClear) == Requested(initial.localDataClear)
				&& Requested(current.remoteSessionRevoke) == Requested(initial.remoteSessionRevoke)
				&& Requested(current.currentSessionLogout) == Requested(initial.currentSessionLogout);
		});
}

} // namespace Ayu::EmergencyActions
