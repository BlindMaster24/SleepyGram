// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_emergency_bundle.h"

#include "ayu/features/profile_sets/profile_revocable_emergency_capability.h"
#include "ayu/features/profile_sets/profile_vault.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QtEndian>

#include <algorithm>

namespace Ayu::ProfileSets {
namespace {

constexpr char kMagic[] = "SGEB3";
constexpr char kCheckpointMagic[] = "SGER3";
constexpr auto kIdBytes = qsizetype(16);
constexpr auto kDigestBytes = qsizetype(32);
constexpr auto kBundleLimit = qsizetype(4 * 1024 * 1024);
constexpr auto kRules = EmergencyActions::kMaxSealedEmergencyRules;

namespace EA = EmergencyActions;

QByteArray Digest(QByteArrayView data) {
	return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
}

bool IsId(QByteArrayView data) {
	return data.size() == kIdBytes && data != QByteArray(kIdBytes, '\0');
}

bool IsRevocableCapability(QByteArrayView data) {
	return data.startsWith(QByteArrayView(
		reinterpret_cast<const char*>(kRevocableEmergencyCapabilityMagic.data()),
		kRevocableEmergencyCapabilityMagic.size()));
}

QByteArray Epoch(const EmergencyActions::EmergencyRuleAuthority &authority) {
	const auto hex = QByteArray::fromStdString(authority.generation.transactionId);
	const auto decoded = QByteArray::fromHex(hex);
	return (IsId(decoded) && decoded.toHex() == hex) ? decoded : QByteArray();
}

void WriteSize(QByteArray &bytes, quint32 value) {
	const auto encoded = qToBigEndian(value);
	bytes.append(reinterpret_cast<const char*>(&encoded), sizeof(encoded));
}

QByteArrayView Take(QByteArrayView &bytes, qsizetype size) {
	if (size < 0 || size > bytes.size()) {
		return {};
	}
	const auto result = bytes.first(size);
	bytes = bytes.sliced(size);
	return result;
}

std::optional<quint32> ReadSize(QByteArrayView &bytes) {
	const auto found = Take(bytes, sizeof(quint32));
	return found.isEmpty() ? std::nullopt
		: std::optional(qFromBigEndian<quint32>(found.constData()));
}

EmergencyActions::EmergencyRuleAuthority MakeAuthority(
		QByteArrayView installationId,
		QByteArrayView epoch,
		QByteArrayView rules) {
	auto result = EmergencyActions::EmergencyRuleAuthority{
		.generation = {
			.installationId = EmergencyActions::InstallationId(installationId.toByteArray().toHex().toStdString()),
			.transactionId = epoch.toByteArray().toHex().toStdString(),
		},
	};
	const auto digest = Digest(rules);
	std::copy_n(digest.constData(), kDigestBytes, result.digest.begin());
	return result;
}

bool MatchesTargets(const RevocableEmergencyCheckpoint &checkpoint) {
	const auto &journal = checkpoint.journal;
	const auto &accounts = checkpoint.accounts;
	if (accounts.size() != journal.accounts.size()
		|| accounts.size() > EA::kMaxEmergencyExecutionAccounts) {
		return false;
	}
	auto locators = std::set<std::string>();
	auto namedStores = std::set<EA::ScopedWebviewStoreId>();
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto &account = accounts[i];
		const auto hex = QByteArray::fromStdString(account.locator);
		const auto locator = QByteArray::fromHex(hex);
		if (account.accountId != journal.accounts[i].accountId
			|| !IsId(locator) || locator.toHex() != hex
			|| !locators.emplace(account.locator).second
			|| account.namedWebviewStores.has_value() != accounts.front().namedWebviewStores.has_value()) {
			return false;
		}
		if (account.namedWebviewStores) {
			const auto &stores = *account.namedWebviewStores;
			if (!EA::ValidScopedWebviewStoreIds(stores)) {
				return false;
			}
			for (const auto &store : stores) {
				if (!namedStores.insert(store).second) {
					return false;
				}
			}
		}
	}
	return true;
}

} // namespace

std::optional<RevocableProfileEmergencyBundle> ParseRevocableProfileEmergencyBundle(
		QByteArrayView installationId,
		QByteArrayView sealed) {
	const auto magic = QByteArrayView(kMagic);
	if (!IsId(installationId) || sealed.size() > kBundleLimit
		|| Take(sealed, magic.size()) != magic) {
		return std::nullopt;
	}
	const auto epoch = Take(sealed, kIdBytes);
	const auto rules = Take(sealed, qsizetype(EmergencyActions::SealedEmergencyRulesSize()));
	if (!IsId(epoch) || rules.isEmpty()) {
		return std::nullopt;
	}
	const auto remaining = ReadSize(sealed);
	if (!remaining || *remaining > kRules) {
		return std::nullopt;
	}
	auto result = RevocableProfileEmergencyBundle();
	result.rules.authority = MakeAuthority(installationId, epoch, rules);
	result.rules.rules = rules.toByteArray();
	for (auto i = quint32(0); i != *remaining; ++i) {
		const auto digest = Take(sealed, kDigestBytes);
		const auto size = ReadSize(sealed);
		const auto capsule = size ? Take(sealed, *size) : QByteArrayView();
		if (digest.isEmpty() || !IsRevocableCapability(capsule) || Digest(capsule) != digest
			|| (!result.rules.capsules.empty() && digest <= result.rules.capsules.rbegin()->first)) {
			return std::nullopt;
		}
		result.rules.capsules.emplace(digest.toByteArray(), capsule.toByteArray());
	}
	const auto used = ReadSize(sealed);
	if (!used || *used > kRules - *remaining || sealed.size() < *used * kDigestBytes) {
		return std::nullopt;
	}
	for (auto i = quint32(0); i != *used; ++i) {
		const auto digest = Take(sealed, kDigestBytes);
		if ((!result.consumed.empty() && digest <= *result.consumed.rbegin())
			|| result.rules.capsules.contains(digest.toByteArray())) {
			return std::nullopt;
		}
		result.consumed.emplace(digest.toByteArray());
	}
	const auto pending = ReadSize(sealed);
	if (!pending || *pending > *used || sealed.size() != *pending * (kDigestBytes + kIdBytes)) {
		return std::nullopt;
	}
	auto operations = std::set<QByteArray>();
	for (auto i = quint32(0); i != *pending; ++i) {
		const auto digest = Take(sealed, kDigestBytes).toByteArray();
		const auto operation = Take(sealed, kIdBytes).toByteArray();
		if (!IsId(operation) || !result.consumed.contains(digest)
			|| (!result.landings.empty() && digest <= result.landings.rbegin()->first)
			|| !operations.insert(operation).second) {
			return std::nullopt;
		}
		result.landings.emplace(digest, operation);
	}
	return result;
}

QByteArray SerializeRevocableProfileEmergencyBundle(const RevocableProfileEmergencyBundle &bundle) {
	const auto &rules = bundle.rules;
	const auto epoch = Epoch(rules.authority);
	const auto idHex = QByteArray::fromStdString(rules.authority.generation.installationId.value);
	const auto id = QByteArray::fromHex(idHex);
	if (epoch.isEmpty() || !IsId(id) || id.toHex() != idHex
		|| size_t(rules.rules.size()) != EmergencyActions::SealedEmergencyRulesSize()
		|| rules.capsules.size() + bundle.consumed.size() > kRules
		|| bundle.landings.size() > bundle.consumed.size()
		|| rules.authority != MakeAuthority(id, epoch, rules.rules)) {
		return {};
	}
	auto result = QByteArray(kMagic) + epoch + rules.rules;
	WriteSize(result, quint32(rules.capsules.size()));
	for (const auto &[digest, encrypted] : rules.capsules) {
		if (digest.size() != kDigestBytes || !IsRevocableCapability(encrypted) || Digest(encrypted) != digest
			|| encrypted.size() > kBundleLimit - result.size() - kDigestBytes - qsizetype(sizeof(quint32))) {
			return {};
		}
		result.append(digest);
		WriteSize(result, quint32(encrypted.size()));
		result.append(encrypted);
	}
	WriteSize(result, quint32(bundle.consumed.size()));
	for (const auto &digest : bundle.consumed) {
		if (digest.size() != kDigestBytes || rules.capsules.contains(digest)) {
			return {};
		}
		result.append(digest);
	}
	WriteSize(result, quint32(bundle.landings.size()));
	auto operations = std::set<QByteArray>();
	for (const auto &[digest, operation] : bundle.landings) {
		if (!bundle.consumed.contains(digest) || !IsId(operation) || !operations.insert(operation).second) {
			return {};
		}
		result.append(digest);
		result.append(operation);
	}
	return (result.size() <= kBundleLimit) ? result : QByteArray();
}

std::optional<RevocableProfileEmergencyBundle> ConsumeRevocableProfileEmergencyRule(
		const RevocableProfileEmergencyBundle &bundle,
		QByteArrayView capsuleDigest,
		QByteArrayView enrollmentOperation) {
	const auto digest = capsuleDigest.toByteArray();
	if (digest.size() != kDigestBytes || !bundle.rules.capsules.contains(digest)
		|| bundle.consumed.contains(digest) || (!enrollmentOperation.isEmpty()
			&& (!IsId(enrollmentOperation) || std::ranges::any_of(bundle.landings, [&](const auto &entry) {
				return entry.second == enrollmentOperation;
			})))) {
		return std::nullopt;
	}
	auto result = bundle;
	result.rules.capsules.erase(digest);
	result.consumed.insert(digest);
	if (!enrollmentOperation.isEmpty()) {
		result.landings.emplace(digest, enrollmentOperation.toByteArray());
	}
	return result;
}

QByteArray RevocableEnrollmentOperation(const EA::OperationId &operation) {
	if (!operation.valid()) {
		return {};
	}
	return Digest(QByteArray("SleepyGram emergency enrollment operation v3/")
		+ QByteArray::fromStdString(operation.value)).first(kIdBytes);
}

std::optional<RevocableProfileEmergencyBundle> CompleteRevocableProfileEmergencyEnrollment(
		const RevocableProfileEmergencyBundle &bundle,
		QByteArrayView enrollmentOperation) {
	const auto found = std::ranges::find_if(bundle.landings, [&](const auto &item) {
		return item.second == enrollmentOperation;
	});
	if (!IsId(enrollmentOperation) || found == bundle.landings.end()) {
		return std::nullopt;
	}
	auto result = bundle;
	result.landings.erase(found->first);
	return result;
}

bool CanKeepRevocableProfileEmergencyRules(
		QByteArrayView installationId,
		QByteArrayView sealed,
		const DerivedCredential &master,
		const Metadata &before,
		const Metadata &after) {
	if (sealed.isEmpty()) {
		return true;
	}
	const auto bundle = ParseRevocableProfileEmergencyBundle(installationId, sealed);
	if (!bundle || !master.valid()) {
		return false;
	}
	const auto bytes = [](QByteArrayView value) {
		return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(value.data()), size_t(value.size()));
	};
	const auto id = [](SetId id) {
		return u"%1%2"_q.arg(qulonglong(id.high), 16, 16, QChar('0'))
			.arg(qulonglong(id.low), 16, 16, QChar('0')).toStdString();
	};
	auto normals = std::vector<EA::NormalCredential>();
	normals.reserve(after.sets.size());
	for (const auto &set : after.sets) {
		auto verifier = EA::CredentialVerifier();
		if (size_t(set.verifier.size()) != verifier.size()) {
			return false;
		}
		std::ranges::copy(bytes(set.verifier), verifier.begin());
		normals.push_back({ EA::NormalPasscodeId(id(set.id)), verifier });
	}
	const auto authority = bundle->rules.authority;
	const auto rules = bytes(bundle->rules.rules);
	const auto key = bytes(master.key);
	const auto entries = EA::OpenEmergencyRulesForMaster(authority, rules, key);
	if (!entries || !EA::EmergencyRulesAcceptNormalCredentials(authority, rules, key, normals)) {
		return false;
	}
	for (const auto &entry : *entries) {
		const auto &details = entry.details;
		if (!details.executionCapsuleDigest) {
			return false;
		}
		const auto &hash = *details.executionCapsuleDigest;
		const auto digest = QByteArray(reinterpret_cast<const char*>(hash.data()), hash.size());
		if (bundle->consumed.contains(digest)) {
			continue;
		} else if (!bundle->rules.capsules.contains(digest)) {
			return false;
		}
		const auto safe = details.rule.safeProfileId;
		if (safe.valid()) {
			const auto isSafe = [&](const auto &set) { return id(set.id) == safe.value; };
			const auto original = std::ranges::find_if(before.sets, isSafe);
			const auto updated = std::ranges::find_if(after.sets, isSafe);
			if (original == before.sets.end() || updated == after.sets.end()
				|| original->verifier != updated->verifier || original->accounts != updated->accounts) {
				return false;
			}
		}
	}
	return true;
}

QByteArray SerializeRevocableEmergencyCheckpoint(const RevocableEmergencyCheckpoint &checkpoint) {
	const auto &journal = checkpoint.journal;
	const auto installationHex = QByteArray::fromStdString(journal.installationId.value);
	const auto installation = QByteArray::fromHex(installationHex);
	const auto removing = (journal.action == EA::EmergencyAction::RemoveInstallation);
	if (!IsId(installation) || installation.toHex() != installationHex
		|| !IsId(checkpoint.activeTransactionId)
		|| checkpoint.gateTableDigest.size() != kDigestBytes
		|| checkpoint.rulesDigest.size() != kDigestBytes
		|| (removing ? (checkpoint.installationPackageDigest.size() != kDigestBytes
				|| checkpoint.installationPackageDigest == QByteArray(kDigestBytes, '\0'))
			: !checkpoint.installationPackageDigest.isEmpty())
		|| EA::Status(journal) != EA::JournalStatus::Ready || !MatchesTargets(checkpoint)) {
		return {};
	}
	const auto seed = EA::EncodeJournal(journal);
	if (seed.empty() || seed.size() > EA::kMaxJournalBytes) {
		return {};
	}
	auto result = QByteArray(kCheckpointMagic) + installation + checkpoint.activeTransactionId
		+ checkpoint.gateTableDigest + checkpoint.rulesDigest;
	result.append(char(removing));
	result.append(checkpoint.installationPackageDigest);
	WriteSize(result, quint32(seed.size()));
	result.append(reinterpret_cast<const char*>(seed.data()), seed.size());
	for (const auto &target : checkpoint.accounts) {
		result.append(QByteArray::fromHex(QByteArray::fromStdString(target.locator)));
		result.append(target.namedWebviewStores ? char(1 + target.namedWebviewStores->size()) : char(0));
		if (target.namedWebviewStores) {
			for (const auto &store : *target.namedWebviewStores) {
				result.append(reinterpret_cast<const char*>(store.data()), store.size());
			}
		}
	}
	return result;
}

std::optional<RevocableEmergencyCheckpoint> ParseRevocableEmergencyCheckpoint(
		QByteArrayView installationId,
		QByteArrayView transactionId,
		QByteArrayView gateTable,
		QByteArrayView rules,
		QByteArrayView sealed) {
	const auto original = sealed;
	const auto magic = QByteArrayView(kCheckpointMagic);
	if (!IsId(installationId) || !IsId(transactionId) || gateTable.isEmpty() || rules.isEmpty()
		|| sealed.size() > kBundleLimit || Take(sealed, magic.size()) != magic
		|| Take(sealed, kIdBytes) != installationId || Take(sealed, kIdBytes) != transactionId) {
		return std::nullopt;
	}
	const auto gateDigest = Take(sealed, kDigestBytes);
	const auto rulesDigest = Take(sealed, kDigestBytes);
	if (gateDigest != Digest(gateTable) || rulesDigest != Digest(rules)) {
		return std::nullopt;
	}
	const auto packageMarker = Take(sealed, 1);
	if (packageMarker.isEmpty() || uchar(packageMarker.front()) > 1) {
		return std::nullopt;
	}
	const auto package = packageMarker.front() ? Take(sealed, kDigestBytes) : QByteArrayView();
	const auto size = ReadSize(sealed);
	const auto seed = (size && *size <= EA::kMaxJournalBytes) ? Take(sealed, *size) : QByteArrayView();
	const auto journal = seed.isEmpty() ? std::nullopt : EA::DecodeJournal({
		reinterpret_cast<const std::byte*>(seed.constData()), size_t(seed.size()),
	});
	if (!journal || journal->installationId.value != installationId.toByteArray().toHex().toStdString()
		|| journal->accounts.size() > EA::kMaxEmergencyExecutionAccounts) {
		return std::nullopt;
	}
	auto result = RevocableEmergencyCheckpoint{
		.activeTransactionId = transactionId.toByteArray(),
		.gateTableDigest = gateDigest.toByteArray(),
		.rulesDigest = rulesDigest.toByteArray(),
		.installationPackageDigest = package.toByteArray(),
		.journal = *journal,
	};
	result.accounts.reserve(journal->accounts.size());
	for (const auto &account : journal->accounts) {
		const auto locator = Take(sealed, kIdBytes);
		const auto marker = Take(sealed, 1);
		if (!IsId(locator) || marker.isEmpty() || uchar(marker.front()) > 3) {
			return std::nullopt;
		}
		auto target = EA::ScopedAccountLocator{
			.accountId = account.accountId,
			.locator = locator.toByteArray().toHex().toStdString(),
		};
		if (marker.front()) {
			auto &stores = target.namedWebviewStores.emplace();
			for (auto i = 1; i != marker.front(); ++i) {
				const auto bytes = Take(sealed, kIdBytes);
				if (!IsId(bytes)) {
					return std::nullopt;
				}
				auto store = EA::ScopedWebviewStoreId();
				std::copy_n(bytes.constData(), store.size(), store.begin());
				stores.push_back(store);
			}
		}
		result.accounts.push_back(std::move(target));
	}
	return (sealed.isEmpty() && SerializeRevocableEmergencyCheckpoint(result) == original)
		? std::optional(std::move(result)) : std::nullopt;
}

} // namespace Ayu::ProfileSets
