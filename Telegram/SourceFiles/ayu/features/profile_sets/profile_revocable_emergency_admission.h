// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_revocable_emergency_bundle.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_capability.h"
#include "ayu/features/profile_sets/profile_vault.h"

namespace Ayu::ProfileSets {

using ResolveRevocableEmergencyNamedStores = std::function<
	std::optional<EmergencyActions::ScopedWebviewStoreIds>(
		const AccountKey&,
		const AccountGateBinding&,
		const EmergencyActions::EmergencyScopedRemoteIdentity&)>;

using ResolveRevocableEmergencyPackage = std::function<
	std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest>(
		const EmergencyActions::InstallationId&)>;

struct RevocableEmergencyRemoteAccount final {
	EmergencyActions::AccountId accountId;
	AccountGateBinding binding;
	AccountKey key;
	EmergencyActions::EmergencyScopedRemoteIdentity identity;
};

struct InvalidRevocableEmergencyAdmission final {};
struct ConsumedRevocableEmergencyAdmission final {
	QByteArray enrollmentOperation;
};

class PreparedRevocableEmergencyAdmission;

using RevocableEmergencyAdmissionResult = std::variant<
	EmergencyActions::WrongPasscode,
	InvalidRevocableEmergencyAdmission,
	ConsumedRevocableEmergencyAdmission,
	RevokedRevocableEmergencyTargets,
	PreparedRevocableEmergencyAdmission>;

class PreparedRevocableEmergencyAdmission final {
public:
	PreparedRevocableEmergencyAdmission(PreparedRevocableEmergencyAdmission&&) noexcept;
	~PreparedRevocableEmergencyAdmission();

	[[nodiscard]] const MigrationGenerationProof &sourceProof() const;
	[[nodiscard]] const QByteArray &nextTransactionId() const;
	[[nodiscard]] const QByteArray &gateTable() const;
	[[nodiscard]] const QByteArray &rules() const;
	[[nodiscard]] const QByteArray &receipt() const;
	[[nodiscard]] const RevocableEmergencyCheckpoint &checkpoint() const;
	[[nodiscard]] std::span<const RevocableEmergencyRemoteAccount> remoteAccounts() const;
	[[nodiscard]] const std::optional<SetGrantCredential> &safeSet() const;

private:
	friend RevocableEmergencyAdmissionResult PrepareRevocableEmergencyAdmission(
		const CommittedMigration&,
		QByteArrayView,
		const DerivedCredential&,
		const ResolveRevocableEmergencyPackage&,
		const ResolveRevocableEmergencyNamedStores&);

	struct Data;
	explicit PreparedRevocableEmergencyAdmission(std::unique_ptr<Data> data);
	std::unique_ptr<Data> _data;

};

// Commit against sourceProof() before using any prepared effects.
[[nodiscard]] RevocableEmergencyAdmissionResult PrepareRevocableEmergencyAdmission(
	const CommittedMigration &committed,
	QByteArrayView nextTransactionId,
	const DerivedCredential &credential,
	const ResolveRevocableEmergencyPackage &resolvePackage = {},
	const ResolveRevocableEmergencyNamedStores &resolveNamedStores = {});

} // namespace Ayu::ProfileSets
