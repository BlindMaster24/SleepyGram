// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_emergency_bundle.h"
#include "ayu/features/emergency_actions/scoped_account_clear.h"

#include <set>

namespace Ayu::ProfileSets {

struct DerivedCredential;
struct Metadata;

struct RevocableProfileEmergencyBundle final {
	ProfileEmergencyBundle rules;
	std::set<QByteArray> consumed;
	std::map<QByteArray, QByteArray> landings;
};

[[nodiscard]] std::optional<RevocableProfileEmergencyBundle> ParseRevocableProfileEmergencyBundle(
	QByteArrayView installationId,
	QByteArrayView sealed);

[[nodiscard]] QByteArray SerializeRevocableProfileEmergencyBundle(
	const RevocableProfileEmergencyBundle &bundle);

[[nodiscard]] std::optional<RevocableProfileEmergencyBundle> ConsumeRevocableProfileEmergencyRule(
	const RevocableProfileEmergencyBundle &bundle,
	QByteArrayView capsuleDigest,
	QByteArrayView enrollmentOperation = {});

[[nodiscard]] QByteArray RevocableEnrollmentOperation(const EmergencyActions::OperationId &operation);

[[nodiscard]] std::optional<RevocableProfileEmergencyBundle> CompleteRevocableProfileEmergencyEnrollment(
	const RevocableProfileEmergencyBundle &bundle,
	QByteArrayView enrollmentOperation);

[[nodiscard]] bool CanKeepRevocableProfileEmergencyRules(
	QByteArrayView installationId,
	QByteArrayView sealed,
	const DerivedCredential &master,
	const Metadata &before,
	const Metadata &after);

struct RevocableEmergencyCheckpoint final {
	QByteArray activeTransactionId;
	QByteArray gateTableDigest;
	QByteArray rulesDigest;
	QByteArray installationPackageDigest;
	EmergencyActions::EmergencyActionJournal journal;
	std::vector<EmergencyActions::ScopedAccountLocator> accounts;
};

[[nodiscard]] QByteArray SerializeRevocableEmergencyCheckpoint(
	const RevocableEmergencyCheckpoint &checkpoint);

[[nodiscard]] std::optional<RevocableEmergencyCheckpoint> ParseRevocableEmergencyCheckpoint(
	QByteArrayView installationId,
	QByteArrayView transactionId,
	QByteArrayView gateTable,
	QByteArrayView rules,
	QByteArrayView sealed);

} // namespace Ayu::ProfileSets
