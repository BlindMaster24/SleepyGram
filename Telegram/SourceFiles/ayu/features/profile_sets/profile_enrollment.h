// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_generation.h"

namespace MTP {
enum class Environment : uchar;
} // namespace MTP

namespace Ayu::ProfileSets {

struct ScopedEnrollmentRequest final {
	QByteArray expectedTransactionId;
	SetId targetSet;
	QString masterPasscode;
	QString setPasscode;
	UserId userId;
	MTP::Environment environment = {};
	QByteArray authorization;
	QByteArray configuration;
	std::optional<MigrationGenerationProof> expectedRevocableProof;
	QByteArray enrollmentOperation;
};

enum class ScopedEnrollmentResult : uchar {
	Complete,
	Stale,
	InvalidAuthorization,
	InvalidPasscodes,
	RuleUpdateRequired,
	DuplicateAccount,
	StorageFailed,
};

void EnrollScopedAccount(
	MigrationController workspace,
	ScopedEnrollmentRequest request,
	Fn<void(ScopedEnrollmentResult)> done);

} // namespace Ayu::ProfileSets
