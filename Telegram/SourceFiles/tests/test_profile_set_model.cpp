/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_sets.h"
#include "base/basic_types.h"

#include <QtCore/QCoreApplication>

#include <cstdio>

namespace {

using namespace Ayu::ProfileSets;

QByteArray Verifier(quint32 value) {
	auto result = QByteArray(kVerifierSize, '\0');
	for (auto i = 0; i != 4; ++i) {
		result[i] = char(value >> (8 * i));
	}
	return result;
}

int RunChecks() {
	auto passed = 0;
	auto total = 0;
	const auto check = [&](const char *name, bool condition) {
		++total;
		if (condition) {
			++passed;
			std::printf("PASS %s\n", name);
		} else {
			std::printf("FAIL %s\n", name);
		}
	};

	auto metadata = Metadata{
		.verifierSalt = QByteArray(kVerifierSaltSize, 's'),
		.verifierKdf = { .kind = 2, .memory = 2, .time = 1, .parallel = 1 },
		.masterVerifier = Verifier(0xFFFFFFFF),
		.sets = {
			{
				.id = { 1, 1 },
				.name = u"Personal"_q,
				.verifier = Verifier(1),
				.accounts = { { 5, 10 }, { 5, 11 } },
			},
			{
				.id = { 1, 2 },
				.name = u"Shared"_q,
				.verifier = Verifier(2),
				.accounts = { { 5, 10 } },
			},
			{
				.id = { 1, 3 },
				.name = u"Empty"_q,
				.verifier = Verifier(3),
			},
		},
	};
	check("empty-and-shared-memberships-valid",
		Validate(metadata) == ValidationError::None);

	const auto serialized = SerializeMetadataPayload(metadata);
	ValidationError parseError = ValidationError::Malformed;
	const auto restored = ParseMetadataPayload(serialized, &parseError);
	check("versioned-round-trip",
		restored && *restored == metadata
		&& parseError == ValidationError::None);
	check("master-password-routes-to-management",
		std::holds_alternative<MasterAccess>(RoutePasswordVerifier(
			metadata,
			Verifier(0xFFFFFFFF))));
	const auto setRoute = RoutePasswordVerifier(metadata, Verifier(2));
	check("normal-password-routes-to-exact-set",
		std::holds_alternative<SetAccess>(setRoute)
		&& std::get<SetAccess>(setRoute).id == SetId{ 1, 2 });
	check("unknown-password-rejected",
		std::holds_alternative<WrongPassword>(RoutePasswordVerifier(
			metadata,
			Verifier(4))));

	auto many = Metadata{
		.verifierSalt = QByteArray(kVerifierSaltSize, 's'),
		.verifierKdf = { .kind = 2, .memory = 2, .time = 1, .parallel = 1 },
		.masterVerifier = Verifier(0xFFFFFFFF),
	};
	for (auto i = quint32(0); i != 1000; ++i) {
		many.sets.push_back({
			.id = { 2, quint64(i) + 1 },
			.name = u"Set %1"_q.arg(i),
			.verifier = Verifier(i),
			.accounts = {},
		});
	}
	check("one-thousand-sets-round-trip",
		Validate(many) == ValidationError::None
		&& ParseMetadataPayload(SerializeMetadataPayload(many)).has_value());

	auto invalid = metadata;
	invalid.version = kMetadataVersion + 1;
	check("unknown-version-rejected",
		Validate(invalid) == ValidationError::UnsupportedVersion);
	invalid = metadata;
	invalid.sets[1].id = invalid.sets[0].id;
	check("duplicate-set-id-rejected",
		Validate(invalid) == ValidationError::DuplicateSetId);
	invalid = metadata;
	invalid.sets[0].accounts.push_back(invalid.sets[0].accounts.front());
	check("duplicate-membership-rejected",
		Validate(invalid) == ValidationError::DuplicateMembership);
	invalid = metadata;
	invalid.sets[0].verifier = invalid.sets[1].verifier;
	check("duplicate-password-rejected",
		Validate(invalid) == ValidationError::DuplicateVerifier);
	invalid = metadata;
	invalid.verifierKdf.memory = 262'144;
	check("kdf-cost-is-bounded",
		Validate(invalid) == ValidationError::InvalidKdf);
	check("oversized-payload-rejected",
		!ParseMetadataPayload(QByteArray(64 * 1024 * 1024 + 1, 'x')));

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	return RunChecks();
}
