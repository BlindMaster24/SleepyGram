/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/account_registry.h"

#include "base/qt/qt_string.h"

#include <QtCore/QCoreApplication>

#include <cstdio>
#include <initializer_list>

namespace {

using namespace Ayu::ProfileSets;

VerifiedRegistryIdentity ServerIdentity(quint64 id) {
	auto value = QByteArray(8, Qt::Uninitialized);
	for (auto i = 0; i != 8; ++i) {
		value[i] = char(id >> ((7 - i) * 8));
	}
	return {
		.kind = RegistryIdentityKind::ServerUserId,
		.value = value,
	};
}

VerifiedRegistryIdentity LocatorIdentity(char value) {
	return {
		.kind = RegistryIdentityKind::VerifiedLocator,
		.value = QByteArray(32, value),
	};
}

ObservedLegacyAccount Observed(
		QString dataName,
		quint32 slot,
		std::initializer_list<VerifiedRegistryIdentity> identities) {
	return {
		.dataName = std::move(dataName),
		.slot = slot,
		.identities = identities,
	};
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
	const auto environment = QByteArray(16, 'E');
	const auto registry = NewAccountRegistry(environment);
	if (!registry) {
		return 1;
	}
	auto nextId = quint64(1);
	const auto generateId = [&] { return AccountId{ 0, nextId++ }; };
	auto firstObserved = std::vector<ObservedLegacyAccount>{
		Observed(u"profile"_q, 0, { ServerIdentity(101) }),
		Observed(u"profile"_q, 1, { ServerIdentity(202) }),
	};
	RegistryError error = RegistryError::Malformed;
	auto first = ReconcileAccountRegistry(
		*registry,
		environment,
		firstObserved,
		generateId,
		&error);
	check("initial-account-ids-created", first && first->entries.size() == 2
		&& first->entries[0].id == AccountId{ 0, 1 }
		&& first->entries[1].id == AccountId{ 0, 2 });
	if (!first) {
		return 1;
	}
	const auto account101 = first->entries[0].id;
	const auto account202 = first->entries[1].id;
	auto reordered = ReconcileAccountRegistry(
		*first,
		environment,
		{
			Observed(u"profile"_q, 0, { ServerIdentity(202) }),
			Observed(u"profile"_q, 1, { ServerIdentity(101) }),
		},
		generateId,
		&error);
	check("reorder-keeps-identity-ids", reordered
		&& reordered->entries[0].id == account101
		&& reordered->entries[0].slot == 1
		&& reordered->entries[1].id == account202
		&& reordered->entries[1].slot == 0);
	if (!reordered) {
		return 1;
	}
	auto removed = ReconcileAccountRegistry(
		*reordered,
		environment,
		{ Observed(u"profile"_q, 0, { ServerIdentity(202) }) },
		generateId,
		&error);
	check("missing-account-retired", removed
		&& removed->entries[0].retired
		&& !removed->entries[1].retired);
	if (!removed) {
		return 1;
	}
	auto slotReused = ReconcileAccountRegistry(
		*removed,
		environment,
		{
			Observed(u"profile"_q, 0, { ServerIdentity(202) }),
			Observed(u"profile"_q, 1, { ServerIdentity(303) }),
		},
		generateId,
		&error);
	check("reused-slot-gets-new-id", slotReused
		&& slotReused->entries.size() == 3
		&& slotReused->entries[0].id == account101
		&& slotReused->entries[0].retired
		&& slotReused->entries[2].id == AccountId{ 0, 3 }
		&& !slotReused->entries[2].retired);
	if (!slotReused) {
		return 1;
	}
	auto aliasBound = *slotReused;
	const auto bindResult = BindRegistryIdentity(
		&aliasBound,
		account101,
		LocatorIdentity('L'));
	auto aliasObserved = ReconcileAccountRegistry(
		aliasBound,
		environment,
		{
			Observed(u"renamed"_q, 9, { LocatorIdentity('L') }),
			Observed(u"profile"_q, 0, { ServerIdentity(202) }),
			Observed(u"profile"_q, 1, { ServerIdentity(303) }),
		},
		generateId,
		&error);
	check("verified-locator-alias-retains-id", bindResult == RegistryError::None
		&& aliasObserved && aliasObserved->entries[0].id == account101
		&& aliasObserved->entries[0].slot == 9);
	check("environment-mismatch-rejected", !ReconcileAccountRegistry(
		*slotReused,
		QByteArray(16, 'X'),
		firstObserved,
		generateId,
		&error)
		&& error == RegistryError::EnvironmentMismatch);
	const auto encoded = SerializeAccountRegistry(*slotReused, &error);
	const auto decoded = ParseAccountRegistry(encoded, &error);
	check("registry-codec-round-trip", decoded && *decoded == *slotReused);
	const auto duplicateIdentity = ReconcileAccountRegistry(
		*registry,
		environment,
		{
			Observed(u"profile"_q, 0, { ServerIdentity(404) }),
			Observed(u"profile"_q, 1, { ServerIdentity(404) }),
		},
		generateId,
		&error);
	check("duplicate-observed-identity-rejected", !duplicateIdentity
		&& error == RegistryError::DuplicateObservedIdentity);
	const auto malformed = ParseAccountRegistry(encoded.left(encoded.size() - 1), &error);
	check("truncated-registry-rejected", !malformed);

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	return RunChecks();
}
