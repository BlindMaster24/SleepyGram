// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/account_gate_table.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

#include <array>
#include <cstdio>
#include <type_traits>

namespace {

using namespace Ayu::ProfileSets;

static_assert(!std::is_copy_constructible_v<AccountGateHandle>);
static_assert(!std::is_copy_constructible_v<AccountGateRevocationPermit>);

bool Opens(const AccountGateTable &table, const AccountGateHandle &handle,
		const AccountKey &expected) {
	const auto result = OpenAccountGate(table, handle);
	const auto key = std::get_if<AccountKey>(&result);
	return key && *key == expected;
}

bool Revoked(const AccountGateTable &table, const AccountGateHandle &handle) {
	return std::holds_alternative<AccountGateRevoked>(OpenAccountGate(table, handle));
}

bool Unavailable(const AccountGateTable &table, const AccountGateHandle &handle) {
	return std::holds_alternative<AccountGateUnavailable>(OpenAccountGate(table, handle));
}

std::span<const AccountGateRevocationPermit> SinglePermit(
		const AccountGateRevocationPermit &permit) {
	return { &permit, 1 };
}

int RunChecks() {
	auto passed = 0;
	auto total = 0;
	const auto check = [&](const char *name, bool condition) {
		++total;
		passed += int(condition);
		std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	};

	const auto install = QByteArray(16, 'i');
	const auto foreignInstall = QByteArray(16, 'j');
	const auto locatorA = QByteArray(16, 'a');
	const auto locatorB = QByteArray(16, 'b');
	const auto locatorC = QByteArray(16, 'c');
	const auto keyA = AccountKey{ { 1, 2 }, QByteArray(kAccountKeySize, 'A') };
	const auto keyB = AccountKey{ { 1, 3 }, QByteArray(kAccountKeySize, 'B') };
	const auto keyC = AccountKey{ { 2, 1 }, QByteArray(kAccountKeySize, 'C') };
	const auto empty = AccountGateTable::Create(install);
	const auto foreign = AccountGateTable::Create(foreignInstall);
	if (!empty || !foreign) {
		return 1;
	}
	const auto b = CreateAccountGate(*empty, keyB, locatorB);
	const auto a = b ? CreateAccountGate(b->table, keyA, locatorA) : std::nullopt;
	const auto c = a ? CreateAccountGate(a->table, keyC, locatorC) : std::nullopt;
	const auto anotherA = CreateAccountGate(*empty, keyA, locatorA);
	if (!a || !b || !c || !anotherA) {
		return 1;
	}
	const auto &live = c->table;
	const auto encoded = SerializeAccountGateTable(live);
	const auto directory = QTemporaryDir();
	auto file = QFile(directory.filePath(u"gates"_q));
	if (!directory.isValid() || !file.open(QIODevice::WriteOnly)
		|| file.write(encoded) != encoded.size() || !file.flush()) {
		return 1;
	}
	file.close();
	if (!file.open(QIODevice::ReadOnly)) {
		return 1;
	}
	const auto restored = ParseAccountGateTable(file.readAll(), install);
	if (!restored) {
		return 1;
	}
	check("bounded canonical round trip out of insertion order",
		restored->installationId() == install
		&& SerializeAccountGateTable(*restored) == encoded
		&& ParseAccountGateTable(SerializeAccountGateTable(*empty), install)
		&& !AccountGateTable::Create(QByteArray(16, '\0'))
		&& !AccountGateTable::Create(install.chopped(1)));
	check("each handle opens only its own published DEK",
		Opens(*restored, a->handle, keyA)
		&& Opens(*restored, b->handle, keyB)
		&& Opens(*restored, c->handle, keyC)
		&& Unavailable(b->table, a->handle)
		&& Unavailable(live, anotherA->handle)
		&& Unavailable(*foreign, a->handle));
	check("creation refuses invalid keys, IDs, locators and duplicate binding",
		!CreateAccountGate(live, { {}, keyA.key }, locatorA)
		&& !CreateAccountGate(*empty, { keyA.id, QByteArray(kAccountKeySize, '\0') }, locatorA)
		&& !CreateAccountGate(*empty, keyA, QByteArray(16, '\0'))
		&& !CreateAccountGate(live, keyA, QByteArray(16, 'd'))
		&& !CreateAccountGate(live, { { 4, 1 }, keyA.key }, locatorA));

	const auto aBytes = a->handle.serialize();
	const auto aPermitBytes = a->permit.serialize();
	const auto savedHandle = AccountGateHandle::Parse(aBytes);
	const auto savedPermit = AccountGateRevocationPermit::Parse(aPermitBytes);
	if (!savedHandle || !savedPermit) {
		return 1;
	}
	check("capability codecs enforce type, extent and nonzero material",
		savedHandle->binding() == a->handle.binding()
		&& savedPermit->binding() == a->permit.binding()
		&& Opens(*restored, *savedHandle, keyA)
		&& !AccountGateHandle::Parse(aPermitBytes)
		&& !AccountGateRevocationPermit::Parse(aBytes)
		&& !AccountGateHandle::Parse(aBytes.chopped(1))
		&& !AccountGateRevocationPermit::Parse(aPermitBytes + 'z')
		&& !AccountGateHandle::Parse(aBytes.first(53) + QByteArray(64, '\0'))
		&& !AccountGateRevocationPermit::Parse(aPermitBytes.first(53) + QByteArray(32, '\0')));

	auto linkedHandle = aBytes;
	linkedHandle.replace(21, 32, b->handle.serialize().sliced(21, 32));
	auto relocatedHandle = aBytes;
	relocatedHandle.replace(37, 16, locatorB);
	auto linkedPermit = aPermitBytes;
	linkedPermit.replace(21, 32, b->permit.serialize().sliced(21, 32));
	auto relocatedPermit = aPermitBytes;
	relocatedPermit.replace(37, 16, locatorB);
	const auto parsedLinked = AccountGateHandle::Parse(linkedHandle);
	const auto parsedRelocated = AccountGateHandle::Parse(relocatedHandle);
	const auto parsedLinkedPermit = AccountGateRevocationPermit::Parse(linkedPermit);
	const auto parsedRelocatedPermit = AccountGateRevocationPermit::Parse(relocatedPermit);
	check("account and locator substitution refuses handles and permits",
		parsedLinked && Unavailable(live, *parsedLinked)
		&& parsedRelocated && Unavailable(live, *parsedRelocated)
		&& parsedLinkedPermit && !RevokeAccountGates(live, SinglePermit(*parsedLinkedPermit))
		&& parsedRelocatedPermit && !RevokeAccountGates(live, SinglePermit(*parsedRelocatedPermit)));
	check("missing, foreign, empty and stale permits cannot authorize revocation",
		!RevokeAccountGates(*empty, SinglePermit(a->permit))
		&& !RevokeAccountGates(*foreign, SinglePermit(a->permit))
		&& !RevokeAccountGates(live, SinglePermit(anotherA->permit))
		&& !RevokeAccountGates(live, {}));

	const auto tryBatch = [&](const QByteArray &first, const QByteArray &second) {
		auto one = AccountGateRevocationPermit::Parse(first);
		auto two = AccountGateRevocationPermit::Parse(second);
		if (!one || !two) {
			return std::optional<AccountGateTable>();
		}
		const auto permits = std::array{ std::move(*one), std::move(*two) };
		return RevokeAccountGates(live, permits);
	};
	const auto batch = tryBatch(aPermitBytes, b->permit.serialize());
	check("batches require unique exact permits before altering any row",
		!tryBatch(b->permit.serialize(), anotherA->permit.serialize())
		&& !tryBatch(aPermitBytes, aPermitBytes)
		&& batch && Revoked(*batch, a->handle) && Revoked(*batch, b->handle)
		&& Opens(live, a->handle, keyA) && Opens(live, b->handle, keyB));

	const auto withoutA = RevokeAccountGates(*restored, SinglePermit(*savedPermit));
	const auto withoutAB = withoutA
		? RevokeAccountGates(*withoutA, SinglePermit(b->permit))
		: std::nullopt;
	if (!withoutA || !withoutAB) {
		return 1;
	}
	check("sequential disjoint revocation retains unrelated access",
		Revoked(*withoutA, *savedHandle)
		&& Opens(*withoutA, b->handle, keyB)
		&& Opens(*withoutA, c->handle, keyC)
		&& Revoked(*withoutAB, *savedHandle)
		&& Revoked(*withoutAB, b->handle)
		&& Opens(*withoutAB, c->handle, keyC)
		&& Unavailable(*withoutAB, anotherA->handle)
		&& !CreateAccountGate(*withoutAB, keyA, locatorA)
		&& !CreateAccountGate(*withoutAB, { { 4, 1 }, keyA.key }, locatorA));
	const auto revokedEncoded = SerializeAccountGateTable(*withoutAB);
	const auto revokedReloaded = ParseAccountGateTable(revokedEncoded, install);
	const auto retried = RevokeAccountGates(*withoutAB, SinglePermit(*savedPermit));
	check("authenticated tombstones survive reloading and exact replay is idempotent",
		revokedReloaded && Revoked(*revokedReloaded, *savedHandle)
		&& Revoked(*revokedReloaded, b->handle)
		&& Opens(*revokedReloaded, c->handle, keyC)
		&& retried && SerializeAccountGateTable(*retried) == revokedEncoded
		&& !RevokeAccountGates(*withoutAB, SinglePermit(anotherA->permit)));

	constexpr auto kHeader = 23;
	constexpr auto kActiveRow = 189;
	constexpr auto kReadCommitmentEnd = kHeader + 65;
	constexpr auto kPermitProofEnd = kReadCommitmentEnd + 64;
	auto malformed = encoded;
	malformed[kHeader] = char(2);
	auto malformedKeyring = encoded;
	malformedKeyring[kHeader + 97] = char(0);
	auto excess = encoded;
	excess[21] = char(0xFF);
	auto unsorted = encoded;
	unsorted.replace(kHeader, 2 * kActiveRow, encoded.sliced(kHeader + kActiveRow, kActiveRow)
		+ encoded.sliced(kHeader, kActiveRow));
	auto duplicateLocator = encoded;
	duplicateLocator.replace(kHeader + 17, 16, locatorB);
	check("parser rejects wrong installation, malformed rows and noncanonical encoding",
		!ParseAccountGateTable(encoded, foreignInstall)
		&& !ParseAccountGateTable(encoded.chopped(1), install)
		&& !ParseAccountGateTable(encoded + 'z', install)
		&& !ParseAccountGateTable(malformed, install)
		&& !ParseAccountGateTable(malformedKeyring, install)
		&& !ParseAccountGateTable(excess, install)
		&& !ParseAccountGateTable(unsorted, install)
		&& !ParseAccountGateTable(duplicateLocator, install));

	auto ciphertext = encoded;
	const auto cipherEnd = kHeader + kActiveRow - 1;
	ciphertext[cipherEnd] = char(ciphertext.at(cipherEnd) ^ 1);
	const auto corruptActive = ParseAccountGateTable(ciphertext, install);
	auto proof = revokedEncoded;
	const auto proofEnd = kPermitProofEnd - 1;
	proof[proofEnd] = char(proof.at(proofEnd) ^ 1);
	check("ciphertext and tombstone proof tampering fail closed",
		corruptActive && Unavailable(*corruptActive, *savedHandle)
		&& Opens(*corruptActive, b->handle, keyB)
		&& !ParseAccountGateTable(proof, install));

	const auto wrongRevocation = RevokeAccountGates(anotherA->table, SinglePermit(anotherA->permit));
	if (!wrongRevocation) {
		return 1;
	}
	auto falseProof = revokedEncoded;
	falseProof.replace(kReadCommitmentEnd, 64,
		SerializeAccountGateTable(*wrongRevocation).sliced(kReadCommitmentEnd, 64));
	const auto corruptRevoked = ParseAccountGateTable(falseProof, install);
	check("even a self-consistent replacement tombstone cannot pass the original handle",
		corruptRevoked && Unavailable(*corruptRevoked, *savedHandle)
		&& Revoked(*corruptRevoked, b->handle));

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	const auto application = QCoreApplication(argc, argv);
	return RunChecks();
}
