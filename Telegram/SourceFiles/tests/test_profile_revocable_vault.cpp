// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_revocable_vault.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QtEndian>

#include <array>
#include <cstdio>
#include <type_traits>

namespace {

using namespace Ayu::ProfileSets;

static_assert(!std::is_copy_constructible_v<RevocableSetVaultAccess>);
static_assert(!std::is_constructible_v<AccountKey, AccountGateHandle>);

DerivedCredential Credential(char verifier, char key) {
	return { QByteArray(kVerifierSize, verifier), QByteArray(kProfileVaultKeySize, key) };
}

bool Opens(const AccountGateTable &table, const AccountGateHandle &handle,
		const AccountKey &expected) {
	const auto result = OpenAccountGate(table, handle);
	const auto key = std::get_if<AccountKey>(&result);
	return key && *key == expected;
}

bool Denied(RevocableProfileVaultAccess access) {
	return std::holds_alternative<WrongPassword>(access);
}

int RunChecks() {
	auto passed = 0;
	auto total = 0;
	const auto check = [&](const char *name, bool condition) {
		++total;
		passed += int(condition);
		std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	};

	const auto admin = Credential('a', 'A');
	const auto first = Credential('b', 'B');
	const auto second = Credential('c', 'C');
	const auto empty = Credential('d', 'D');
	const auto replacement = Credential('e', 'E');
	const auto third = Credential('f', 'F');
	const auto keyA = AccountKey{ { 1, 2 }, QByteArray(kAccountKeySize, '1') };
	const auto keyB = AccountKey{ { 1, 3 }, QByteArray(kAccountKeySize, '2') };
	const auto locatorA = QByteArray(16, 'x');
	const auto locatorB = QByteArray(16, 'y');
	const auto setA = SetId{ 2, 1 };
	const auto setB = SetId{ 2, 2 };
	const auto setEmpty = SetId{ 2, 3 };
	const auto setC = SetId{ 2, 4 };
	const auto metadata = Metadata{
		.verifierSalt = QByteArray(kVerifierSaltSize, 's'),
		.verifierKdf = { .kind = 1, .memory = 8192, .time = 1, .parallel = 1 },
		.masterVerifier = admin.verifier,
		.sets = {
			{ setB, u"Both"_q, second.verifier, { keyB.id, keyA.id } },
			{ setA, u"First"_q, first.verifier, { keyA.id } },
			{ setEmpty, u"Empty"_q, empty.verifier, {} },
		},
	};
	const auto credentials = std::vector<SetGrantCredential>{
		{ setA, first }, { setB, second }, { setEmpty, empty },
	};
	const auto v2 = SealProfileVault(metadata, { keyA, keyB }, {
		{ keyA.id, locatorA }, { keyB.id, locatorB },
	}, admin, credentials);
	if (!v2) {
		return 1;
	}
	const auto start = AccountGateTable::Create(v2->id);
	auto a = start ? CreateAccountGate(*start, keyA, locatorA) : std::nullopt;
	auto b = a ? CreateAccountGate(a->table, keyB, locatorB) : std::nullopt;
	auto staleA = start ? CreateAccountGate(*start, keyA, locatorA) : std::nullopt;
	if (!a || !b || !staleA) {
		return 1;
	}
	const auto catalog = std::array{
		RevocableAccountGrant{ std::move(b->handle), std::move(b->permit) },
		RevocableAccountGrant{ std::move(a->handle), std::move(a->permit) },
	};
	const auto v3 = RevocableProfileVault::Seal(v2->id, metadata, catalog, admin, credentials);
	if (!v3) {
		return 1;
	}
	const auto encoded = v3->serialize();
	const auto vault = RevocableProfileVault::Parse(encoded);
	if (!vault) {
		return 1;
	}
	check("separate v3 parser and legacy v2 reader accept only their own versions",
		vault->serialize() == encoded
		&& !ParseProfileVault(encoded)
		&& !RevocableProfileVault::Parse(SerializeProfileVault(*v2))
		&& ParseProfileVault(SerializeProfileVault(*v2))
		&& vault->installationId() == v2->id
		&& vault->salt() == metadata.verifierSalt
		&& vault->kdf() == metadata.verifierKdf);
	auto downgraded = encoded;
	downgraded[7] = char(kProfileVaultVersion);
	const auto editedVersion = ParseProfileVault(downgraded);
	check("rewriting the format header cannot route a v3 grant to the DEK decoder",
		editedVersion
		&& std::holds_alternative<WrongPassword>(OpenProfileVault(*editedVersion, admin))
		&& std::holds_alternative<WrongPassword>(OpenProfileVault(*editedVersion, first)));

	const auto firstAccess = vault->open(first);
	const auto secondAccess = vault->open(second);
	const auto emptyAccess = vault->open(empty);
	const auto masterAccess = vault->open(admin);
	const auto oldFirst = OpenProfileVault(*v2, first);
	const auto firstSet = std::get_if<RevocableSetVaultAccess>(&firstAccess);
	const auto secondSet = std::get_if<RevocableSetVaultAccess>(&secondAccess);
	const auto emptySet = std::get_if<RevocableSetVaultAccess>(&emptyAccess);
	const auto oldFirstSet = std::get_if<SetVaultAccess>(&oldFirst);
	const auto master = std::get_if<RevocableAdminVaultAccess>(&masterAccess);
	if (!firstSet || !secondSet || !emptySet || !master || !oldFirstSet) {
		return 1;
	}
	check("ordinary v3 scope opens only typed handles, including scoped overlap and empty sets",
		firstSet->id() == setA && firstSet->handles().size() == 1
		&& Opens(b->table, firstSet->handles().front(), keyA)
		&& secondSet->id() == setB && secondSet->handles().size() == 2
		&& Opens(b->table, secondSet->handles()[0], keyA)
		&& Opens(b->table, secondSet->handles()[1], keyB)
		&& emptySet->id() == setEmpty && emptySet->handles().empty()
		&& emptySet->settingsKey().size() == kProfileVaultKeySize);
	check("physical and settings bindings match the existing v2 scopes",
		firstSet->handles().front().binding().locator == locatorA
		&& firstSet->settingsKey() == oldFirstSet->settingsKey);
	check("master receives authenticated catalog, paired permits and metadata",
		master->metadata == metadata && master->accounts.size() == 2
		&& master->accounts[0].handle.matches(master->accounts[0].permit)
		&& master->accounts[1].handle.matches(master->accounts[1].permit)
		&& !master->accounts[0].handle.matches(master->accounts[1].permit)
		&& !master->accounts[0].handle.matches(staleA->permit));
	check("wrong credentials and same-verifier wrong derived key fail closed",
		Denied(vault->open(third))
		&& Denied(vault->open({ admin.verifier, third.key }))
		&& Denied(vault->open({ first.verifier, third.key }))
		&& !vault->updated(first, metadata, {}));

	const auto revoked = RevokeAccountGates(
		b->table,
		std::span(&master->accounts[0].permit, 1));
	check("unchanged v3 grant is interpreted by the current gate table after revocation",
		revoked && std::holds_alternative<AccountGateRevoked>(
			OpenAccountGate(*revoked, firstSet->handles().front()))
		&& std::holds_alternative<AccountGateRevoked>(
			OpenAccountGate(*revoked, secondSet->handles()[0]))
		&& Opens(*revoked, secondSet->handles()[1], keyB));

	auto changed = metadata;
	changed.sets[0].accounts = { keyB.id };
	changed.sets[1].name = u"Rotated"_q;
	changed.sets[1].verifier = replacement.verifier;
	changed.sets[1].accounts = { keyB.id };
	changed.sets.push_back({ setC, u"New"_q, third.verifier, { keyA.id } });
	const auto nextVault = vault->updated(admin, changed, { { setA, replacement }, { setC, third } });
	if (!nextVault) {
		return 1;
	}
	const auto nextFirst = nextVault->open(replacement);
	const auto nextSecond = nextVault->open(second);
	const auto nextThird = nextVault->open(third);
	const auto nextEmpty = nextVault->open(empty);
	const auto nextFirstSet = std::get_if<RevocableSetVaultAccess>(&nextFirst);
	const auto nextSecondSet = std::get_if<RevocableSetVaultAccess>(&nextSecond);
	const auto nextThirdSet = std::get_if<RevocableSetVaultAccess>(&nextThird);
	const auto nextEmptySet = std::get_if<RevocableSetVaultAccess>(&nextEmpty);
	check("master updates membership and rotates one passcode without unrelated passcodes",
		Denied(nextVault->open(first))
		&& nextFirstSet && nextFirstSet->id() == setA && nextFirstSet->handles().size() == 1
		&& Opens(b->table, nextFirstSet->handles().front(), keyB)
		&& nextSecondSet && nextSecondSet->handles().size() == 1
		&& Opens(b->table, nextSecondSet->handles().front(), keyB)
		&& nextThirdSet && nextThirdSet->handles().size() == 1
		&& Opens(b->table, nextThirdSet->handles().front(), keyA));
	check("rewrite retains installation, credential derivation, settings and locator per scope",
		nextVault->installationId() == vault->installationId() && nextVault->salt() == vault->salt()
		&& nextVault->kdf() == vault->kdf()
		&& nextFirstSet && nextFirstSet->settingsKey() == firstSet->settingsKey()
		&& nextSecondSet && nextSecondSet->settingsKey() == secondSet->settingsKey()
		&& nextThirdSet && nextThirdSet->handles().front().binding().locator == locatorA
		&& nextEmptySet && nextEmptySet->settingsKey() == emptySet->settingsKey());
	auto duplicateVerifier = changed;
	duplicateVerifier.sets[1].verifier = second.verifier;
	auto absentAccount = metadata;
	absentAccount.sets[1].accounts = { { 8, 1 } };
	auto changedSalt = metadata;
	changedSalt.verifierSalt[0] = 't';
	auto removed = metadata;
	removed.sets.erase(removed.sets.begin());
	const auto withoutSecond = vault->updated(admin, removed, {});
	check("master update rejects invalid replacements and can remove a grant",
		!vault->updated(admin, changed, { { setC, third } })
		&& !vault->updated(admin, duplicateVerifier, {})
		&& !vault->updated(admin, absentAccount, {})
		&& !vault->updated(admin, changedSalt, {})
		&& !vault->updated(admin, metadata, { { setB, second } })
		&& withoutSecond && Denied(withoutSecond->open(second)));

	auto wrongHandle = AccountGateHandle::Parse(catalog[1].handle.serialize());
	if (!wrongHandle) {
		return 1;
	}
	const auto wrongPair = RevocableAccountGrant{ std::move(*wrongHandle), std::move(staleA->permit) };
	auto noSets = metadata;
	noSets.sets.clear();
	check("seal rejects same-address stale permit and foreign installation handles",
		!RevocableProfileVault::Seal(v2->id, noSets, std::span(&wrongPair, 1), admin, {})
		&& !RevocableProfileVault::Seal(QByteArray(16, 'q'), metadata, catalog, admin, credentials));

	auto corrupted = details::ParseRevocableProfileEnvelope(encoded, nullptr);
	if (!corrupted) {
		return 1;
	}
	auto &ciphertext = corrupted->grants[1].ciphertext;
	ciphertext[0] = char(ciphertext.at(0) ^ 1);
	const auto tampered = RevocableProfileVault::Parse(
		details::SerializeRevocableProfileEnvelope(*corrupted, nullptr));
	auto wrongId = encoded;
	wrongId[8] = char(wrongId.at(8) ^ 1);
	const auto substituted = RevocableProfileVault::Parse(wrongId);
	check("master authenticates every set grant, and set opening authenticates its own binding",
		tampered && Denied(tampered->open(admin)) && Denied(tampered->open(second))
		&& !tampered->updated(admin, metadata, {})
		&& substituted && Denied(substituted->open(first)) && Denied(substituted->open(admin))
		&& !RevocableProfileVault::Parse(encoded.chopped(1)));

	auto forged = details::ParseRevocableProfileEnvelope(encoded, nullptr);
	if (!forged) {
		return 1;
	}
	const auto setWrap = details::RevocableProfileEnvelopeKey(*forged, setA, first);
	auto setPayload = details::OpenRevocableProfileGrant(*forged, forged->grants.front(), setWrap);
	setPayload.replace(54, AccountGateHandle::kSerializedSize, keyA.key);
	auto forgedSet = details::SealRevocableProfileGrant(
		*forged,
		setA,
		first.verifier,
		setWrap,
		setPayload);
	if (!forgedSet) {
		return 1;
	}
	forged->grants.front() = std::move(*forgedSet);
	const auto forgedVault = RevocableProfileVault::Parse(
		details::SerializeRevocableProfileEnvelope(*forged, nullptr));
	check("correctly encrypted legacy-sized DEKs are rejected by the v3 grant reader",
		forgedVault && Denied(forgedVault->open(first)));

	auto badPairEnvelope = details::ParseRevocableProfileEnvelope(encoded, nullptr);
	if (!badPairEnvelope) {
		return 1;
	}
	const auto masterWrap = details::RevocableProfileEnvelopeKey(*badPairEnvelope, {}, admin);
	auto masterPayload = details::OpenRevocableProfileGrant(*badPairEnvelope, SealedSetGrant{
		.verifier = badPairEnvelope->adminVerifier,
		.nonce = badPairEnvelope->adminNonce,
		.ciphertext = badPairEnvelope->adminCiphertext,
	}, masterWrap);
	const auto firstPermit = 42 + qFromBigEndian<quint32>(masterPayload.constData() + 36)
		+ AccountGateHandle::kSerializedSize;
	masterPayload.replace(firstPermit, AccountGateRevocationPermit::kSerializedSize,
		wrongPair.permit.serialize());
	const auto badPair = details::SealRevocableProfileGrant(
		*badPairEnvelope,
		{},
		admin.verifier,
		masterWrap,
		masterPayload);
	if (!badPair) {
		return 1;
	}
	badPairEnvelope->adminNonce = badPair->nonce;
	badPairEnvelope->adminCiphertext = badPair->ciphertext;
	const auto badPairVault = RevocableProfileVault::Parse(
		details::SerializeRevocableProfileEnvelope(*badPairEnvelope, nullptr));
	check("master reader rejects a mismatched permit despite a valid master AEAD and grant manifest",
		badPairVault && Denied(badPairVault->open(admin)) && !badPairVault->updated(admin, metadata, {}));

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	const auto application = QCoreApplication(argc, argv);
	return RunChecks();
}
