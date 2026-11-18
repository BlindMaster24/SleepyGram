/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#if defined _DEBUG || defined TDESKTOP_RELEASE_TEST_HARNESS

#include "core/application.h"
#include "main/main_account.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/storage_account.h"
#include "test/test_log.h"
#include "test/test_runner.h"
#include "wallet/wallet_vault.h"

#include <QtCore/QTemporaryDir>

namespace Test {
namespace {

using namespace Wallet;
using State = KeyringReading::State;

constexpr auto kFirstWallet = uint64(101);
constexpr auto kSecondWallet = uint64(102);

MTP::AuthKeyPtr FixtureStorageKey(gsl::byte seed) {
	auto key = MTP::AuthKey::Data();
	key.fill(seed);
	return std::make_shared<MTP::AuthKey>(key);
}

std::optional<DeviceKeyring> FixtureRing() {
	const auto prepared = PrepareVaultPasscodeWrap(QByteArray("wallet-factor-a"));
	if (!prepared) {
		return std::nullopt;
	}
	auto ring = RotateDeviceKeyring({}, {}, *prepared);
	if (!ring) {
		return std::nullopt;
	}
	auto entry = SealDeviceKeyringEntry(
		ring->key,
		QByteArray(kVaultKeyIdSize, 'a'),
		kFirstWallet,
		SecureBytes(QByteArray(kVaultKeySize, 'b')));
	if (!entry) {
		return std::nullopt;
	}
	ring->keyring.entries.push_back(std::move(*entry));
	return std::move(ring->keyring);
}

void CheckScopedCodec(const DeviceKeyring &ring) {
	const auto encoded = SerializeDeviceKeyring(ring);
	const auto accepted = ParseScopedDeviceKeyring(encoded, kFirstWallet);
	Check(
		accepted.state == State::Read && accepted.keyring.entries.size() == 1,
		u"Scoped keyring accepts its own bound entry"_q);
	Check(
		ParseScopedDeviceKeyring(encoded, kSecondWallet).state == State::Broken,
		u"Scoped keyring rejects another account's entries"_q);
	const auto correct = DeriveVaultWrapKey(
		ring.wrap, QByteArray("wallet-factor-a"));
	const auto wrong = DeriveVaultWrapKey(
		ring.wrap, QByteArray("wallet-factor-b"));
	Check(
		correct && UnwrapVaultKey(ring.wrap, *correct)
			&& wrong && !UnwrapVaultKey(ring.wrap, *wrong),
		u"Scoped custody requires its independent wallet passcode"_q);
	auto old = ring;
	old.wrap.kdf = {};
	old.wrap.openSecret = QByteArray(kVaultOpenSecretSize, 'c');
	for (const auto kind : { VaultKind::Open, VaultKind::TouchId, VaultKind::WindowsHello }) {
		old.wrap.kind = kind;
		const auto legacy = SerializeDeviceKeyring(old);
		Check(
			!legacy.isEmpty()
				&& ParseScopedDeviceKeyring(legacy, kFirstWallet).state == State::Unsupported,
			u"Scoped storage declines legacy device and open protection"_q);
	}
}

void CheckScopedRuntime(
		const Storage::AccountPaths &firstPaths,
		const Storage::AccountPaths &secondPaths,
		const DeviceKeyring &ring) {
	const auto domain = &Core::App().domain();
	auto first = Main::Account(domain, firstPaths);
	auto second = Main::Account(domain, secondPaths);
	first.prepareToStartAdded(FixtureStorageKey(gsl::byte(1)));
	second.prepareToStartAdded(FixtureStorageKey(gsl::byte(2)));
	const auto firstVault = std::make_shared<VaultRuntime>(first, kFirstWallet);
	const auto secondVault = std::make_shared<VaultRuntime>(second, kSecondWallet);
	Check(
		firstVault->usesScopedStorage()
			&& secondVault->usesScopedStorage()
			&& firstVault->canInitializeScopedKeyring()
			&& secondVault->canInitializeScopedKeyring(),
		u"Scoped vaults initialize from separate empty account stores"_q);
	Check(
		firstVault->writeKeyring(ring) && firstVault->reading().state == State::Read
			&& secondVault->reading().state == State::Absent
			&& !secondVault->writeKeyring(ring),
		u"Writing one account's keyring leaves the other account untouched"_q);
	for (auto count = 0; count != 3; ++count) {
		firstVault->recordPasscodeTry(false);
	}
	Check(
		!firstVault->canTryPasscode() && secondVault->canTryPasscode(),
		u"Scoped wallet passcode throttling is per account"_q);
	Check(
		second.local().writeWalletEngineValue(u"secret/test"_q, QByteArray("fixture"))
			&& !secondVault->canInitializeScopedKeyring()
			&& secondVault->reading().state == State::Absent,
		u"Missing ring with existing secrets cannot install a new factor"_q);
}

void RunWalletScopedKeyring() {
	const auto sandbox = QTemporaryDir();
	if (!sandbox.isValid()) {
		Fail(u"Scoped wallet fixture needs temporary storage"_q);
		return;
	}
	const auto first = Storage::ScopedAccountPaths(
		sandbox.path(), QString(32, QLatin1Char('a')));
	const auto second = Storage::ScopedAccountPaths(
		sandbox.path(), QString(32, QLatin1Char('b')));
	const auto ring = FixtureRing();
	Check(first && second && ring, u"Scoped wallet fixture initialized"_q);
	if (first && second && ring) {
		CheckScopedCodec(*ring);
		CheckScopedRuntime(*first, *second, *ring);
	}
}

[[maybe_unused]] const auto kRegistered = [] {
	RegisterScenarioProvider([](not_null<Runner*> runner) {
		if (!qEnvironmentVariableIsSet("TDESKTOP_TEST_WALLET_SCOPED_KEYRING")) {
			return false;
		}
		runner->add({
			.name = u"Scoped wallet keyring"_q,
			.then = RunWalletScopedKeyring,
		});
		return true;
	});
	return true;
}();

} // namespace
} // namespace Test

#endif
