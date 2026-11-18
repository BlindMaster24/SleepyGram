/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#if defined _DEBUG || defined TDESKTOP_RELEASE_TEST_HARNESS

#include "main/main_domain.h"
#include "storage/storage_account.h"
#include "storage/storage_domain.h"
#include "test/test_log.h"
#include "test/test_runner.h"

namespace Test {
namespace {

void RunScopedStorageDomain() {
	auto domain = Main::Domain(u"scoped-domain-fixture"_q);
	auto &storage = domain.local();
	Check(!storage.scopedStorageReserved()
		&& !storage.hasPasscode(), u"Fresh storage retains legacy defaults"_q);
	Check(storage.reserveScopedStorage()
		&& storage.reserveScopedStorage()
		&& storage.scopedStorageReserved(), u"Scope selection is sticky"_q);
	Check(storage.hasPasscode()
		&& storage.hasLocalPasscode()
		&& storage.appLockEnabled()
		&& storage.oldVersion() == 0, u"Scoped storage reports the app lock"_q);
	Check(storage.readWalletKeyring().state == Storage::WalletEngineValue::State::Broken,
		u"Scoped storage refuses legacy wallet lookup"_q);
	const auto passcode = QByteArray("fixture secret");
	auto open = storage.prepareOpen(passcode);
	auto change = storage.prepareNewWrap(passcode);
	Check(open.empty() && change.empty(), u"Scoped storage discards legacy passcode input"_q);
	open.run();
	change.run();
	Check(!storage.checkPasscode(std::move(open))
		&& !storage.verifyPasscode(passcode), u"Scoped storage declines legacy proof"_q);
	const auto failed = Storage::SetPasscodeResult::Failed;
	Check(storage.setPasscode(passcode, {}) == failed
		&& storage.setPasscode(QByteArray(), {}) == failed
		&& storage.setPasscode(std::move(change), {}) == failed,
		u"Scoped storage declines legacy passcode changes"_q);
	Check(storage.createPasscodeWithoutAppLock(storage.prepareNewWrap(passcode)) == failed
		&& storage.setAppLockEnabled(false, {}) == failed,
		u"Scoped storage keeps legacy wallet custody and lock-off disabled"_q);
	storage.clearPasscodeAfterReset();
	Check(storage.appLockEnabled(), u"Scoped lock survives legacy cleanup entry point"_q);
}

[[maybe_unused]] const auto kRegistered = [] {
	RegisterScenarioProvider([](not_null<Runner*> runner) {
		if (!qEnvironmentVariableIsSet("TDESKTOP_TEST_STORAGE_DOMAIN_SCOPE")) {
			return false;
		}
		runner->add({
			.name = u"Scoped storage domain"_q,
			.then = RunScopedStorageDomain,
		});
		return true;
	});
	return true;
}();

} // namespace
} // namespace Test

#endif
