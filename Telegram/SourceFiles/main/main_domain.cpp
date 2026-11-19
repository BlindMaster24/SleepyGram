/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "main/main_domain.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "core/shortcuts.h"
#include "core/crash_reports.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "data/data_session.h"
#include "data/data_changes.h"
#include "data/data_user.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/mtproto_dc_options.h"
#include "storage/storage_domain.h"
#include "storage/storage_account.h"
#include "storage/localstorage.h"
#include "export/export_settings.h"
#include "wallet/wallet_unlock.h"
#include "wallet/wallet_vault.h"
#include "window/notifications_manager.h"
#include "window/window_controller.h"
#include "data/data_peer_values.h" // Data::AmPremiumValue.

#include <QtCore/QFileInfo>
#include <openssl/crypto.h>

#include <array>
#include <map>
#include <set>
#include <utility>

// AyuGram includes
#include "ayu/data/ayu_database.h"
#include "ayu/features/chat_lock/chat_lock.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_generation.h"


namespace Main {
namespace {

namespace ProfileSets = Ayu::ProfileSets;

struct PreparedScopedAccount final {
	Storage::AccountPaths paths;
	Storage::ScopedAccountStartupInfo identity;
	MTP::AuthKeyPtr storageKey;
};

std::optional<PreparedScopedAccount> PrepareScopedAccount(
		const QString &root,
		const ProfileSets::AccountStorageTarget &target,
		const ProfileSets::AccountKey &key,
		std::unique_ptr<MTP::Config> *config = nullptr) {
	const auto paths = Storage::ScopedAccountPaths(root, target.dataName);
	if (key.id != target.id || !paths || target.paths.mode != paths->mode
		|| target.paths.dataNameKey != paths->dataNameKey
		|| target.paths.basePath != paths->basePath
		|| target.paths.tempPath != paths->tempPath
		|| target.paths.databasePath != paths->databasePath
		|| target.paths.authPath != paths->authPath) {
		return std::nullopt;
	}
	auto storageKey = ProfileSets::ProfileAccountStorageKey(key);
	const auto identity = storageKey
		? Storage::ValidateScopedAccountForStartup(*paths, storageKey, config)
		: std::nullopt;
	if (!identity || !identity->userId) {
		return std::nullopt;
	}
	return PreparedScopedAccount{
		.paths = *paths,
		.identity = *identity,
		.storageKey = std::move(storageKey),
	};
}

bool FailScopedStartup(
		ProfileSets::ProfileGenerationError *error,
		ProfileSets::ProfileGenerationError reason) {
	if (error) {
		*error = reason;
	}
	return false;
}

} // namespace

struct Domain::ScopedProfile final {
	ProfileSets::ProfileGenerationAccess access;
	std::map<ProfileSets::AccountId, PreparedScopedAccount> accounts;
	// The generation releases its prepared accounts during destruction.
	ProfileSets::OpenedProfileGeneration generation;
	std::optional<AyuDatabase::ScopedArchiveLease> archives;
};

Domain::Domain(const QString &dataName)
: _dataName(dataName)
, _local(std::make_unique<Storage::Domain>(this, dataName)) {
	_active.changes(
	) | rpl::take(1) | rpl::on_next([=] {
		// In case we had a legacy passcoded app we start settings here.
		Core::App().startSettingsAndBackground();

		crl::on_main(this, [=] {
			Core::App().notifications().createManager();
		});
	}, _lifetime);

	_active.changes(
	) | rpl::map([](Main::Account *account) {
		return account ? account->sessionValue() : rpl::never<Session*>();
		}) | rpl::flatten_latest(
	) | rpl::map([](Main::Session *session) {
		return session
			? session->changes().peerFlagsValue(
				session->user(),
				Data::PeerUpdate::Flag::Username)
			: rpl::never<Data::PeerUpdate>();
	}) | rpl::flatten_latest(
	) | rpl::on_next([=](const Data::PeerUpdate &update) {
		if (!scopedProfileReserved()) {
			CrashReports::SetAnnotation("Username", update.peer->username());
		}
	}, _lifetime);
}

Domain::~Domain() {
	if (_walletKeyring) {
		_walletKeyring->clear();
	}
}

Wallet::VaultRuntime &Domain::walletKeyring() {
	Expects(!scopedProfileReserved());

	if (!_walletKeyring) {
		_walletKeyring = std::make_shared<Wallet::VaultRuntime>(*this);
	}
	return *_walletKeyring;
}

Storage::Domain &Domain::local() const {
	return *_local;
}

bool Domain::started() const {
	return !_accounts.empty();
}

Storage::StartResult Domain::start(const QByteArray &passcode) {
	if (scopedProfileReserved()) {
		return Storage::StartResult::IncorrectPasscode;
	}
	_profileStorageMode = ProfileStorageMode::Legacy;
	return startWith(_local->prepareOpen(passcode));
}

bool Domain::reserveScopedProfile() {
	if (_profileStorageMode == ProfileStorageMode::Legacy
		|| started() || _walletKeyring || !_local->reserveScopedStorage()) {
		return false;
	}
	_profileStorageMode = ProfileStorageMode::Scoped;
	AyuDatabase::ReserveScopedArchives();
	return true;
}

bool Domain::scopedProfileReserved() const {
	return _profileStorageMode == ProfileStorageMode::Scoped;
}

bool Domain::prepareScopedProfile(
		const ProfileSets::MigrationController &sidecar,
		ProfileSets::OpenedProfileGeneration generation,
		ProfileSets::ProfileGenerationError *error) {
	using Error = ProfileSets::ProfileGenerationError;
	if (error) {
		*error = Error::InvalidPlan;
	}
	if (Core::Quitting() || _changingScopedProfile
		|| _scopedProfile || !reserveScopedProfile()) {
		return false;
	}
	const auto root = sidecar.accountStorageRoot();
	const auto access = generation.access();
	const auto &targets = generation.plan().targets();
	if (root.isEmpty() || sidecar.isIsolatedFixture()
		|| targets.size() > size_t(kPremiumMaxAccounts)
		|| (access.role == ProfileSets::ProfileGenerationRole::Master
			? (access.setId || !targets.empty() || !generation.adminMetadata())
			: (!access.setId || generation.adminMetadata()))) {
		return false;
	}
	auto profile = std::make_unique<ScopedProfile>(ScopedProfile{
		.access = access,
		.generation = std::move(generation),
	});
	auto candidates = decltype(profile->accounts)();
	auto identities = std::set<std::pair<MTP::Environment, uint64>>();
	const auto validate = [&](const ProfileSets::AccountStorageTarget &target,
			const ProfileSets::AccountKey &key) {
		auto candidate = PrepareScopedAccount(root, target, key);
		if (!candidate || !identities.emplace(
				candidate->identity.environment,
				candidate->identity.userId.bare).second) {
			return false;
		}
		return candidates.emplace(target.id, std::move(*candidate)).second;
	};
	const auto adopt = [&](const ProfileSets::AccountStorageTarget &target,
			const ProfileSets::AccountKey &) -> std::optional<Fn<void()>> {
		auto candidate = candidates.extract(target.id);
		if (candidate.empty()
			|| !profile->accounts.insert(std::move(candidate)).inserted) {
			return std::nullopt;
		}
		return Fn<void()>([prepared = profile.get(), id = target.id] {
			prepared->accounts.erase(id);
		});
	};
	if (!profile->generation.Start(sidecar, validate, adopt, error)) {
		return false;
	}
	_scopedProfile = std::move(profile);
	return true;
}

bool Domain::startPreparedScopedProfile(
		const ProfileSets::MigrationController &sidecar,
		ProfileSets::ProfileGenerationError *error) {
	using Error = ProfileSets::ProfileGenerationError;
	if (Core::Quitting() || !scopedProfileReserved() || started()
		|| _changingScopedProfile || !_scopedProfile
		|| _scopedProfile->access.role != ProfileSets::ProfileGenerationRole::Set
		|| !_scopedProfile->access.setId || _scopedProfile->accounts.empty()
		|| _scopedProfile->archives || sidecar.isIsolatedFixture()) {
		return FailScopedStartup(error, Error::InvalidPlan);
	}
	const auto settingsKey = preparedScopedSettingsKey();
	if (!Local::usesScopedSettings() || !Local::matchesScopedSettings(settingsKey)) {
		return FailScopedStartup(error, Error::SettingsRejected);
	}

	_changingScopedProfile = true;
	const auto reset = gsl::finally([&] { _changingScopedProfile = false; });
	const auto launch = [&] {
		return launchScopedAccounts(sidecar.accountStorageRoot(), settingsKey, error);
	};
	auto migrationError = ProfileSets::MigrationError::None;
	if (!_scopedProfile->generation.WithCurrent(
		sidecar,
		launch,
		&migrationError)) {
		return (migrationError == ProfileSets::MigrationError::CallbackFailed)
			? false
			: FailScopedStartup(
				error,
				(migrationError == ProfileSets::MigrationError::StaleGeneration)
					? Error::StaleGeneration
					: Error::InvalidSidecar);
	}
	activateAfterStarting();
	_accountsChanges.fire({});
	if (error) {
		*error = Error::None;
	}
	return true;
}

bool Domain::launchScopedAccounts(
		const QString &root,
		const std::shared_ptr<MTP::AuthKey> &settingsKey,
		ProfileSets::ProfileGenerationError *error) {
	using Error = ProfileSets::ProfileGenerationError;
	auto &profile = *_scopedProfile;
	const auto &plan = profile.generation.plan();
	const auto &targets = plan.targets();
	if (root.isEmpty() || targets.size() != profile.accounts.size()) {
		return FailScopedStartup(error, Error::InvalidPlan);
	}
	struct PendingAccount {
		PreparedScopedAccount local;
		std::unique_ptr<MTP::Config> config;
	};
	using ArchiveKey = std::array<std::byte, ProfileSets::kAccountArchiveKeySize>;
	auto archiveKeys = std::vector<ArchiveKey>(targets.size());
	const auto wipeArchiveKeys = gsl::finally([&] {
		for (auto &key : archiveKeys) {
			OPENSSL_cleanse(key.data(), key.size());
		}
	});
	auto archives = std::vector<AyuDatabase::ScopedArchiveAccount>();
	auto pending = std::vector<PendingAccount>();
	archives.reserve(targets.size());
	pending.reserve(targets.size());
	for (const auto &target : targets) {
		const auto key = plan.keyFor(target.id);
		const auto prepared = profile.accounts.find(target.id);
		if (!key || prepared == end(profile.accounts)) {
			return FailScopedStartup(error, Error::InvalidPlan);
		}
		auto config = std::unique_ptr<MTP::Config>();
		auto account = PrepareScopedAccount(root, target, *key, &config);
		auto &archiveKey = archiveKeys[pending.size()];
		if (!account
			|| account->identity.userId != prepared->second.identity.userId
			|| account->identity.environment != prepared->second.identity.environment
			|| !ProfileSets::DeriveAccountArchiveKey(
				*key,
				bytes::make_span(archiveKey))) {
			return FailScopedStartup(error, Error::ValidationFailed);
		}
		const auto archive = QFileInfo(
			account->paths.databasePath + u"archive.db"_q);
		archives.push_back({
			.userId = int64_t(account->identity.userId.bare),
			.path = archive.filesystemFilePath(),
			.key = archiveKey,
		});
		if (!config) {
			config = std::make_unique<MTP::Config>(
				MTP::Environment::Production);
		}
		pending.push_back({ std::move(*account), std::move(config) });
	}
	auto archiveLease = AyuDatabase::InstallScopedArchives(archives);
	if (!archiveLease) {
		return FailScopedStartup(error, Error::ValidationFailed);
	}
	auto accounts = std::vector<AccountWithIndex>();
	accounts.reserve(pending.size());
	for (auto &candidate : pending) {
		auto &local = candidate.local;
		auto account = std::make_unique<Account>(this, std::move(local.paths));
		if (!account->prepareScopedToStart(
			local.storageKey,
			local.identity.userId)) {
			return FailScopedStartup(error, Error::ValidationFailed);
		}
		accounts.push_back({
			.index = int(accounts.size()),
			.account = std::move(account),
		});
	}
	if (Core::Quitting() || !Local::matchesScopedSettings(settingsKey)) {
		return FailScopedStartup(error, Error::StartFailed);
	}
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		accounts[i].account->start(std::move(pending[i].config));
	}
	_accounts = std::move(accounts);
	profile.archives = std::move(archiveLease);
	return true;
}

bool Domain::startPreparedScopedEnrollment(
		const ProfileSets::MigrationController &sidecar,
		Fn<void(ProvisionalAccountAuthorization)> done) {
	if (!done || Core::Quitting() || !scopedProfileReserved() || started()
		|| !_scopedProfile || !_scopedProfile->access.setId
		|| _scopedProfile->access.role != ProfileSets::ProfileGenerationRole::Set
		|| !_scopedProfile->accounts.empty()
		|| !Local::matchesScopedSettings(preparedScopedSettingsKey())) {
		return false;
	}
	const auto started = _scopedProfile->generation.WithCurrent(sidecar, [&] {
			auto account = Account::CreateProvisionalScopedLogin(this,
				std::make_unique<MTP::Config>(MTP::Environment::Production), std::move(done));
			if (!account) {
				return false;
			}
			_accounts.push_back({ .index = 0, .account = std::move(account) });
			return true;
		});
	if (started) {
		activate(_accounts.front().account.get());
		_accountsChanges.fire({});
	}
	return started;
}

bool Domain::provisionalEnrollmentActive() const {
	return scopedProfileReserved() && _scopedProfile && _scopedProfile->access.setId
		&& _scopedProfile->accounts.empty() && _accounts.size() == 1
		&& _active.current() == _accounts.front().account.get()
		&& _accounts.front().account->isProvisionalScopedLogin();
}

void Domain::clearPreparedScopedProfile() {
	if (!started() && !_changingScopedProfile) {
		_scopedProfile.reset();
	}
}

auto Domain::preparedScopedProfileAccess() const
-> const ProfileSets::ProfileGenerationAccess* {
	return _scopedProfile ? &_scopedProfile->access : nullptr;
}

auto Domain::preparedScopedAdminMetadata() const
-> const ProfileSets::Metadata* {
	return _scopedProfile ? _scopedProfile->generation.adminMetadata() : nullptr;
}

auto Domain::preparedScopedAdminAccountIds() const
-> const std::vector<ProfileSets::AccountId>* {
	return preparedScopedAdminMetadata()
		? &_scopedProfile->generation.adminAccountIds()
		: nullptr;
}

QByteArray Domain::preparedScopedProfileTransactionId() const {
	return _scopedProfile ? _scopedProfile->generation.transactionId() : QByteArray();
}

auto Domain::preparedScopedProfileProof() const
-> const ProfileSets::MigrationGenerationProof* {
	return _scopedProfile ? _scopedProfile->generation.revocableProof() : nullptr;
}

std::shared_ptr<MTP::AuthKey> Domain::preparedScopedSettingsKey() const {
	return _scopedProfile
		? ProfileSets::ProfileSettingsStorageKey(
			_scopedProfile->generation.settingsKey())
		: nullptr;
}

int Domain::preparedScopedAccountCount() const {
	return _scopedProfile ? int(_scopedProfile->accounts.size()) : 0;
}

Storage::StartResult Domain::startWith(
		Storage::PasscodeDerivation derived) {
	Expects(!started());

	const auto result = _local->start(std::move(derived));
	if (result == Storage::StartResult::Success) {
		activateAfterStarting();
		Wallet::DropUnusedPasscode();
		crl::on_main(&Core::App(), [=] { suggestExportIfNeeded(); });
	} else {
		Assert(!started());
	}
	return result;
}

bool Domain::tryPasscode(
		const QByteArray &passcode,
		Fn<void(bool correct)> done) {
	if (scopedProfileReserved() || _passcodeDeriving) {
		return false;
	}
	_profileStorageMode = ProfileStorageMode::Legacy;
	_passcodeDeriving = true;
	const auto cold = !started();
	Storage::DeriveOnWorker(
		_local->prepareOpen(passcode),
		crl::guard(this, [=](Storage::PasscodeDerivation &&derived) {
			_passcodeDeriving = false;
			if (Core::Quitting()) {
				return;
			}
			const auto correct = (cold == started())
				? false
				: cold
				? (startWith(std::move(derived))
					== Storage::StartResult::Success)
				: _local->checkPasscode(std::move(derived));
			done(correct);
		}));
	return true;
}

void Domain::finish() {
	if (scopedProfileReserved()) {
		if (_changingScopedProfile) {
			return;
		}
		_changingScopedProfile = true;
		const auto reset = gsl::finally([&] { _changingScopedProfile = false; });
		_accountToActivate = _lastActiveIndex = -1;
		_activeLifetime.destroy();
		auto accounts = base::take(_accounts);
		if (!accounts.empty()) {
			_active = nullptr;
			_activeSessions.fire(nullptr);
			accounts.clear();
			Local::sync();
			updateUnreadBadge();
		}
		_scopedProfile.reset();
		return;
	}
	clearPreparedScopedProfile();
	if (_walletKeyring) {
		_walletKeyring->clear();
	}
	_accountToActivate = -1;
	_active.reset(nullptr);
	base::take(_accounts);
}

void Domain::suggestExportIfNeeded() {
	Expects(started());

	for (const auto &[index, account] : _accounts) {
		if (const auto session = account->maybeSession()) {
			const auto settings = session->local().readExportSettings();
			if (const auto availableAt = settings.availableAt) {
				session->data().suggestStartExport(availableAt);
			}
		}
	}
}

void Domain::accountAddedInStorage(AccountWithIndex accountWithIndex) {
	Expects(!scopedProfileReserved());
	Expects(accountWithIndex.account != nullptr);

	for (const auto &[index, _] : _accounts) {
		if (index == accountWithIndex.index) {
			Unexpected("Repeated account index.");
		}
	}
	_accounts.push_back(std::move(accountWithIndex));
}

void Domain::activateFromStorage(int index) {
	Expects(!scopedProfileReserved());

	_accountToActivate = index;
}

int Domain::activeForStorage() const {
	return _accountToActivate;
}

void Domain::resetWithForgottenPasscode() {
	if (scopedProfileReserved()) {
		return;
	}
	_profileStorageMode = ProfileStorageMode::Legacy;
	if (_walletKeyring) {
		_walletKeyring->clear();
	}
	if (_accounts.empty()) {
		_local->startFromScratch();
		activateAfterStarting();
	} else {
		for (const auto &[index, account] : _accounts) {
			account->logOut();
		}
	}
}

bool Domain::finishPasscodeClearAfterReset() {
	if (!passcodeRemovalAuthorized()) {
		return false;
	}
	return clearPasscodeAfterLastLogout();
}

void Domain::activateAfterStarting() {
	Expects(started());

	auto toActivate = _accounts.front().account.get();
	for (const auto &[index, account] : _accounts) {
		if (index == _accountToActivate) {
			toActivate = account.get();
		}
		watchSession(account.get());
	}

	activate(toActivate);
	removePasscodeIfEmpty();
}

const std::vector<Domain::AccountWithIndex> &Domain::accounts() const {
	return _accounts;
}

std::vector<not_null<Account*>> Domain::orderedAccounts() const {
	const auto order = Core::App().settings().accountsOrder();
	auto accounts = ranges::views::all(
		_accounts
	) | ranges::views::transform([](const Domain::AccountWithIndex &a) {
		return not_null{ a.account.get() };
	}) | ranges::to_vector;
	ranges::stable_sort(accounts, [&](
			not_null<Account*> a,
			not_null<Account*> b) {
		const auto aIt = a->sessionExists()
			? ranges::find(order, a->session().uniqueId())
			: end(order);
		const auto bIt = b->sessionExists()
			? ranges::find(order, b->session().uniqueId())
			: end(order);
		return aIt < bIt;
	});
	return accounts;
}

rpl::producer<> Domain::accountsChanges() const {
	return _accountsChanges.events();
}

Account *Domain::maybeLastOrSomeAuthedAccount() {
	auto result = (Account*)nullptr;
	for (const auto &[index, account] : _accounts) {
		if (!account->sessionExists()) {
			continue;
		} else if (index == _lastActiveIndex) {
			return account.get();
		} else if (!result) {
			result = account.get();
		}
	}
	return result;
}

int Domain::accountsAuthedCount() const {
	auto result = 0;
	for (const auto &[index, account] : _accounts) {
		if (account->sessionExists()) {
			++result;
		}
	}
	return result;
}

rpl::producer<Account*> Domain::activeValue() const {
	return _active.value();
}

Account &Domain::active() const {
	Expects(!_accounts.empty());

	Ensures(_active.current() != nullptr);
	return *_active.current();
}

rpl::producer<not_null<Account*>> Domain::activeChanges() const {
	return _active.changes() | rpl::filter([](Account *value) {
		return value != nullptr;
	}) | rpl::map([](Account *value) {
		return not_null{ value };
	});
}

rpl::producer<Session*> Domain::activeSessionChanges() const {
	return _activeSessions.events();
}

rpl::producer<Session*> Domain::activeSessionValue() const {
	const auto current = _accounts.empty()
		? nullptr
		: active().maybeSession();
	return rpl::single(current) | rpl::then(_activeSessions.events());
}

int Domain::unreadBadge() const {
	return _unreadBadge;
}

bool Domain::unreadBadgeMuted() const {
	return _unreadBadgeMuted;
}

rpl::producer<> Domain::unreadBadgeChanges() const {
	return _unreadBadgeChanges.events();
}

void Domain::notifyUnreadBadgeChanged() {
	for (const auto &[index, account] : _accounts) {
		if (const auto session = account->maybeSession()) {
			session->data().notifyUnreadBadgeChanged();
		}
	}
}

void Domain::updateUnreadBadge() {
	_unreadBadge = 0;
	_unreadBadgeMuted = true;
	for (const auto &[index, account] : _accounts) {
		if (const auto session = account->maybeSession()) {
			const auto data = &session->data();
			_unreadBadge += data->unreadBadge();
			if (!data->unreadBadgeMuted()) {
				_unreadBadgeMuted = false;
			}
		}
	}
	_unreadBadgeChanges.fire({});
}

void Domain::scheduleUpdateUnreadBadge() {
	if (_unreadBadgeUpdateScheduled || Core::Quitting()) {
		return;
	}
	_unreadBadgeUpdateScheduled = true;
	Core::App().postponeCall(crl::guard(&Core::App(), [=] {
		_unreadBadgeUpdateScheduled = false;
		updateUnreadBadge();
	}));
}

not_null<Main::Account*> Domain::add(MTP::Environment environment) {
	Expects(!scopedProfileReserved());
	Expects(started());
	Expects(_accounts.size() < kPremiumMaxAccounts);

	static const auto cloneConfig = [](const MTP::Config &config) {
		return std::make_unique<MTP::Config>(config);
	};
	auto mainDcId = MTP::Instance::Fields::kNotSetMainDc;
	const auto accountConfig = [&](not_null<Account*> account) {
		mainDcId = account->mtp().mainDcId();
		return cloneConfig(account->mtp().config());
	};
	auto config = [&] {
		if (_active.current()->mtp().environment() == environment) {
			return accountConfig(_active.current());
		}
		for (const auto &[index, account] : _accounts) {
			if (account->mtp().environment() == environment) {
				return accountConfig(account.get());
			}
		}
		return (environment == MTP::Environment::Production)
			? cloneConfig(Core::App().fallbackProductionConfig())
			: std::make_unique<MTP::Config>(environment);
	}();
	auto index = 0;
	while (ranges::contains(_accounts, index, &AccountWithIndex::index)) {
		++index;
	}
	_accounts.push_back(AccountWithIndex{
		.index = index,
		.account = std::make_unique<Account>(this, _dataName, index)
	});
	const auto account = _accounts.back().account.get();
	account->setMtpMainDcId(mainDcId);
	_local->startAdded(account, std::move(config));
	watchSession(account);
	_accountsChanges.fire({});

	auto &settings = Core::App().settings();
	if (_accounts.size() == 2 && !settings.mainMenuAccountsShown()) {
		settings.setMainMenuAccountsShown(true);
		Core::App().saveSettingsDelayed();
	}

	return account;
}

void Domain::addActivated(MTP::Environment environment, bool newWindow) {
	if (scopedProfileReserved()) {
		return;
	}
	const auto added = [&](not_null<Main::Account*> account) {
		if (newWindow) {
			Core::App().ensureSeparateWindowFor(account);
		} else if (const auto window = Core::App().separateWindowFor(
				account)) {
			window->activate();
		} else {
			activate(account);
		}
	};
	if (accounts().size() < maxAccounts()) {
		added(add(environment));
	} else {
		for (auto &[index, account] : accounts()) {
			if (!account->sessionExists()
				&& account->mtp().environment() == environment) {
				added(account.get());
				break;
			}
		}
	}
}

void Domain::watchSession(not_null<Account*> account) {
	account->sessionValue(
	) | rpl::filter([=](Session *session) {
		return session != nullptr;
	}) | rpl::on_next([=](Session *session) {
		session->data().unreadBadgeChanges(
		) | rpl::on_next([=] {
			scheduleUpdateUnreadBadge();
		}, session->lifetime());

		Data::AmPremiumValue(
			session
		) | rpl::on_next([=] {
			_lastMaxAccounts = maxAccounts();
		}, session->lifetime());
	}, account->lifetime());

	account->sessionChanges(
	) | rpl::filter([=](Session *session) {
		return !session;
	}) | rpl::on_next([=] {
		scheduleUpdateUnreadBadge();
		closeAccountWindows(account);
		if (!Core::Quitting()) {
			crl::on_main(&Core::App(), [=] {
				removeRedundantAccounts();
			});
		}
	}, account->lifetime());
}

void Domain::closeAccountWindows(not_null<Main::Account*> account) {
	auto another = (Main::Account*)nullptr;
	for (auto i = _accounts.begin(); i != _accounts.end(); ++i) {
		const auto other = not_null(i->account.get());
		if (other == account) {
			continue;
		} else if (Core::App().separateWindowFor(other)) {
			const auto that = Core::App().separateWindowFor(account);
			if (that) {
				that->close();
			}
		} else if (!another
			|| (other->sessionExists() && !another->sessionExists())) {
			another = other;
		}
	}
	if (another) {
		activate(another);
	}
}

bool Domain::removePasscodeIfEmpty() {
	if (scopedProfileReserved() || _accounts.size() != 1
		|| _active.current()->sessionExists()) {
		return false;
	}
	Local::reset();

	// We completely logged out, remove the passcode if it was there.
	if (Core::App().passcodeLocked()) {
		Core::App().unlockPasscode();
	}
	if (!_local->hasPasscode()) {
		return false;
	} else if (!clearPasscodeAfterLastLogout()) {
		reportFailedPasscodeClear();
		return false;
	}
	return true;
}

bool Domain::passcodeRemovalAuthorized() const {
	return !scopedProfileReserved()
		&& (_accounts.size() == 1)
		&& !_active.current()->sessionExists()
		&& _local->hasPasscode();
}

bool Domain::clearPasscodeAfterLastLogout() {
	Expects(passcodeRemovalAuthorized());

	_local->clearPasscodeAfterReset();
	if (_local->hasPasscode()) {
		return false;
	}
	Core::App().settings().setSystemUnlockEnabled(false);
	Core::App().saveSettingsDelayed();
	return true;
}

void Domain::reportFailedPasscodeClear() {
	crl::on_main(this, [=] {
		if (!passcodeRemovalAuthorized()) {
			return;
		}
		if (const auto window = Core::App().activePrimaryWindow()) {
			window->showPasscodeClearFailed(crl::guard(this, [=] {
				return finishPasscodeClearAfterReset();
			}));
		}
	});
}

void Domain::removeRedundantAccounts() {
	if (scopedProfileReserved()) {
		return;
	}
	Expects(started());

	for (const auto &one : _accounts) {
		if (one.account->destroyingSession()) {
			// We were invoked from a crl::on_main drain that a nested
			// event dispatch started from inside that account's own
			// destroySession(). Erasing it now would free the object
			// under its own stack frame. Retry after unwinding.
			crl::on_main(&Core::App(), [=] {
				removeRedundantAccounts();
			});
			return;
		}
	}

	const auto was = _accounts.size();
	for (auto i = _accounts.begin(); i != _accounts.end();) {
		if (Core::App().separateWindowFor(not_null(i->account.get()))
			|| i->account->sessionExists()) {
			++i;
			continue;
		}
		checkForLastProductionConfig(i->account.get());
		i = _accounts.erase(i);
	}

	if (!removePasscodeIfEmpty() && _accounts.size() != was) {
		scheduleWriteAccounts();
		_accountsChanges.fire({});
	}
	// Session teardown already removed the logged-out account's live keyring
	// membership, including when its window keeps the account in the list.
	// The last-logout case retains its checked clear and retry route, and
	// passcodeRemovalAuthorized() stays true until that clear has landed.
	if (!passcodeRemovalAuthorized()) {
		Wallet::DropUnusedPasscode();
	}
}

void Domain::checkForLastProductionConfig(
		not_null<Main::Account*> account) {
	const auto mtp = &account->mtp();
	if (mtp->environment() != MTP::Environment::Production) {
		return;
	}
	for (const auto &[index, other] : _accounts) {
		if (other.get() != account
			&& other->mtp().environment() == MTP::Environment::Production) {
			return;
		}
	}
	Core::App().refreshFallbackProductionConfig(mtp->config());
}

void Domain::maybeActivate(not_null<Main::Account*> account) {
	if (Core::App().separateWindowFor(account)) {
		activate(account);
	} else {
		Core::App().preventOrInvoke(crl::guard(account, [=] {
			activate(account);
		}));
	}
}

void Domain::activate(not_null<Main::Account*> account) {
	const auto pointer = [](
			const AccountWithIndex &value) {
		return value.account.get();
	};
	const auto provisional = _scopedProfile && _scopedProfile->accounts.empty()
		&& _accounts.size() == 1 && account->isProvisionalScopedLogin();
	if (scopedProfileReserved()
		&& (!_scopedProfile || (!_scopedProfile->archives && !provisional)
			|| !ranges::contains(_accounts, account.get(), pointer))) {
		return;
	}
	if (const auto window = Core::App().separateWindowFor(account)) {
		window->activate();
	}
	if (_active.current() == account.get()) {
		return;
	}
	const auto previousSession = _active.current()
		? _active.current()->maybeSession()
		: nullptr;
	const auto previousUserId = previousSession
		? previousSession->userId().bare
		: uint64(0);
	const auto i = ranges::find(_accounts, account.get(), pointer);
	if (scopedProfileReserved() && i == end(_accounts)) {
		return;
	}
	Assert(i != end(_accounts));
	const auto changed = (_accountToActivate != i->index);
	auto wasAuthed = false;

	_activeLifetime.destroy();
	if (_active.current()) {
		_lastActiveIndex = _accountToActivate;
		wasAuthed = _active.current()->sessionExists();
	}
	_accountToActivate = i->index;
	_active = account.get();
	_active.current()->sessionValue(
	) | rpl::start_to_stream(_activeSessions, _activeLifetime);
	const auto currentSession = _active.current()->maybeSession();
	Ayu::ChatLock::OnAccountSwitch(
		previousUserId,
		currentSession ? currentSession->userId().bare : uint64(0));

	if (changed && !scopedProfileReserved()) {
		if (wasAuthed) {
			scheduleWriteAccounts();
		} else {
			crl::on_main(&Core::App(), [=] {
				removeRedundantAccounts();
			});
		}
	}
}

void Domain::scheduleWriteAccounts() {
	if (scopedProfileReserved() || _writeAccountsScheduled) {
		return;
	}
	_writeAccountsScheduled = true;
	crl::on_main(&Core::App(), [=] {
		_writeAccountsScheduled = false;
		_local->writeAccounts();
	});
}

int Domain::maxAccounts() const {
	const auto premiumCount = ranges::count_if(accounts(), [](
			const Main::Domain::AccountWithIndex &d) {
		return d.account->sessionExists()
			&& (d.account->session().premium()
				|| d.account->session().isTestMode());
	});
	return std::min(int(premiumCount) + kMaxAccounts, kPremiumMaxAccounts);
}

rpl::producer<int> Domain::maxAccountsChanges() const {
	return _lastMaxAccounts.changes();
}

} // namespace Main
