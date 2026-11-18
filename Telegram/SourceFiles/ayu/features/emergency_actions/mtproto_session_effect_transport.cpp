// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/mtproto_session_effect_transport.h"

#include "ayu/features/emergency_actions/mtproto_device_inventory_response.h"
#include "ayu/features/profile_sets/account_storage_plan.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_migration.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_config.h"

#include <crl/crl_async.h>
#include <crl/crl_on_main.h>
#include <QtCore/QCoreApplication>
#include <QtCore/QPointer>
#include <QtCore/QThread>
#include <QtCore/QTimer>

#include <algorithm>
#include <bit>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>

namespace Ayu::EmergencyActions {
namespace {

using details::SessionRequest;
using details::SessionRequestKind;
using TimePoint = CoordinatorClock::TimePoint;

struct GrantedAccount final {
	Storage::AccountPaths paths;
	MTP::AuthKeyPtr key;
	uint64_t expectedUserId = 0;
	bool testEnvironment = false;
};

template <typename Result>
class SessionOperationState final {
public:
	SessionOperationState(TimePoint deadline, Result unavailable);

	[[nodiscard]] bool setConnection(
		std::unique_ptr<Storage::ScopedAccountConnection> connection);
	[[nodiscard]] auto takeConnection()
	-> std::unique_ptr<Storage::ScopedAccountConnection>;
	[[nodiscard]] Result wait();
	void finish(Result result);

	const TimePoint deadline;
	const Result unavailable;

private:
	std::mutex _mutex;
	std::condition_variable _done;
	std::unique_ptr<Storage::ScopedAccountConnection> _connection;
	std::optional<Result> _result;

};

template <typename Result>
SessionOperationState<Result>::SessionOperationState(
		TimePoint deadline,
		Result unavailable)
: deadline(deadline)
, unavailable(std::move(unavailable)) {
}

template <typename Result>
bool SessionOperationState<Result>::setConnection(
		std::unique_ptr<Storage::ScopedAccountConnection> connection) {
	const auto lock = std::lock_guard(_mutex);
	if (_result || std::chrono::steady_clock::now() >= deadline) {
		return false;
	}
	_connection = std::move(connection);
	return true;
}

template <typename Result>
auto SessionOperationState<Result>::takeConnection()
-> std::unique_ptr<Storage::ScopedAccountConnection> {
	const auto lock = std::lock_guard(_mutex);
	return !_result && std::chrono::steady_clock::now() < deadline
		? std::move(_connection)
		: nullptr;
}

template <typename Result>
Result SessionOperationState<Result>::wait() {
	auto lock = std::unique_lock(_mutex);
	if (!_done.wait_until(lock, deadline, [&] { return _result.has_value(); })) {
		_connection.reset();
		_result.emplace(unavailable);
	}
	return std::move(*_result);
}

template <typename Result>
void SessionOperationState<Result>::finish(Result result) {
	const auto lock = std::lock_guard(_mutex);
	if (!_result) {
		if (std::chrono::steady_clock::now() < deadline) {
			_result.emplace(std::move(result));
		} else {
			_result.emplace(unavailable);
		}
		_done.notify_one();
	}
}

using SessionBatchState = SessionOperationState<EffectResult>;
using DeviceInventory = std::optional<std::vector<MtprotoDeviceInventoryEntry>>;
using DeviceInventoryState = SessionOperationState<DeviceInventory>;

bool IsWorkerThread() {
	const auto app = QCoreApplication::instance();
	return app && !QCoreApplication::closingDown()
		&& QThread::currentThread() != app->thread();
}

template <typename State, typename OnReady>
void StartVerifiedSessionOperation(
		std::shared_ptr<State> state,
		GrantedAccount account,
		OnReady ready) {
	crl::async([state, account = std::move(account), ready = std::move(ready)]() mutable {
		if (std::chrono::steady_clock::now() >= state->deadline) {
			return;
		}
		auto data = Storage::ReadScopedAccountConnection(account.paths, account.key);
		if (!data || !data->config || data->userId.bare != account.expectedUserId
			|| data->config->isTestMode() != account.testEnvironment) {
			state->finish(state->unavailable);
			return;
		}
		if (!state->setConnection(std::move(data))) {
			return;
		}
		crl::on_main([state, ready = std::move(ready)]() mutable {
			const auto app = QCoreApplication::instance();
			if (!app || QCoreApplication::closingDown()) {
				state->finish(state->unavailable);
				return;
			}
			ready(app, std::move(state));
		});
	});
}

MTP::Instance::Fields InstanceFields(
		Storage::ScopedAccountConnection &data,
		TimePoint deadline) {
	auto fields = MTP::Instance::Fields();
	fields.config = std::move(data.config);
	fields.mainDcId = data.mainDcId;
	fields.keys.push_back(std::move(data.mainKey));
	fields.emergencyDeadline = deadline;
	return fields;
}

class SessionBatch final : public QObject {
public:
	SessionBatch(
		QObject *parent,
		std::shared_ptr<SessionBatchState> state,
		std::vector<SessionRequest> requests);

	void start();

private:
	void send(SessionRequest request);
	template <typename Request, typename Confirm>
	void send(Request request, Confirm confirm);
	void received(EffectResult result);
	void close(EffectResult result);

	const std::shared_ptr<SessionBatchState> _state;
	const std::vector<SessionRequest> _requests;
	size_t _pending = 0;
	EffectResult _aggregate = EffectResult::ConfirmedSuccess;
	std::vector<mtpRequestId> _ids;
	std::unique_ptr<MTP::Instance> _instance;
	QTimer _timer;
	bool _closed = false;

};

SessionBatch::SessionBatch(
	QObject *parent,
	std::shared_ptr<SessionBatchState> state,
	std::vector<SessionRequest> requests)
: QObject(parent)
, _state(std::move(state))
, _requests(std::move(requests))
, _pending(_requests.size()) {
	_timer.setSingleShot(true);
	_timer.setTimerType(Qt::PreciseTimer);
	connect(&_timer, &QTimer::timeout, this, [this] {
		close(EffectResult::Unconfirmed);
	});
}

void SessionBatch::start() {
	auto data = _state->takeConnection();
	if (!data) {
		close(EffectResult::Unconfirmed);
		return;
	}
	const auto remaining = _state->deadline - std::chrono::steady_clock::now();
	if (remaining <= std::chrono::steady_clock::duration::zero()) {
		close(EffectResult::Unconfirmed);
		return;
	}
	_timer.start(std::chrono::ceil<std::chrono::milliseconds>(remaining));
	_instance = std::make_unique<MTP::Instance>(
		MTP::Instance::Mode::EmergencySessionEffect,
		InstanceFields(*data, _state->deadline));
	for (const auto &request : _requests) {
		if (_instance->emergencySessionEffectExpired()) {
			close(EffectResult::Unconfirmed);
			return;
		}
		send(request);
	}
}

void SessionBatch::send(SessionRequest request) {
	const auto fromBool = [](const MTPBool &result) {
		return mtpIsTrue(result)
			? EffectResult::ConfirmedSuccess
			: EffectResult::ConfirmedFailure;
	};
	switch (request.kind) {
	case SessionRequestKind::RevokeSelected:
		send(MTPaccount_ResetAuthorization(
			MTP_long(std::bit_cast<int64_t>(request.hash))), fromBool);
		break;
	case SessionRequestKind::RevokeAllOther:
		send(MTPauth_ResetAuthorizations(), fromBool);
		break;
	case SessionRequestKind::LogoutCurrent:
		send(MTPauth_LogOut(), [](const MTPauth_LoggedOut &) {
			return EffectResult::ConfirmedSuccess;
		});
		break;
	}
}

template <typename Request, typename Confirm>
void SessionBatch::send(Request request, Confirm confirm) {
	using Result = typename Request::ResponseType;
	const auto weak = QPointer<SessionBatch>(this);
	_ids.push_back(_instance->send(MTPInvokeWithoutUpdates<Request>(request),
		[weak, confirm](const MTP::Response &response) {
			auto result = Result();
			auto from = response.reply.constData();
			const auto end = from + response.reply.size();
			if (!result.read(from, end) || from != end) {
				return false;
			}
			if (weak) {
				weak->received(confirm(result));
			}
			return true;
		},
		[weak](const MTP::Error &error, const MTP::Response &) {
			if (weak) {
				weak->received((error.code() >= 400
					&& error.code() < 500
					&& !MTP::IsFloodError(error))
					? EffectResult::ConfirmedFailure
					: EffectResult::Unconfirmed);
			}
			return true;
		}));
}

void SessionBatch::received(EffectResult result) {
	if (_closed || !_pending) {
		return;
	}
	if (result == EffectResult::Unconfirmed
		|| _aggregate == EffectResult::ConfirmedSuccess) {
		_aggregate = result;
	}
	if (!--_pending) {
		QMetaObject::invokeMethod(this, [this] { close(_aggregate); },
			Qt::QueuedConnection);
	}
}

void SessionBatch::close(EffectResult result) {
	if (_closed) {
		return;
	}
	_closed = true;
	_timer.stop();
	if (_instance) {
		for (const auto id : _ids) {
			_instance->cancel(id);
		}
		_instance.reset();
	}
	_state->finish(result);
	deleteLater();
}

class DeviceInventoryOperation final : public QObject {
public:
	DeviceInventoryOperation(
		QObject *parent,
		std::shared_ptr<DeviceInventoryState> state);

	void start();

private:
	void received(DeviceInventory result);
	void close(DeviceInventory result);

	const std::shared_ptr<DeviceInventoryState> _state;
	std::unique_ptr<MTP::Instance> _instance;
	QTimer _timer;
	mtpRequestId _requestId = 0;
	bool _closed = false;

};

DeviceInventoryOperation::DeviceInventoryOperation(
		QObject *parent,
		std::shared_ptr<DeviceInventoryState> state)
: QObject(parent)
, _state(std::move(state)) {
	_timer.setSingleShot(true);
	_timer.setTimerType(Qt::PreciseTimer);
	connect(&_timer, &QTimer::timeout, this, [this] { close(std::nullopt); });
}

void DeviceInventoryOperation::start() {
	auto connection = _state->takeConnection();
	const auto remaining = _state->deadline - std::chrono::steady_clock::now();
	if (!connection || remaining <= std::chrono::steady_clock::duration::zero()) {
		close(std::nullopt);
		return;
	}
	_timer.start(std::chrono::ceil<std::chrono::milliseconds>(remaining));
	_instance = std::make_unique<MTP::Instance>(
		MTP::Instance::Mode::EmergencyDeviceInventory,
		InstanceFields(*connection, _state->deadline));
	if (_instance->emergencySessionEffectExpired()) {
		close(std::nullopt);
		return;
	}
	const auto weak = QPointer<DeviceInventoryOperation>(this);
	_requestId = _instance->send(
		MTPInvokeWithoutUpdates<MTPaccount_GetAuthorizations>(
			MTPaccount_GetAuthorizations()),
		[weak](const MTP::Response &response) {
			if (weak && std::chrono::steady_clock::now() < weak->_state->deadline) {
				weak->received(details::ParseMtprotoDeviceInventory(std::span(
					response.reply.constData(), response.reply.size())));
			}
			return true;
		},
		[weak](const MTP::Error &, const MTP::Response &) {
			if (weak) {
				weak->received(std::nullopt);
			}
			return true;
		});
}

void DeviceInventoryOperation::received(DeviceInventory result) {
	QMetaObject::invokeMethod(this, [this, result = std::move(result)]() mutable {
		close(std::move(result));
	}, Qt::QueuedConnection);
}

void DeviceInventoryOperation::close(DeviceInventory result) {
	if (_closed) {
		return;
	}
	_closed = true;
	_timer.stop();
	if (_instance) {
		if (_requestId) {
			_instance->cancel(_requestId);
		}
		_instance.reset();
	}
	_state->finish(std::move(result));
	deleteLater();
}

class TelegramSessionTransport final : public details::SessionRequestTransport {
public:
	explicit TelegramSessionTransport(
		std::map<AccountId, GrantedAccount> accounts);

	EffectResult send(
		const AccountId &accountId,
		std::span<const SessionRequest> requests,
		TimePoint deadline) override;

private:
	const std::map<AccountId, GrantedAccount> _accounts;

};

TelegramSessionTransport::TelegramSessionTransport(
	std::map<AccountId, GrantedAccount> accounts)
: _accounts(std::move(accounts)) {
}

EffectResult TelegramSessionTransport::send(
		const AccountId &accountId,
		std::span<const SessionRequest> requests,
		TimePoint deadline) {
	const auto granted = _accounts.find(accountId);
	if (!IsWorkerThread()
		|| granted == _accounts.end()
		|| requests.empty()
		|| std::chrono::steady_clock::now() >= deadline) {
		return EffectResult::Unconfirmed;
	}
	const auto state = std::make_shared<SessionBatchState>(
		deadline, EffectResult::Unconfirmed);
	StartVerifiedSessionOperation(
		state,
		granted->second,
		[batch = std::vector<SessionRequest>(requests.begin(), requests.end())](
				QObject *app,
				std::shared_ptr<SessionBatchState> state) mutable {
			const auto operation = new SessionBatch(app, std::move(state), std::move(batch));
			operation->start();
		});
	return state->wait();
}

} // namespace

std::optional<std::vector<MtprotoDeviceInventoryEntry>> ReadMtprotoDeviceInventory(
		const ProfileSets::MigrationController &workspace,
		const ProfileSets::AdminVaultAccess &authenticatedMaster,
		ProfileSets::AccountId accountId,
		uint64_t expectedUserId,
		bool testEnvironment,
		CoordinatorClock::TimePoint deadline) {
	const auto now = std::chrono::steady_clock::now();
	if (!IsWorkerThread() || deadline <= now || deadline - now > std::chrono::seconds(15)
		|| !accountId || !expectedUserId || workspace.isIsolatedFixture()
		|| authenticatedMaster.version != ProfileSets::kProfileVaultVersion) {
		return std::nullopt;
	}
	using ProfileSets::AccountKey;
	using ProfileSets::AccountVaultLocator;
	if (std::ranges::count(authenticatedMaster.accounts, accountId, &AccountKey::id) != 1
		|| std::ranges::count(authenticatedMaster.locators, accountId, &AccountVaultLocator::id) != 1) {
		return std::nullopt;
	}
	const auto key = std::ranges::find(authenticatedMaster.accounts, accountId, &AccountKey::id);
	const auto locator = std::ranges::find(
		authenticatedMaster.locators, accountId, &AccountVaultLocator::id);
	const auto root = workspace.accountStorageRoot();
	auto paths = Storage::ScopedAccountPaths(root, ProfileSets::AccountVaultDataName(*locator));
	auto localKey = ProfileSets::ProfileAccountStorageKey(*key);
	if (!paths || !localKey) {
		return std::nullopt;
	}
	const auto state = std::make_shared<DeviceInventoryState>(deadline, std::nullopt);
	StartVerifiedSessionOperation(
		state,
		GrantedAccount{
			.paths = std::move(*paths),
			.key = std::move(localKey),
			.expectedUserId = expectedUserId,
			.testEnvironment = testEnvironment,
		},
		[](QObject *app, std::shared_ptr<DeviceInventoryState> state) {
			const auto operation = new DeviceInventoryOperation(app, std::move(state));
			operation->start();
		});
	return state->wait();
}

std::unique_ptr<RemoteSessionEffect> MakeMtprotoSessionEffect(
		const InstallationId &currentInstallation,
		const EmergencyActionJournal &approved,
		const ProfileSets::MigrationController &workspace,
		const ProfileSets::AccountStoragePlan &grants,
		std::span<const ScopedSessionBinding> bindings) {
	const auto root = workspace.accountStorageRoot();
	if (root.isEmpty()
		|| currentInstallation != approved.installationId
		|| workspace.isIsolatedFixture()) {
		return nullptr;
	}
	auto accounts = std::map<AccountId, GrantedAccount>();
	auto seen = std::set<ProfileSets::AccountId>();
	for (const auto &binding : bindings) {
		const auto permitted = std::ranges::find(
			approved.accounts,
			binding.accountId,
			&JournalAccount::accountId);
		const auto target = grants.targetFor(binding.scopedAccountId);
		const auto key = grants.keyFor(binding.scopedAccountId);
		auto expected = target
			? Storage::ScopedAccountPaths(root, target->dataName)
			: std::nullopt;
		if (permitted == approved.accounts.end()
			|| !binding.expectedUserId
			|| !seen.insert(binding.scopedAccountId).second
			|| !key
			|| !expected
			|| target->paths.mode != Storage::AccountStorageMode::Scoped
			|| target->paths.authPath != expected->authPath
			|| target->paths.basePath != expected->basePath
			|| target->paths.databasePath != expected->databasePath
			|| target->paths.tempPath != expected->tempPath) {
			return nullptr;
		}
		auto localKey = ProfileSets::ProfileAccountStorageKey(*key);
		if (!localKey || !accounts.emplace(binding.accountId, GrantedAccount{
				.paths = std::move(*expected),
				.key = std::move(localKey),
			.expectedUserId = binding.expectedUserId,
			.testEnvironment = binding.testEnvironment,
			}).second) {
			return nullptr;
		}
	}
	return details::MakeBoundSessionEffect(
		currentInstallation,
		approved,
		std::make_unique<TelegramSessionTransport>(std::move(accounts)));
}

} // namespace Ayu::EmergencyActions
