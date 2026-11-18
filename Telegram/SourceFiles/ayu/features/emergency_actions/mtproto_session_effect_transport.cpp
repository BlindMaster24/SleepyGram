// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/mtproto_session_effect_transport.h"

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
};

class SessionBatchState final {
public:
	explicit SessionBatchState(TimePoint deadline);

	[[nodiscard]] bool setConnection(
		std::unique_ptr<Storage::ScopedAccountConnection> connection);
	[[nodiscard]] auto takeConnection()
	-> std::unique_ptr<Storage::ScopedAccountConnection>;
	[[nodiscard]] EffectResult wait();
	void finish(EffectResult result);

	const TimePoint deadline;

private:
	std::mutex _mutex;
	std::condition_variable _done;
	std::unique_ptr<Storage::ScopedAccountConnection> _connection;
	std::optional<EffectResult> _result;

};

SessionBatchState::SessionBatchState(TimePoint deadline)
: deadline(deadline) {
}

bool SessionBatchState::setConnection(
		std::unique_ptr<Storage::ScopedAccountConnection> connection) {
	const auto lock = std::lock_guard(_mutex);
	if (_result || std::chrono::steady_clock::now() >= deadline) {
		return false;
	}
	_connection = std::move(connection);
	return true;
}

auto SessionBatchState::takeConnection()
-> std::unique_ptr<Storage::ScopedAccountConnection> {
	const auto lock = std::lock_guard(_mutex);
	return !_result && std::chrono::steady_clock::now() < deadline
		? std::move(_connection)
		: nullptr;
}

EffectResult SessionBatchState::wait() {
	auto lock = std::unique_lock(_mutex);
	if (!_done.wait_until(lock, deadline, [&] { return _result.has_value(); })) {
		_connection.reset();
		_result = EffectResult::Unconfirmed;
	}
	return *_result;
}

void SessionBatchState::finish(EffectResult result) {
	const auto lock = std::lock_guard(_mutex);
	if (!_result) {
		_result = (std::chrono::steady_clock::now() < deadline)
			? result
			: EffectResult::Unconfirmed;
		_done.notify_one();
	}
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
	auto fields = MTP::Instance::Fields();
	fields.config = std::move(data->config);
	fields.mainDcId = data->mainDcId;
	fields.keys.push_back(std::move(data->mainKey));
	fields.emergencyDeadline = _state->deadline;
	_instance = std::make_unique<MTP::Instance>(
		MTP::Instance::Mode::EmergencySessionEffect,
		std::move(fields));
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
	const auto app = QCoreApplication::instance();
	const auto granted = _accounts.find(accountId);
	if (!app || QCoreApplication::closingDown()
		|| QThread::currentThread() == app->thread()
		|| granted == _accounts.end()
		|| requests.empty()
		|| std::chrono::steady_clock::now() >= deadline) {
		return EffectResult::Unconfirmed;
	}
	const auto &account = granted->second;
	const auto state = std::make_shared<SessionBatchState>(deadline);
	crl::async([state, account, batch = std::vector<SessionRequest>(
			requests.begin(), requests.end())]() mutable {
		if (std::chrono::steady_clock::now() >= state->deadline) {
			return;
		}
		auto data = Storage::ReadScopedAccountConnection(account.paths, account.key);
		if (!data) {
			state->finish(EffectResult::Unconfirmed);
			return;
		}
		if (!state->setConnection(std::move(data))) {
			return;
		}
		crl::on_main([state, batch = std::move(batch)]() mutable {
			const auto app = QCoreApplication::instance();
			if (!app || QCoreApplication::closingDown()) {
				state->finish(EffectResult::Unconfirmed);
				return;
			}
			const auto operation = new SessionBatch(app, state, std::move(batch));
			operation->start();
		});
	});
	return state->wait();
}

} // namespace

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
