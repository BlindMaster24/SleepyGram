#include "ayu/features/chat_lock/chat_lock.h"

#include "base/random.h"
#include "base/weak_ptr.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/storage_account.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/vertical_list.h"
#include "window/window_session_controller.h"
#include "styles/style_settings.h"
#include "styles/style_passcode_box.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <QApplication>
#include <QEvent>
#include <QStringList>
#include <QTimer>

namespace Ayu::ChatLock {
namespace {

constexpr auto kPinSaltSize = 16;
constexpr auto kMaximumFailures = 5;
constexpr auto kMaximumBackoff = crl::time(60'000);
constexpr auto kInactivityTimeout = 5 * 60 * 1000;

struct PinMaterial final {
	QByteArray salt;
	QByteArray hash;
	Storage::details::PasscodeKdf kdf;
};

struct State final {
	std::set<PeerId> protectedPeers;
	std::set<PeerId> unlockedPeers;
	std::unique_ptr<QTimer> timer;
	int failures = 0;
	crl::time blockedUntil = 0;
	bool verifying = false;
	bool loaded = false;
};

class Manager final : public QObject {
public:
	static Manager &Instance() {
		static auto manager = Manager();
		return manager;
	}

	State &state(uint64 accountId) {
		auto &result = _states[accountId];
		if (!result.timer) {
			result.timer = std::make_unique<QTimer>();
			result.timer->setSingleShot(true);
			connect(result.timer.get(), &QTimer::timeout, this, [=] {
				LockAccount(accountId);
			});
		}
		return result;
	}

	void load(not_null<Main::Session*> session) {
		auto &value = state(session->userId().bare);
		if (value.loaded) {
			return;
		}
		value.loaded = true;
		const auto peers = session->local().readPref<QString>(
			"ayu.chatPin.protected",
			QString());
		for (const auto &part : peers.split(u',', Qt::SkipEmptyParts)) {
			bool ok = false;
			const auto raw = part.toULongLong(&ok);
			if (ok && raw) {
				value.protectedPeers.insert(PeerId(PeerIdHelper{ raw }));
			}
		}
	}

	bool hasPin(not_null<Main::Session*> session) const {
		return !session->local().readPref<QString>(
			"ayu.chatPin.hash",
			QString()).isEmpty();
	}

	void fire(uint64 accountId, PeerId peerId) {
		_changes.fire({ .accountId = accountId, .peerId = peerId });
	}

	void startTimer(uint64 accountId) {
		if (_activeAccountId != accountId) {
			return;
		}
		state(accountId).timer->start(kInactivityTimeout);
	}

	void noteActivity() {
		if (!_activeAccountId) {
			return;
		}
		const auto i = _states.find(_activeAccountId);
		if (i != end(_states) && !i->second.unlockedPeers.empty()) {
			startTimer(_activeAccountId);
		}
	}

	void lockPeer(uint64 accountId, PeerId peerId) {
		const auto i = _states.find(accountId);
		if (i == end(_states) || !i->second.unlockedPeers.erase(peerId)) {
			return;
		}
		if (i->second.unlockedPeers.empty()) {
			i->second.timer->stop();
		}
		fire(accountId, peerId);
	}

	void lockAccount(uint64 accountId) {
		const auto i = _states.find(accountId);
		if (i == end(_states) || i->second.unlockedPeers.empty()) {
			return;
		}
		i->second.unlockedPeers.clear();
		i->second.timer->stop();
		fire(accountId, PeerId());
	}

	void switchAccount(uint64 previous, uint64 next) {
		if (previous) {
			lockAccount(previous);
		}
		if (next) {
			lockAccount(next);
		}
		_activeAccountId = next;
	}

	void unlockPeer(not_null<Main::Session*> session, PeerId peerId) {
		const auto id = session->userId().bare;
		auto &value = state(id);
		value.unlockedPeers.insert(peerId);
		value.failures = 0;
		value.blockedUntil = 0;
		value.verifying = false;
		startTimer(id);
		fire(id, peerId);
	}

	bool failed(not_null<Main::Session*> session) {
		auto &value = state(session->userId().bare);
		value.verifying = false;
		const auto now = crl::now();
		if (value.blockedUntil > now) {
			return true;
		}
		value.failures = std::min(value.failures + 1, kMaximumFailures);
		if (value.failures == kMaximumFailures) {
			const auto multiplier = (value.failures - kMaximumFailures + 1);
			value.blockedUntil = now + std::min(
				crl::time(5'000 * multiplier),
				kMaximumBackoff);
		}
		return false;
	}

	bool blocked(not_null<Main::Session*> session) {
		const auto &value = state(session->userId().bare);
		return value.verifying || (value.blockedUntil > crl::now());
	}

	bool beginVerification(not_null<Main::Session*> session) {
		auto &value = state(session->userId().bare);
		if (value.verifying || value.blockedUntil > crl::now()) {
			return false;
		}
		value.verifying = true;
		return true;
	}

	bool eventFilter(QObject *watched, QEvent *event) override {
		if (event->type() == QEvent::KeyPress
			|| event->type() == QEvent::MouseButtonPress
			|| event->type() == QEvent::TouchBegin) {
			noteActivity();
		}
		return QObject::eventFilter(watched, event);
	}

	rpl::producer<Change> changes() const {
		return _changes.events();
	}

private:
	Manager() {
		if (qApp) {
			qApp->installEventFilter(this);
		}
	}

	std::map<uint64, State> _states;
	uint64 _activeAccountId = 0;
	rpl::event_stream<Change> _changes;
};

struct Derivation final {
	QByteArray passcode;
	PinMaterial material;
	QByteArray result;
	bool matched = false;

	void run() {
		const auto key = Storage::details::CreatePasscodeKey(
			passcode,
			material.salt,
			material.kdf);
		if (key) {
			const auto bytes = key->data();
			result = QByteArray(
				reinterpret_cast<const char*>(bytes.data()),
				int(bytes.size()));
			if (!material.hash.isEmpty()) {
				matched = (result.size() == material.hash.size())
					&& (CRYPTO_memcmp(
						result.constData(),
						material.hash.constData(),
						size_t(result.size())) == 0);
			}
		}
		OPENSSL_cleanse(passcode.data(), size_t(passcode.size()));
	}
};

PinMaterial ReadPinMaterial(not_null<Main::Session*> session) {
	const auto kdfText = session->local().readPref<QString>(
		"ayu.chatPin.kdf",
		QString());
	const auto parts = kdfText.split(u',');
	if (parts.size() != 4) {
		return {};
	}
	bool ok = true;
	const auto read = [&](int index) {
		bool current = false;
		const auto value = parts[index].toUInt(&current);
		ok = ok && current;
		return value;
	};
	const auto kdf = Storage::details::PasscodeKdf{
		.kind = read(0),
		.memory = read(1),
		.time = read(2),
		.parallel = read(3),
	};
	const auto salt = QByteArray::fromBase64(session->local().readPref<QString>(
		"ayu.chatPin.salt",
		QString()).toUtf8());
	const auto hash = QByteArray::fromHex(session->local().readPref<QString>(
		"ayu.chatPin.hash",
		QString()).toLatin1());
	if (!ok || !kdf.valid() || !kdf.costWithinLimits()
		|| salt.size() < Storage::details::kPasscodeSaltMinSize
		|| hash.isEmpty()) {
		return {};
	}
	return { salt, hash, kdf };
}

void RunDerivation(Derivation job, Fn<void(Derivation)> done) {
	crl::async([job = std::move(job), done = std::move(done)]() mutable {
		job.run();
		crl::on_main([job = std::move(job), done = std::move(done)]() mutable {
			done(std::move(job));
		});
	});
}

} // namespace

bool HasPin(not_null<Main::Session*> session) {
	return Manager::Instance().hasPin(session);
}

bool IsPeerProtected(not_null<Main::Session*> session, PeerId peerId) {
	auto &manager = Manager::Instance();
	manager.load(session);
	return manager.state(session->userId().bare).protectedPeers.contains(peerId);
}

bool IsChatLocked(not_null<Main::Session*> session, PeerId peerId) {
	if (!IsPeerProtected(session, peerId)) {
		return false;
	}
	if (!HasPin(session)) {
		return true;
	}
	return !Manager::Instance().state(session->userId().bare).unlockedPeers.contains(peerId);
}

void SetPin(
		not_null<Main::Session*> session,
		QString pin,
		Fn<void(bool)> done) {
	if (pin.size() < 4 || pin.size() > 64) {
		done(false);
		return;
	}
	auto salt = QByteArray(kPinSaltSize, Qt::Uninitialized);
	base::RandomFill(salt.data(), salt.size());
	auto job = Derivation{
		.passcode = pin.toUtf8(),
		.material = {
			.salt = salt,
			.kdf = Storage::details::DefaultPasscodeKdf(),
		},
	};
	pin.fill(QChar(0));
	const auto weak = base::make_weak(session.get());
	RunDerivation(std::move(job), [=](Derivation result) mutable {
		const auto strong = weak.get();
		if (!strong || result.result.isEmpty()) {
			done(false);
			return;
		}
		const auto kdf = result.material.kdf;
		strong->local().writePref<QString>(
			"ayu.chatPin.salt",
			QString::fromLatin1(result.material.salt.toBase64()));
		strong->local().writePref<QString>(
			"ayu.chatPin.hash",
			QString::fromLatin1(result.result.toHex()));
		strong->local().writePref<QString>(
			"ayu.chatPin.kdf",
			QStringLiteral("%1,%2,%3,%4")
				.arg(kdf.kind)
				.arg(kdf.memory)
				.arg(kdf.time)
				.arg(kdf.parallel));
		done(true);
	});
}

void VerifyPin(
		not_null<Main::Session*> session,
		PeerId peerId,
		QString pin,
		Fn<void(bool)> done) {
	auto &manager = Manager::Instance();
	manager.load(session);
	if (manager.blocked(session)) {
		done(false);
		return;
	}
	if (!manager.beginVerification(session)) {
		done(false);
		return;
	}
	auto material = ReadPinMaterial(session);
	if (material.hash.isEmpty() || pin.isEmpty()) {
		manager.failed(session);
		done(false);
		return;
	}
	auto job = Derivation{ .passcode = pin.toUtf8(), .material = material };
	pin.fill(QChar(0));
	const auto weak = base::make_weak(session.get());
	RunDerivation(std::move(job), [=](Derivation result) mutable {
		const auto strong = weak.get();
		if (!strong) {
			done(false);
			return;
		}
		if (!result.matched) {
			Manager::Instance().failed(strong);
			done(false);
			return;
		}
		Manager::Instance().unlockPeer(strong, peerId);
		done(true);
	});
}

bool SetPeerProtected(
		not_null<Main::Session*> session,
		PeerId peerId,
		bool protectedChat) {
	auto &manager = Manager::Instance();
	manager.load(session);
	auto &value = manager.state(session->userId().bare);
	if (protectedChat && !manager.hasPin(session)) {
		return false;
	}
	if (!protectedChat
		&& value.protectedPeers.contains(peerId)
		&& !value.unlockedPeers.contains(peerId)) {
		return false;
	}
	if (protectedChat) {
		value.protectedPeers.insert(peerId);
		value.unlockedPeers.erase(peerId);
	} else {
		value.protectedPeers.erase(peerId);
		value.unlockedPeers.erase(peerId);
	}
	auto ids = QStringList();
	for (const auto id : value.protectedPeers) {
		ids.push_back(QString::number(id.value));
	}
	session->local().writePref<QString>(
		"ayu.chatPin.protected",
		ids.join(u','));
	manager.fire(session->userId().bare, peerId);
	return true;
}

void LockPeer(uint64 accountId, PeerId peerId) {
	Manager::Instance().lockPeer(accountId, peerId);
}

void LockAccount(uint64 accountId) {
	Manager::Instance().lockAccount(accountId);
}

void OnAccountSwitch(uint64 previousAccountId, uint64 nextAccountId) {
	Manager::Instance().switchAccount(previousAccountId, nextAccountId);
}

void ShowUnlockDialog(
		not_null<Window::SessionController*> controller,
		PeerId peerId,
		Fn<void(bool)> done) {
	const auto session = &controller->session();
	const auto weak = base::make_weak(controller.get());
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		const auto weakBox = base::weak_qptr<Ui::BoxContent>(box.get());
		box->setTitle(tr::lng_passcode_enter_old());
		const auto wrap = box->addRow(object_ptr<Ui::RpWidget>(box));
		wrap->resize(wrap->width(), st::settingLocalPasscodeInputField.heightMin);
		const auto field = Ui::CreateChild<Ui::PasswordInput>(
			wrap,
			st::settingLocalPasscodeInputField,
			tr::lng_passcode_enter_old());
		wrap->widthValue(
		) | rpl::on_next([=](int width) {
			field->moveToLeft((width - field->width()) / 2, 0);
		}, wrap->lifetime());
		box->setFocusCallback([=] { field->setFocus(); });
		box->addButton(tr::lng_cancel(), [=] {
			box->closeBox();
			if (done) done(false);
		});
		box->addButton(tr::lng_continue(), [=] {
			auto pin = field->text();
			field->clear();
			VerifyPin(session, peerId, std::move(pin), [=](bool success) {
			const auto strongBox = weakBox.get();
			if (!weak || !strongBox) return;
				if (success) {
				strongBox->closeBox();
					if (done) done(true);
				} else {
					field->clear();
					field->setPlaceholderText(tr::lng_passcode_wrong(tr::now));
				}
			});
		});
	}));
}

void ShowProtectDialog(
		not_null<Window::SessionController*> controller,
		PeerId peerId) {
	const auto session = &controller->session();
	if (HasPin(session)) {
		if (IsPeerProtected(session, peerId)) {
			if (IsChatLocked(session, peerId)) {
				ShowUnlockDialog(controller, peerId, nullptr);
			} else {
				SetPeerProtected(session, peerId, false);
			}
		} else {
			SetPeerProtected(session, peerId, true);
		}
		return;
	}
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		const auto weakBox = base::weak_qptr<Ui::BoxContent>(box.get());
		box->setTitle(tr::lng_passcode_create());
		const auto makeField = [&](rpl::producer<QString> placeholder) {
			const auto wrap = box->addRow(object_ptr<Ui::RpWidget>(box));
			wrap->resize(wrap->width(), st::settingLocalPasscodeInputField.heightMin);
			const auto field = Ui::CreateChild<Ui::PasswordInput>(
				wrap,
				st::settingLocalPasscodeInputField,
				std::move(placeholder));
			wrap->widthValue(
			) | rpl::on_next([=](int width) {
				field->moveToLeft((width - field->width()) / 2, 0);
			}, wrap->lifetime());
			return field;
		};
		const auto first = makeField(tr::lng_passcode_enter_first());
		const auto second = makeField(tr::lng_passcode_confirm_new());
		box->setFocusCallback([=] { first->setFocus(); });
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
		box->addButton(tr::lng_continue(), [=] {
			auto pin = first->text();
			const auto confirmation = second->text();
			first->clear();
			second->clear();
			if (pin.size() < 4 || pin != confirmation) {
				pin.fill(QChar(0));
				first->setPlaceholderText(tr::lng_passcode_differ(tr::now));
				return;
			}
			SetPin(session, std::move(pin), [=](bool success) {
				const auto strongBox = weakBox.get();
				if (!strongBox) return;
				if (success) {
					SetPeerProtected(session, peerId, true);
					strongBox->closeBox();
				} else {
					first->setPlaceholderText(tr::lng_passcode_wrong(tr::now));
				}
			});
		});
	}));
}

rpl::producer<Change> Changes() {
	return Manager::Instance().changes();
}

} // namespace Ayu::ChatLock
