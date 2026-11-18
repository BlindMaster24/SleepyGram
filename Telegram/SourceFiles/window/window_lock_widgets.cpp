/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "window/window_lock_widgets.h"

#include "base/platform/base_platform_info.h"
#include "base/call_delayed.h"
#include "base/openssl_help.h"
#include "base/system_unlock.h"
#include "lang/lang_keys.h"
#include "storage/storage_domain.h"
#include "mainwindow.h"
#include "core/application.h"
#include "core/crash_report_window.h"
#include "api/api_text_entities.h"
#include "ui/text/text.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "ui/wrap/vertical_layout.h"
#include "ui/toast/toast.h"
#include "ui/ui_utility.h"
#include "window/window_controller.h"
#include "window/window_slide_animation.h"
#include "window/window_session_controller.h"
#include "main/main_domain.h"
#include "styles/style_layers.h"
#include "styles/style_passcode_box.h"
#include "styles/style_window_lock_widgets.h"

#include <QtCore/QPointer>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QVBoxLayout>

// AyuGram includes
#include "ayu/features/profile_sets/profile_generation.h"


namespace Window {
namespace {

namespace ProfileSets = Ayu::ProfileSets;

constexpr auto kSystemUnlockDelay = crl::time(1000);

class ScopedProfileLockWindow final : public PreLaunchWindow {
public:
	ScopedProfileLockWindow(
		not_null<Main::Domain*> domain,
		ProfileSets::MigrationController sidecar,
		Fn<bool(const ProfileSets::MigrationController &)> startSet);
	~ScopedProfileLockWindow() override;

protected:
	void closeEvent(QCloseEvent *e) override;

private:
	void showForm(QString status);
	void submit();
	void authenticationDone(
		std::optional<ProfileSets::OpenedProfileGeneration> generation,
		ProfileSets::ProfileGenerationError error);
	void showPreparedProfile();
	void lockProfile();
	void clearProfile();

	const not_null<Main::Domain*> _domain;
	const ProfileSets::MigrationController _sidecar;
	const Fn<bool(const ProfileSets::MigrationController &)> _startSet;
	const not_null<PreLaunchLabel*> _status;
	const not_null<PreLaunchInput*> _passcode;
	const not_null<QListWidget*> _sets;
	const not_null<PreLaunchButton*> _unlock;
	const not_null<PreLaunchButton*> _lock;
	bool _checking = false;
	bool _closing = false;

};

ScopedProfileLockWindow::ScopedProfileLockWindow(
		not_null<Main::Domain*> domain,
		ProfileSets::MigrationController sidecar,
		Fn<bool(const ProfileSets::MigrationController &)> startSet)
: _domain(domain)
, _sidecar(std::move(sidecar))
, _startSet(std::move(startSet))
, _status(new PreLaunchLabel(this))
, _passcode(new PreLaunchInput(this, true))
, _sets(new QListWidget(this))
, _unlock(new PreLaunchButton(this))
, _lock(new PreLaunchButton(this)) {
	_status->setWordWrap(true);
	_passcode->setAccessibleName(u"Passcode"_q);
	_passcode->setInputMethodHints(
		Qt::ImhHiddenText | Qt::ImhSensitiveData | Qt::ImhNoPredictiveText);
	_sets->setSelectionMode(QAbstractItemView::NoSelection);
	_sets->setAccessibleName(u"Sets"_q);
	_unlock->setText(u"Unlock"_q);
	_lock->setText(u"Lock"_q);
	const auto close = new PreLaunchButton(this, false);
	close->setText(u"Close"_q);

	connect(_passcode.get(), &QLineEdit::returnPressed, this, [this] {
		submit();
	});
	connect(_unlock.get(), &QPushButton::clicked, this, [this] { submit(); });
	connect(_lock.get(), &QPushButton::clicked, this, [this] { lockProfile(); });
	connect(close, &QPushButton::clicked, this, [this] { this->close(); });

	const auto layout = new QVBoxLayout(this);
	layout->addWidget(_status.get());
	layout->addWidget(_passcode.get());
	layout->addWidget(_sets.get());
	const auto actions = new QHBoxLayout();
	actions->addStretch();
	actions->addWidget(close);
	actions->addWidget(_lock.get());
	actions->addWidget(_unlock.get());
	layout->addLayout(actions);
	showForm(u"Enter your passcode."_q);
}

ScopedProfileLockWindow::~ScopedProfileLockWindow() {
	_closing = true;
	clearProfile();
}

void ScopedProfileLockWindow::showForm(QString status) {
	_status->setText(status);
	_sets->hide();
	_lock->hide();
	_passcode->show();
	_unlock->show();
	_passcode->setEnabled(true);
	_unlock->setEnabled(true);
	_passcode->setFocus();
}

void ScopedProfileLockWindow::submit() {
	if (_checking || _closing || Core::Quitting()
		|| _domain->preparedScopedProfileAccess()) {
		return;
	}
	if (_passcode->text().isEmpty()) {
		showForm(u"Enter your passcode."_q);
		return;
	} else if (!passcodeCanTry()) {
		_passcode->setText(QString());
		showForm(u"Too many tries. Please try again later."_q);
		return;
	}
	auto passcode = _passcode->text();
	_passcode->setText(QString());
	_checking = true;
	_status->setText(u"Checking passcode…"_q);
	_passcode->setEnabled(false);
	_unlock->setEnabled(false);
	const auto weak = QPointer<ScopedProfileLockWindow>(this);
	ProfileSets::AuthenticateScopedProfilePasscode(
		_sidecar,
		std::move(passcode),
		[weak](std::optional<ProfileSets::OpenedProfileGeneration> generation,
				ProfileSets::ProfileGenerationError error) {
			if (weak) {
				weak->authenticationDone(std::move(generation), error);
			}
		});
}

void ScopedProfileLockWindow::authenticationDone(
		std::optional<ProfileSets::OpenedProfileGeneration> generation,
		ProfileSets::ProfileGenerationError error) {
	if (!_checking || _closing || Core::Quitting()) {
		return;
	}
	_checking = false;
	if (!generation) {
		if (error == ProfileSets::ProfileGenerationError::WrongPassword) {
			cSetPasscodeBadTries(cPasscodeBadTries() + 1);
			cSetPasscodeLastTry(crl::now());
			showForm(u"Wrong passcode."_q);
		} else {
			showForm(u"Local data could not be opened."_q);
		}
		return;
	}
	if (!_domain->prepareScopedProfile(_sidecar, std::move(*generation))) {
		showForm(u"Local data could not be opened."_q);
		return;
	}
	cSetPasscodeBadTries(0);
	showPreparedProfile();
}

void ScopedProfileLockWindow::showPreparedProfile() {
	_passcode->hide();
	_unlock->hide();
	_lock->show();
	if (const auto metadata = _domain->preparedScopedAdminMetadata()) {
		_status->setText(metadata->sets.empty() ? u"No sets yet."_q : u"Sets"_q);
		for (const auto &set : metadata->sets) {
			_sets->addItem(set.name);
		}
		_sets->setVisible(!metadata->sets.empty());
	} else if (_domain->preparedScopedAccountCount() == 0) {
		_status->setText(u"This set has no accounts."_q);
	} else if (_startSet(_sidecar)) {
		hide();
		return;
	} else {
		clearProfile();
		showForm(u"Local data could not be opened."_q);
		return;
	}
	_lock->setFocus();
}

void ScopedProfileLockWindow::lockProfile() {
	clearProfile();
	showForm(u"Enter your passcode."_q);
}

void ScopedProfileLockWindow::clearProfile() {
	_passcode->setText(QString());
	_sets->clear();
	_domain->clearPreparedScopedProfile();
}

void ScopedProfileLockWindow::closeEvent(QCloseEvent *e) {
	_closing = true;
	clearProfile();
	PreLaunchWindow::closeEvent(e);
	Core::Quit();
}

} // namespace

std::unique_ptr<PreLaunchWindow> CreateScopedProfileLockWindow(
		not_null<Main::Domain*> domain,
		ProfileSets::MigrationController sidecar,
		Fn<bool(const ProfileSets::MigrationController &)> startSet) {
	return std::make_unique<ScopedProfileLockWindow>(
		domain,
		std::move(sidecar),
		std::move(startSet));
}

PasscodeAttempt TryPasscode(
		const QString &passcode,
		Fn<void(bool correct)> done) {
	if (!Core::App().legacyProfileAccessAllowed()) {
		return PasscodeAttempt::Unavailable;
	} else if (passcode.isEmpty()) {
		return PasscodeAttempt::Empty;
	} else if (!passcodeCanTry()) {
		return PasscodeAttempt::Flood;
	}
	auto utf8 = passcode.toUtf8();
	const auto cleanse = gsl::finally([&] {
		OPENSSL_cleanse(utf8.data(), utf8.size());
	});
	auto counted = [done = std::move(done)](bool correct) {
		if (!correct && Core::App().passcodeLocked()) {
			cSetPasscodeBadTries(cPasscodeBadTries() + 1);
			cSetPasscodeLastTry(crl::now());
		}
		done(correct);
	};
	return Core::App().domain().tryPasscode(utf8, std::move(counted))
		? PasscodeAttempt::Started
		: PasscodeAttempt::Busy;
}

PasscodeAttempt TryLockScreenPasscode(
		const QString &passcode,
		Fn<void(bool correct)> done) {
	return TryPasscode(passcode, std::move(done));
}

LockWidget::LockWidget(QWidget *parent, not_null<Controller*> window)
: RpWidget(parent)
, _window(window) {
	show();
}

LockWidget::~LockWidget() = default;

not_null<Controller*> LockWidget::window() const {
	return _window;
}

void LockWidget::setInnerFocus() {
	setFocus();
}

void LockWidget::showAnimated(QPixmap oldContentCache) {
	_showAnimation = nullptr;

	showChildren();
	setInnerFocus();
	auto newContentCache = Ui::GrabWidget(this);
	hideChildren();

	_showAnimation = std::make_unique<Window::SlideAnimation>();
	_showAnimation->setRepaintCallback([=] { update(); });
	_showAnimation->setFinishedCallback([=] { showFinished(); });
	_showAnimation->setPixmaps(oldContentCache, newContentCache);
	_showAnimation->start();

	show();
}

void LockWidget::showFinished() {
	showChildren();
	_window->widget()->setInnerFocus();
	_showAnimation = nullptr;
	if (const auto controller = _window->sessionController()) {
		controller->clearSectionStack();
	}
}

void LockWidget::paintEvent(QPaintEvent *e) {
	auto p = QPainter(this);

	if (_showAnimation) {
		_showAnimation->paintContents(p);
		return;
	}
	paintContent(p);
}

void LockWidget::paintContent(QPainter &p) {
	p.fillRect(rect(), st::windowBg);
}

PasscodeLockWidget::PasscodeLockWidget(
	QWidget *parent,
	not_null<Controller*> window)
: LockWidget(parent, window)
, _passcode(this, st::passcodeInput, tr::lng_passcode_ph())
, _submit(this, tr::lng_passcode_submit(), st::passcodeSubmit)
, _logout(this, tr::lng_passcode_logout(tr::now)) {
	connect(_passcode, &Ui::MaskedInputField::changed, [=] { changed(); });
	connect(_passcode, &Ui::MaskedInputField::submitted, [=] { submit(); });
	_submit->setClickedCallback([=] { submit(); });
	_logout->setClickedCallback([=] {
		if (Core::App().legacyProfileAccessAllowed()) {
			window->showLogoutConfirmation();
		}
	});
	const auto legacy = Core::App().legacyProfileAccessAllowed();
	if (!legacy) {
		_logout->hide();
	}

	using namespace rpl::mappers;
	if (legacy && Core::App().settings().systemUnlockEnabled()) {
		_systemUnlockAvailable = base::SystemUnlockStatus(
			true
		) | rpl::map([](base::SystemUnlockAvailability status) {
			return status.withBiometrics
				? SystemUnlockType::Biometrics
				: status.withCompanion
				? SystemUnlockType::Companion
				: status.available
				? SystemUnlockType::Default
				: SystemUnlockType::None;
		});
		if (Core::App().domain().started()) {
			_systemUnlockAllowed = _systemUnlockAvailable.value();
			setupSystemUnlock();
		} else {
			setupSystemUnlockInfo();
		}
	}
}

void PasscodeLockWidget::setupSystemUnlockInfo() {
	const auto macos = [&] {
		return _systemUnlockAvailable.value(
		) | rpl::map([](SystemUnlockType type) {
			return (type == SystemUnlockType::Biometrics)
				? tr::lng_passcode_touchid()
				: (type == SystemUnlockType::Companion)
				? tr::lng_passcode_applewatch()
				: tr::lng_passcode_systempwd();
		}) | rpl::flatten_latest();
	};
	auto text = Platform::IsWindows()
		? tr::lng_passcode_winhello()
		: macos();
	const auto info = Ui::CreateChild<Ui::FlatLabel>(
		this,
		std::move(text),
		st::passcodeSystemUnlockLater);
	_logout->geometryValue(
	) | rpl::on_next([=](QRect logout) {
		info->resizeToWidth(width()
			- st::boxRowPadding.left()
			- st::boxRowPadding.right());
		info->moveToLeft(
			st::boxRowPadding.left(),
			logout.y() + logout.height() + st::passcodeSystemUnlockSkip);
	}, info->lifetime());
	info->showOn(_systemUnlockAvailable.value(
	) | rpl::map(rpl::mappers::_1 != SystemUnlockType::None));
}

void PasscodeLockWidget::setupSystemUnlock() {
	windowActiveValue() | rpl::skip(1) | rpl::filter([=](bool active) {
		return active
			&& !_systemUnlockSuggested
			&& !_systemUnlockCooldown.isActive();
	}) | rpl::on_next([=](bool) {
		[[maybe_unused]] auto refresh = base::SystemUnlockStatus();
		suggestSystemUnlock();
	}, lifetime());

	const auto button = Ui::CreateChild<Ui::IconButton>(
		_passcode.data(),
		st::passcodeSystemUnlock);
	if (!Platform::IsWindows()) {
		using namespace base;
		_systemUnlockAllowed.value(
		) | rpl::on_next([=](SystemUnlockType type) {
			const auto icon = (type == SystemUnlockType::Biometrics)
				? &st::passcodeSystemTouchID
				: (type == SystemUnlockType::Companion)
				? &st::passcodeSystemAppleWatch
				: &st::passcodeSystemSystemPwd;
			button->setIconOverride(icon, icon);
		}, button->lifetime());
	}
	button->showOn(_systemUnlockAllowed.value(
	) | rpl::map(rpl::mappers::_1 != SystemUnlockType::None));
	_passcode->sizeValue() | rpl::on_next([=](QSize size) {
		button->moveToRight(0, size.height() - button->height());
	}, button->lifetime());
	button->setClickedCallback([=] {
		const auto delay = st::passcodeSystemUnlock.ripple.hideDuration;
		base::call_delayed(delay, this, [=] {
			suggestSystemUnlock();
		});
	});
}

void PasscodeLockWidget::suggestSystemUnlock() {
	InvokeQueued(this, [=] {
		if (_systemUnlockSuggested) {
			return;
		}
		_systemUnlockCooldown.cancel();

		using namespace base;
		_systemUnlockAllowed.value(
		) | rpl::filter(
			rpl::mappers::_1 != SystemUnlockType::None
		) | rpl::take(1) | rpl::on_next([=] {
			const auto weak = base::make_weak(this);
			const auto done = [weak](SystemUnlockResult result) {
				crl::on_main([=] {
					if (const auto strong = weak.get()) {
						strong->systemUnlockDone(result);
					}
				});
			};
			SuggestSystemUnlock(
				this,
				(::Platform::IsWindows()
					? tr::lng_passcode_winhello_unlock(tr::now)
					: tr::lng_passcode_touchid_unlock(tr::now)),
				done);
		}, _systemUnlockSuggested);
	});
}

void PasscodeLockWidget::systemUnlockDone(base::SystemUnlockResult result) {
	if (!Core::App().legacyProfileAccessAllowed()) {
		return;
	} else if (result == base::SystemUnlockResult::Success) {
		Core::App().unlockPasscode();
		return;
	}
	_systemUnlockCooldown.callOnce(kSystemUnlockDelay);
	_systemUnlockSuggested.destroy();
	if (result == base::SystemUnlockResult::FloodError) {
		_error = tr::lng_flood_error(tr::now);
		_passcode->setFocusFast();
		update();
	}
}

void PasscodeLockWidget::paintContent(QPainter &p) {
	LockWidget::paintContent(p);

	p.setFont(st::passcodeHeaderFont);
	p.setPen(st::windowFg);
	p.drawText(QRect(0, _passcode->y() - st::passcodeHeaderHeight, width(), st::passcodeHeaderHeight), tr::lng_passcode_enter(tr::now), style::al_center);

	if (!_error.isEmpty()) {
		p.setFont(st::boxTextFont);
		p.setPen(st::boxTextFgError);
		p.drawText(QRect(0, _passcode->y() + _passcode->height(), width(), st::passcodeSubmitSkip), _error, style::al_center);
	}
}

void PasscodeLockWidget::submit() {
	auto done = crl::guard(this, [=](bool correct) {
		setDeriving(false);
		if (correct) {
			Core::App().unlockPasscode(); // Destroys this widget.
		} else {
			error();
		}
	});
	switch (TryLockScreenPasscode(_passcode->text(), std::move(done))) {
	case PasscodeAttempt::Unavailable:
		_error = tr::lng_cant_do_this(tr::now);
		update();
		return;
	case PasscodeAttempt::Empty:
		_passcode->showError();
		return;
	case PasscodeAttempt::Flood:
		_error = tr::lng_flood_error(tr::now);
		_passcode->showError();
		update();
		return;
	case PasscodeAttempt::Busy:
		return;
	case PasscodeAttempt::Started:
		setDeriving(true);
		return;
	}
}

void PasscodeLockWidget::error() {
	_error = tr::lng_passcode_wrong(tr::now);
	_passcode->selectAll();
	_passcode->showError();
	update();
}

void PasscodeLockWidget::setDeriving(bool deriving) {
	_passcode->setDisabled(deriving);
	_submit->setDisabled(deriving);
	_submit->setAttribute(Qt::WA_TransparentForMouseEvents, deriving);
	_submit->setTextFgOverride(deriving
		? std::make_optional(st::passcodeSubmit.numbersTextFg->c)
		: std::nullopt);
	if (!deriving) {
		_passcode->setFocusFast();
	}
}

void PasscodeLockWidget::changed() {
	if (!_error.isEmpty()) {
		_error = QString();
		update();
	}
}

void PasscodeLockWidget::resizeEvent(QResizeEvent *e) {
	_passcode->move((width() - _passcode->width()) / 2, (height() / 3));
	_submit->move(_passcode->x(), _passcode->y() + _passcode->height() + st::passcodeSubmitSkip);
	_logout->move(_passcode->x() + (_passcode->width() - _logout->width()) / 2, _submit->y() + _submit->height() + st::linkFont->ascent);
}

void PasscodeLockWidget::setInnerFocus() {
	LockWidget::setInnerFocus();
	_passcode->setFocusFast();
}

TermsLock TermsLock::FromMTP(
		Main::Session *session,
		const MTPDhelp_termsOfService &data) {
	const auto minAge = data.vmin_age_confirm();
	return {
		bytes::make_vector(data.vid().c_dataJSON().vdata().v),
		TextWithEntities {
			qs(data.vtext()),
			Api::EntitiesFromMTP(session, data.ventities().v) },
		(minAge ? std::make_optional(minAge->v) : std::nullopt),
		data.is_popup()
	};
}

TermsBox::TermsBox(
	QWidget*,
	const TermsLock &data,
	rpl::producer<QString> agree,
	rpl::producer<QString> cancel)
: _data(data)
, _agree(std::move(agree))
, _cancel(std::move(cancel)) {
}

TermsBox::TermsBox(
	QWidget*,
	const TextWithEntities &text,
	rpl::producer<QString> agree,
	rpl::producer<QString> cancel,
	bool attentionAgree)
: _data{ {}, text, std::nullopt, false }
, _agree(std::move(agree))
, _cancel(std::move(cancel))
, _attentionAgree(attentionAgree) {
}

rpl::producer<> TermsBox::agreeClicks() const {
	return _agreeClicks.events();
}

rpl::producer<> TermsBox::cancelClicks() const {
	return _cancelClicks.events();
}

void TermsBox::prepare() {
	setTitle(tr::lng_terms_header());

	auto check = std::make_unique<Ui::CheckView>(st::defaultCheck, false);
	const auto ageCheck = check.get();
	const auto age = _data.minAge
		? Ui::CreateChild<Ui::PaddingWrap<Ui::Checkbox>>(
			this,
			object_ptr<Ui::Checkbox>(
				this,
				tr::lng_terms_age(tr::now, lt_count, *_data.minAge),
				st::defaultCheckbox,
				std::move(check)),
			st::termsAgePadding)
		: nullptr;
	if (age) {
		age->resizeToNaturalWidth(st::boxWideWidth);
	}

	const auto content = setInnerWidget(
		object_ptr<Ui::PaddingWrap<Ui::FlatLabel>>(
			this,
			object_ptr<Ui::FlatLabel> (
				this,
				rpl::single(_data.text),
				st::termsContent),
			st::termsPadding),
		0,
		age ? age->height() : 0);
	const auto show = uiShow();
	content->entity()->setClickHandlerFilter([=](
			const ClickHandlerPtr &handler,
			Qt::MouseButton button) {
		const auto link = handler
			? handler->copyToClipboardText()
			: QString();
		if (TextUtilities::RegExpMention().match(link).hasMatch()) {
			_lastClickedMention = link;
			show->showToast(
				tr::lng_terms_agree_to_proceed(tr::now, lt_bot, link));
			return false;
		}
		return true;
	});

	const auto errorAnimationCallback = [=] {
		const auto check = ageCheck;
		const auto error = _ageErrorAnimation.value(
			_ageErrorShown ? 1. : 0.);
		if (error == 0.) {
			check->setUntoggledOverride(std::nullopt);
		} else {
			const auto color = anim::color(
				st::defaultCheck.untoggledFg,
				st::boxTextFgError,
				error);
			check->setUntoggledOverride(color);
		}
	};
	const auto toggleAgeError = [=](bool shown) {
		if (_ageErrorShown != shown) {
			_ageErrorShown = shown;
			_ageErrorAnimation.start(
				[=] { errorAnimationCallback(); },
				_ageErrorShown ? 0. : 1.,
				_ageErrorShown ? 1. : 0.,
				st::defaultCheck.duration);
		}
	};

	const auto &agreeStyle = _attentionAgree
		? st::attentionBoxButton
		: st::defaultBoxButton;
	addButton(std::move(_agree), [=] {}, agreeStyle)->clicks(
	) | rpl::filter([=] {
		if (age && !age->entity()->checked()) {
			toggleAgeError(true);
			return false;
		}
		return true;
	}) | rpl::to_empty | rpl::start_to_stream(_agreeClicks, lifetime());

	if (_cancel) {
		addButton(std::move(_cancel), [] {})->clicks(
		) | rpl::to_empty | rpl::start_to_stream(_cancelClicks, lifetime());
	}

	if (age) {
		age->entity()->checkedChanges(
		) | rpl::on_next([=] {
			toggleAgeError(false);
		}, age->lifetime());

		heightValue(
		) | rpl::on_next([=](int height) {
			age->moveToLeft(0, height - age->height());
		}, age->lifetime());
	}

	content->resizeToWidth(st::boxWideWidth);

	using namespace rpl::mappers;
	rpl::combine(
		content->heightValue(),
		age ? age->heightValue() : rpl::single(0),
		_1 + _2
	) | rpl::on_next([=](int height) {
		setDimensions(st::boxWideWidth, height);
	}, content->lifetime());
}

void TermsBox::keyPressEvent(QKeyEvent *e) {
	if (e->key() == Qt::Key_Enter || e->key() == Qt::Key_Return) {
		if (!e->isAutoRepeat()) {
			triggerButton(0);
		}
	} else {
		BoxContent::keyPressEvent(e);
	}
}

QString TermsBox::lastClickedMention() const {
	return _lastClickedMention;
}

} // namespace Window
