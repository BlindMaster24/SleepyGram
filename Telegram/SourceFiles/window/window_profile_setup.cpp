// This is the source code of AyuGram for Desktop.
#include "window/window_profile_setup.h"

#include "core/application.h"
#include "core/crash_report_window.h"

#include <QtCore/QPointer>
#include <QtGui/QCloseEvent>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QVBoxLayout>

#include <utility>

// AyuGram includes
#include "ayu/features/profile_sets/profile_migration.h"
#include "ayu/features/profile_sets/profile_setup.h"


namespace Window {
namespace {

namespace ProfileSets = Ayu::ProfileSets;
using Result = ProfileSets::ProfileSetupResult;

constexpr auto kPasscodeLength = 1024;
constexpr auto kSetNameLength = 256;

QString TakeInput(QLineEdit &input) {
	auto result = input.text();
	input.setText(QString());
	return result;
}

void ClearInput(QLineEdit &input) {
	auto discarded = TakeInput(input);
	discarded.fill(QChar(0));
}

QString SetupErrorText(Result result) {
	switch (result) {
	case Result::InvalidInput:
		return u"Check the set name and passcodes and try again."_q;
	case Result::LegacyPasscodeRejected:
		return u"Check the previous local passcode and try again."_q;
	case Result::UnsupportedLegacyData:
		return u"This profile contains local data that setup cannot move."_q;
	case Result::SetupPasscodeRejected:
		return u"Enter the same set name and passcodes you used when setup started."_q;
	case Result::StorageFailed:
	case Result::VerificationFailed:
		return u"Setup could not verify your local data."_q;
	case Result::Complete:
	case Result::RetirementPending:
		break;
	}
	return QString();
}

class ProfileSetupWindow final : public PreLaunchWindow {
public:
	ProfileSetupWindow(
		QString dataDirectory,
		QString dataName,
		bool canContinueLegacy,
		Fn<void()> continueLegacy,
		Fn<void()> restartProtected);
	~ProfileSetupWindow() override;

	[[nodiscard]] bool inProgress() const;

protected:
	void closeEvent(QCloseEvent *event) override;

private:
	enum class State {
		Form,
		Working,
		RestartOnly,
		Leaving,
	};

	void submit();
	void completed(Result result);
	void requireRestart(QString status);
	void restart();
	void clearSecrets();
	[[nodiscard]] bool legacyStartupAllowed() const;

	const QString _dataDirectory;
	const QString _dataName;
	const bool _canContinueLegacy;
	const Fn<void()> _continueLegacy;
	const Fn<void()> _restartProtected;
	const not_null<PreLaunchLabel*> _status;
	const not_null<QWidget*> _form;
	const not_null<PreLaunchInput*> _legacyPasscode;
	const not_null<PreLaunchInput*> _setName;
	const not_null<PreLaunchInput*> _masterPasscode;
	const not_null<PreLaunchInput*> _confirmMaster;
	const not_null<PreLaunchInput*> _setPasscode;
	const not_null<PreLaunchInput*> _confirmSet;
	const not_null<QCheckBox*> _preserveLegacyWebview;
	const not_null<PreLaunchButton*> _close;
	const not_null<PreLaunchButton*> _start;
	const not_null<PreLaunchButton*> _restart;
	State _state = State::Form;

};

ProfileSetupWindow::ProfileSetupWindow(
		QString dataDirectory,
		QString dataName,
		bool canContinueLegacy,
		Fn<void()> continueLegacy,
		Fn<void()> restartProtected)
: PreLaunchWindow(u"Set up Double Bottom"_q)
, _dataDirectory(std::move(dataDirectory))
, _dataName(std::move(dataName))
, _canContinueLegacy(canContinueLegacy)
, _continueLegacy(std::move(continueLegacy))
, _restartProtected(std::move(restartProtected))
, _status(new PreLaunchLabel(this))
, _form(new QWidget(this))
, _legacyPasscode(new PreLaunchInput(this, true))
, _setName(new PreLaunchInput(this))
, _masterPasscode(new PreLaunchInput(this, true))
, _confirmMaster(new PreLaunchInput(this, true))
, _setPasscode(new PreLaunchInput(this, true))
, _confirmSet(new PreLaunchInput(this, true))
, _preserveLegacyWebview(new QCheckBox(_form.get()))
, _close(new PreLaunchButton(this, false))
, _start(new PreLaunchButton(this))
, _restart(new PreLaunchButton(this)) {
	Expects(_restartProtected != nullptr);
	Expects(!_canContinueLegacy || _continueLegacy != nullptr);

	_status->setTextFormat(Qt::PlainText);
	_status->setWordWrap(true);
	_status->setText(
		u"The master passcode manages sets. Your first set will contain all existing accounts."_q);

	const auto form = new QFormLayout(_form.get());
	form->setContentsMargins(0, 0, 0, 0);
	form->setRowWrapPolicy(QFormLayout::WrapLongRows);
	const auto addField = [=](QString name, not_null<PreLaunchInput*> input) {
		input->setAccessibleName(name);
		form->addRow(name, input.get());
	};
	addField(u"Previous local passcode (leave blank if none)"_q, _legacyPasscode);
	addField(u"First set name"_q, _setName);
	addField(u"Master passcode"_q, _masterPasscode);
	addField(u"Confirm master passcode"_q, _confirmMaster);
	addField(u"First set passcode"_q, _setPasscode);
	addField(u"Confirm first set passcode"_q, _confirmSet);
	const auto webviewNotice = new PreLaunchLabel(_form.get());
	webviewNotice->setTextFormat(Qt::PlainText);
	webviewNotice->setWordWrap(true);
	webviewNotice->setText(u"Existing Mini App browser data stays on this device. "
		"You will need to sign in again in the protected profile."_q);
	_preserveLegacyWebview->setText(u"Start with separate Mini App storage"_q);
	form->addRow(webviewNotice);
	form->addRow(_preserveLegacyWebview.get());
	_setName->setMaxLength(kSetNameLength + 1);
	for (const auto input : {
		_legacyPasscode.get(),
		_masterPasscode.get(),
		_confirmMaster.get(),
		_setPasscode.get(),
		_confirmSet.get(),
	}) {
		input->setInputMethodHints(
			Qt::ImhHiddenText | Qt::ImhSensitiveData | Qt::ImhNoPredictiveText);
		input->setMaxLength(kPasscodeLength + 1);
	}

	_close->setText(_canContinueLegacy ? u"Continue without setup"_q : u"Close"_q);
	_start->setText(u"Enable Double Bottom"_q);
	_restart->setText(u"Restart"_q);
	_restart->hide();

	const auto layout = new QVBoxLayout(this);
	layout->addWidget(_status.get());
	layout->addWidget(_form.get());
	const auto actions = new QHBoxLayout();
	actions->addStretch();
	actions->addWidget(_close.get());
	actions->addWidget(_start.get());
	actions->addWidget(_restart.get());
	layout->addLayout(actions);

	connect(_close.get(), &QPushButton::clicked, this, [this] { close(); });
	connect(_start.get(), &QPushButton::clicked, this, [this] { submit(); });
	connect(_confirmSet.get(), &QLineEdit::returnPressed, this, [this] { submit(); });
	connect(_restart.get(), &QPushButton::clicked, this, [this] { restart(); });
	_legacyPasscode->setFocus();
}

ProfileSetupWindow::~ProfileSetupWindow() {
	clearSecrets();
}

bool ProfileSetupWindow::inProgress() const {
	return _state == State::Working;
}

void ProfileSetupWindow::submit() {
	if (_state != State::Form || Core::Quitting()) {
		return;
	}
	auto request = ProfileSets::ProfileSetupRequest{
		.dataDirectory = _dataDirectory,
		.dataName = _dataName,
		.legacyPasscode = TakeInput(*_legacyPasscode),
		.masterPasscode = TakeInput(*_masterPasscode),
		.firstSetName = _setName->text().trimmed(),
		.firstSetPasscode = TakeInput(*_setPasscode),
		.preserveLegacyWebviewStorage = _preserveLegacyWebview->isChecked(),
	};
	const auto wipe = gsl::finally([&] {
		request.legacyPasscode.fill(QChar(0));
		request.masterPasscode.fill(QChar(0));
		request.firstSetPasscode.fill(QChar(0));
	});
	auto confirmMaster = TakeInput(*_confirmMaster);
	auto confirmSet = TakeInput(*_confirmSet);
	const auto matches = (confirmMaster == request.masterPasscode)
		&& (confirmSet == request.firstSetPasscode);
	confirmMaster.fill(QChar(0));
	confirmSet.fill(QChar(0));

	if (request.firstSetName.isEmpty() || request.firstSetName.size() > kSetNameLength) {
		_status->setText(u"Enter a name for the first set."_q);
		_setName->setFocus();
		return;
	} else if (request.legacyPasscode.size() > kPasscodeLength
		|| request.masterPasscode.size() > kPasscodeLength
		|| request.firstSetPasscode.size() > kPasscodeLength) {
		_status->setText(u"Use passcodes of at most 1024 characters."_q);
		return;
	} else if (request.masterPasscode.isEmpty() || request.firstSetPasscode.isEmpty()
		|| request.masterPasscode == request.firstSetPasscode) {
		_status->setText(u"Choose two different passcodes for the master and first set."_q);
		return;
	} else if (!matches) {
		_status->setText(u"Both passcode confirmations must match."_q);
		return;
	}

	_state = State::Working;
	_form->setEnabled(false);
	_close->setEnabled(false);
	_start->setEnabled(false);
	_status->setText(u"Moving and verifying your local data…"_q);
	const auto weak = QPointer<ProfileSetupWindow>(this);
	ProfileSets::SetupProfileFromLegacy(std::move(request), [weak](Result result) {
		if (weak) {
			weak->completed(result);
		}
	});
}

void ProfileSetupWindow::completed(Result result) {
	if (_state != State::Working || Core::Quitting()) {
		return;
	}
	if (result == Result::Complete) {
		_state = State::RestartOnly;
		restart();
	} else if (result == Result::RetirementPending) {
		requireRestart(u"Setup was saved. Restart to finish moving your local data."_q);
	} else {
		const auto retryingCredential = !_canContinueLegacy
			&& (result == Result::InvalidInput
				|| result == Result::LegacyPasscodeRejected
				|| result == Result::SetupPasscodeRejected);
		if (!retryingCredential && !legacyStartupAllowed()) {
			requireRestart(u"Setup was interrupted. Restart to check your local data."_q);
			return;
		}
		_state = State::Form;
		_status->setText(SetupErrorText(result));
		_form->setEnabled(true);
		_close->setEnabled(true);
		_start->setEnabled(true);
		_legacyPasscode->setFocus();
	}
}

void ProfileSetupWindow::requireRestart(QString status) {
	_state = State::RestartOnly;
	clearSecrets();
	_status->setText(status);
	_form->hide();
	_close->hide();
	_start->hide();
	_restart->show();
	_restart->setFocus();
}

void ProfileSetupWindow::restart() {
	if (_state != State::RestartOnly || Core::Quitting()) {
		return;
	}
	_state = State::Leaving;
	clearSecrets();
	_status->setText(u"Restarting…"_q);
	_restart->setEnabled(false);
	const auto callback = _restartProtected;
	callback();
}

void ProfileSetupWindow::clearSecrets() {
	ClearInput(*_legacyPasscode);
	ClearInput(*_masterPasscode);
	ClearInput(*_confirmMaster);
	ClearInput(*_setPasscode);
	ClearInput(*_confirmSet);
}

bool ProfileSetupWindow::legacyStartupAllowed() const {
	const auto mode = ProfileSets::MigrationController::ProbeProfileStartup(
		_dataDirectory);
	return mode == ProfileSets::ProfileStartupMode::Legacy
		|| mode == ProfileSets::ProfileStartupMode::Preparing;
}

void ProfileSetupWindow::closeEvent(QCloseEvent *event) {
	if (_state != State::Form) {
		event->ignore();
		return;
	}
	if (_canContinueLegacy && !legacyStartupAllowed()) {
		event->ignore();
		requireRestart(u"Restart to check your local data."_q);
		return;
	}
	_state = State::Leaving;
	clearSecrets();
	if (_canContinueLegacy) {
		event->ignore();
		hide();
		const auto callback = _continueLegacy;
		callback();
	} else {
		PreLaunchWindow::closeEvent(event);
		Core::Quit();
	}
}

} // namespace

std::unique_ptr<PreLaunchWindow> CreateProfileSetupWindow(
		QString dataDirectory,
		QString dataName,
		bool canContinueLegacy,
		Fn<void()> continueLegacy,
		Fn<void()> restartProtected) {
	return std::make_unique<ProfileSetupWindow>(
		std::move(dataDirectory),
		std::move(dataName),
		canContinueLegacy,
		std::move(continueLegacy),
		std::move(restartProtected));
}

bool ProfileSetupInProgress(const PreLaunchWindow *window) {
	const auto setup = dynamic_cast<const ProfileSetupWindow*>(window);
	return setup && setup->inProgress();
}

} // namespace Window
