// This is the source code of AyuGram for Desktop.
#include "window/window_emergency_rules.h"

#include <QtCore/QPointer>
#include <QtGui/QHideEvent>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QVBoxLayout>

#include <algorithm>
#include <set>
#include <utility>

namespace Window {
namespace {

namespace Rules = Ayu::EmergencyActions;
using Result = EmergencyRulesResult;
using Scope = Rules::TargetScope;
using Remote = Rules::RemoteSessionTargetKind;

constexpr auto kPasscodeLength = 1024;
constexpr auto kRuleNameLength = 256;

struct DraftRule final {
	std::optional<Rules::EmergencyActionId> existingId;
	QString name;
	Rules::EmergencyRule rule;
};

struct AccountFields final {
	QCheckBox *affected = nullptr;
	QComboBox *remote = nullptr;
	QListWidget *devices = nullptr;
	bool selected = false;
};

struct RuleCredentials final {
	QLineEdit *passcode = nullptr;
	QLineEdit *confirm = nullptr;
	QLineEdit *safePasscode = nullptr;
};

QString TakeInput(QLineEdit *input) {
	auto result = input->text();
	input->setText(QString());
	return result;
}

QString ResultText(Result result) {
	switch (result) {
	case Result::WrongMaster:
		return u"Wrong master passcode."_q;
	case Result::PasswordInUse:
		return u"Choose unique emergency passcodes."_q;
	case Result::CredentialsRejected:
		return u"Check the emergency and safe set passcodes."_q;
	case Result::Stale:
		return u"Local data changed. Unlock again to review it."_q;
	case Result::Unavailable:
		return u"Emergency rules are unavailable."_q;
	case Result::Failed:
		return u"Emergency rules could not be saved."_q;
	case Result::Success:
		return QString();
	}
	return QString();
}

QString ActionText(Scope scope) {
	switch (scope) {
	case Scope::SelectedAccounts:
		return u"Reset selected accounts"_q;
	case Scope::AllAccounts:
		return u"Reset all accounts"_q;
	case Scope::CurrentInstallation:
		return u"Remove this installation"_q;
	}
	return QString();
}

QString RemoteText(Remote policy) {
	switch (policy) {
	case Remote::None:
		return u"Keep other devices signed in"_q;
	case Remote::SelectedSessions:
		return u"End selected sessions"_q;
	case Remote::AllOtherSessions:
		return u"End all other sessions"_q;
	}
	return QString();
}

QString DeviceText(const EmergencyDeviceChoice &device) {
	const auto id = QString::fromStdString(device.id.value);
	return device.label.isEmpty()
		? id
		: u"%1 (%2)"_q.arg(device.label, id);
}

QString AccountText(const EmergencyAccountChoice &account) {
	const auto id = QString::fromStdString(account.id.value);
	return account.label.isEmpty()
		? id
		: u"%1 (%2)"_q.arg(account.label, id);
}

void AddText(QVBoxLayout *layout, const QString &text) {
	const auto label = new QLabel();
	label->setTextFormat(Qt::PlainText);
	label->setText(text);
	label->setWordWrap(true);
	layout->addWidget(label);
}

[[nodiscard]] QPushButton *AddButton(QHBoxLayout *layout, QString text) {
	const auto button = new QPushButton(std::move(text));
	layout->addWidget(button);
	return button;
}

[[nodiscard]] QVBoxLayout *AddScrollArea(QVBoxLayout *layout) {
	const auto scroll = new QScrollArea();
	scroll->setWidgetResizable(true);
	const auto content = new QWidget();
	const auto result = new QVBoxLayout(content);
	result->setAlignment(Qt::AlignTop);
	scroll->setWidget(content);
	layout->addWidget(scroll);
	return result;
}

[[nodiscard]] bool Affects(
		const Rules::EmergencyRule &rule,
		const Rules::AccountId &account) {
	return rule.targetScope != Scope::SelectedAccounts
		|| std::ranges::find(rule.selectedAccountIds, account)
			!= end(rule.selectedAccountIds);
}

const Rules::RemoteSessionPolicy *PolicyFor(
		const Rules::EmergencyRule &rule,
		const Rules::AccountId &account) {
	const auto i = std::ranges::find(
		rule.remoteSessionPolicies,
		account,
		&Rules::RemoteSessionPolicy::accountId);
	return i == end(rule.remoteSessionPolicies) ? nullptr : &*i;
}

[[nodiscard]] bool SafeSetAllowed(
		const EmergencySafeSetChoice &set,
		const Rules::EmergencyRule &rule) {
	return rule.targetScope != Scope::CurrentInstallation
		&& std::ranges::none_of(set.accounts, [&](const Rules::AccountId &id) {
			return Affects(rule, id);
		});
}

[[nodiscard]] bool SupportsScope(
		const EmergencyRulesSnapshot &snapshot,
		Scope scope) {
	switch (scope) {
	case Scope::SelectedAccounts:
		return snapshot.canResetSelected && !snapshot.accounts.empty();
	case Scope::AllAccounts:
		return snapshot.canResetAll && !snapshot.accounts.empty();
	case Scope::CurrentInstallation:
		return snapshot.canRemoveInstallation;
	}
	return false;
}

[[nodiscard]] bool SupportsRule(
		const EmergencyRulesSnapshot &snapshot,
		const Rules::EmergencyRule &rule) {
	if (!SupportsScope(snapshot, rule.targetScope)
		|| (rule.targetScope == Scope::CurrentInstallation)
			!= (rule.action == Rules::EmergencyAction::RemoveInstallation)
		|| (rule.targetScope == Scope::SelectedAccounts)
			!= !rule.selectedAccountIds.empty()) {
		return false;
	}
	auto selected = std::set<Rules::AccountId>();
	for (const auto &id : rule.selectedAccountIds) {
		if (!selected.insert(id).second || std::ranges::find(
				snapshot.accounts, id, &EmergencyAccountChoice::id)
				== end(snapshot.accounts)) {
			return false;
		}
	}
	auto policies = std::set<Rules::AccountId>();
	for (const auto &policy : rule.remoteSessionPolicies) {
		const auto account = std::ranges::find(
			snapshot.accounts, policy.accountId, &EmergencyAccountChoice::id);
		if (account == end(snapshot.accounts) || !Affects(rule, account->id)
			|| !policies.insert(account->id).second
			|| (policy.kind != Remote::None
				&& policy.kind != Remote::AllOtherSessions
				&& policy.kind != Remote::SelectedSessions)
			|| (policy.kind == Remote::AllOtherSessions && !account->canEndOtherSessions)
			|| (policy.kind == Remote::SelectedSessions)
				!= !policy.selectedSessionIds.empty()) {
			return false;
		}
		auto devices = std::set<Rules::SessionId>();
		for (const auto &id : policy.selectedSessionIds) {
			if (!devices.insert(id).second || std::ranges::find(
					account->devices, id, &EmergencyDeviceChoice::id)
					== end(account->devices)) {
				return false;
			}
		}
	}
	if (rule.targetScope == Scope::CurrentInstallation) {
		return !rule.safeProfileId.valid();
	}
	const auto safe = std::ranges::find(
		snapshot.safeSets, rule.safeProfileId, &EmergencySafeSetChoice::id);
	return !rule.safeProfileId.valid()
		|| (safe != end(snapshot.safeSets) && SafeSetAllowed(*safe, rule));
}

class EmergencyRulesPanel final : public QWidget {
public:
	EmergencyRulesPanel(QWidget *parent, EmergencyRulesCallbacks callbacks);
	~EmergencyRulesPanel() override;

protected:
	void hideEvent(QHideEvent *event) override;

private:
	[[nodiscard]] bool authorized() const;
	[[nodiscard]] bool canEdit() const;
	[[nodiscard]] bool canAdd() const;
	[[nodiscard]] QVBoxLayout *newPage(QString status);
	[[nodiscard]] QLineEdit *addPassword(QFormLayout *form, QString label);
	void clearPasswords();
	void showAuthentication(QString status);
	void loaded(Result result, std::optional<EmergencyRulesSnapshot> snapshot);
	void showList();
	void edit(std::optional<size_t> index);
	void refreshAccountFields();
	[[nodiscard]] std::optional<DraftRule> readEditor();
	void showReview(std::optional<size_t> single);
	void appendReview(QVBoxLayout *layout, const DraftRule &draft);
	void submitReview(
		bool confirmed,
		QLineEdit *master,
		const std::vector<RuleCredentials> &fields);
	void saved(Result result);
	void leave();

	const EmergencyRulesCallbacks _callbacks;
	const not_null<QVBoxLayout*> _layout;
	const not_null<QLabel*> _status;
	QWidget *_page = nullptr;
	std::vector<QLineEdit*> _passwords;
	std::optional<EmergencyRulesSnapshot> _snapshot;
	std::vector<DraftRule> _drafts;
	std::vector<QString> _removed;
	std::optional<size_t> _edited;
	std::vector<AccountFields> _fields;
	QLineEdit *_name = nullptr;
	QComboBox *_scope = nullptr;
	QComboBox *_safeSet = nullptr;
	bool _changed = false;
	bool _busy = false;

};

EmergencyRulesPanel::EmergencyRulesPanel(
		QWidget *parent,
		EmergencyRulesCallbacks callbacks)
: QWidget(parent)
, _callbacks(std::move(callbacks))
, _layout(new QVBoxLayout(this))
, _status(new QLabel()) {
	_layout->setContentsMargins(0, 0, 0, 0);
	_layout->addWidget(_status.get());
	_status->setTextFormat(Qt::PlainText);
	_status->setWordWrap(true);
	showAuthentication(u"Enter the master passcode to review emergency rules."_q);
}

EmergencyRulesPanel::~EmergencyRulesPanel() {
	clearPasswords();
}

void EmergencyRulesPanel::hideEvent(QHideEvent *event) {
	clearPasswords();
	QWidget::hideEvent(event);
}

bool EmergencyRulesPanel::authorized() const {
	return _callbacks.authorized && _callbacks.authorized();
}

bool EmergencyRulesPanel::canEdit() const {
	return authorized() && !_busy && _snapshot && _snapshot->canSave
		&& _callbacks.save;
}

bool EmergencyRulesPanel::canAdd() const {
	return canEdit() && _drafts.size() < Rules::kMaxSealedEmergencyRules
		&& (SupportsScope(*_snapshot, Scope::SelectedAccounts)
			|| SupportsScope(*_snapshot, Scope::AllAccounts)
			|| SupportsScope(*_snapshot, Scope::CurrentInstallation));
}

QVBoxLayout *EmergencyRulesPanel::newPage(QString status) {
	clearPasswords();
	_passwords.clear();
	if (_page) {
		_layout->removeWidget(_page);
		_page->hide();
		_page->deleteLater();
	}
	_status->setText(std::move(status));
	_page = new QWidget(this);
	_layout->addWidget(_page);
	const auto layout = new QVBoxLayout(_page);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setAlignment(Qt::AlignTop);
	return layout;
}

QLineEdit *EmergencyRulesPanel::addPassword(QFormLayout *form, QString label) {
	const auto input = new QLineEdit();
	input->setEchoMode(QLineEdit::Password);
	input->setAccessibleName(label);
	input->setMaxLength(kPasscodeLength + 1);
	input->setInputMethodHints(
		Qt::ImhHiddenText | Qt::ImhSensitiveData | Qt::ImhNoPredictiveText);
	form->addRow(label, input);
	_passwords.push_back(input);
	return input;
}

void EmergencyRulesPanel::clearPasswords() {
	for (const auto input : _passwords) {
		auto text = TakeInput(input);
		text.fill(QChar(0));
	}
}

void EmergencyRulesPanel::showAuthentication(QString status) {
	const auto layout = newPage(std::move(status));
	const auto actions = new QHBoxLayout();
	const auto back = AddButton(actions, u"Back"_q);
	connect(back, &QPushButton::clicked, this, [this] { leave(); });
	if (!authorized() || !_callbacks.load) {
		_status->setText(ResultText(Result::Unavailable));
		layout->addLayout(actions);
		return;
	}
	const auto form = new QFormLayout();
	const auto master = addPassword(form, u"Master passcode"_q);
	layout->addLayout(form);
	const auto open = AddButton(actions, u"Open rules"_q);
	layout->addLayout(actions);
	const auto submit = [=, this] {
		if (_busy || !authorized()) {
			return;
		}
		auto passcode = TakeInput(master);
		if (passcode.isEmpty() || passcode.size() > kPasscodeLength) {
			passcode.fill(QChar(0));
			_status->setText(u"Enter the master passcode."_q);
			return;
		}
		_busy = true;
		_page->setEnabled(false);
		_status->setText(u"Opening emergency rules…"_q);
		const auto weak = QPointer<EmergencyRulesPanel>(this);
		const auto load = _callbacks.load;
		load(std::move(passcode), [weak](
				Result result,
				std::optional<EmergencyRulesSnapshot> snapshot) {
			if (weak && weak->authorized()) {
				weak->loaded(result, std::move(snapshot));
			}
		});
	};
	connect(open, &QPushButton::clicked, this, submit);
	connect(master, &QLineEdit::returnPressed, this, submit);
	master->setFocus();
}

void EmergencyRulesPanel::loaded(
		Result result,
		std::optional<EmergencyRulesSnapshot> snapshot) {
	_busy = false;
	if (result != Result::Success || !snapshot || snapshot->transactionId.isEmpty()) {
		if (result == Result::Stale) {
			const auto lock = _callbacks.lock;
			lock(result);
			return;
		}
		showAuthentication((result == Result::WrongMaster || result == Result::Unavailable)
			? ResultText(result)
			: u"Emergency rules could not be opened."_q);
		return;
	}
	_snapshot = std::move(snapshot);
	_drafts.clear();
	for (const auto &entry : _snapshot->entries) {
		_drafts.push_back({
			.existingId = entry.details.actionId,
			.name = QString::fromStdString(entry.name),
			.rule = entry.details.rule,
		});
	}
	showList();
}

void EmergencyRulesPanel::showList() {
	const auto layout = newPage(!canEdit()
		? u"Emergency rules are read-only."_q
		: _changed
		? u"Review changes before saving."_q
		: _drafts.empty()
		? (canAdd() ? u"No emergency rules yet."_q : ResultText(Result::Unavailable))
		: u"Emergency rules"_q);
	if (_snapshot && _snapshot->lastReset) {
		const auto &last = *_snapshot->lastReset;
		AddText(layout, u"Last reset cleared local data for %1 accounts."_q.arg(last.clearedAccounts));
		if (last.installationRemovalRefused) {
			AddText(layout, u"SleepyGram could not fully remove its installation."_q);
		}
		if (last.unconfirmedDeviceRevokes || last.unconfirmedLogouts) {
			AddText(layout, u"Unconfirmed on Telegram: %1 device revokes, %2 sign-outs."_q
				.arg(last.unconfirmedDeviceRevokes).arg(last.unconfirmedLogouts));
		}
	}
	const auto list = new QListWidget();
	list->setAccessibleName(u"Emergency rules"_q);
	for (const auto &draft : _drafts) {
		list->addItem(draft.name);
	}
	layout->addWidget(list);
	const auto actions = new QHBoxLayout();
	const auto back = AddButton(actions, u"Back"_q);
	const auto view = AddButton(actions, u"Review rule"_q);
	const auto add = AddButton(actions, u"Add rule"_q);
	const auto editRule = AddButton(actions, u"Edit"_q);
	const auto remove = AddButton(actions, u"Remove"_q);
	const auto review = AddButton(actions, u"Review changes"_q);
	layout->addLayout(actions);
	const auto selectionChanged = [=, this](int row) {
		const auto selected = row >= 0 && size_t(row) < _drafts.size();
		view->setEnabled(selected);
		editRule->setEnabled(selected && canEdit()
			&& SupportsRule(*_snapshot, _drafts[row].rule));
		remove->setEnabled(selected && canEdit());
	};
	connect(list, &QListWidget::currentRowChanged, this, selectionChanged);
	connect(back, &QPushButton::clicked, this, [this] { leave(); });
	connect(view, &QPushButton::clicked, this, [=, this] {
		if (authorized() && list->currentRow() >= 0) {
			showReview(size_t(list->currentRow()));
		}
	});
	connect(add, &QPushButton::clicked, this, [this] { edit({}); });
	connect(editRule, &QPushButton::clicked, this, [=, this] {
		if (list->currentRow() >= 0) {
			edit(size_t(list->currentRow()));
		}
	});
	connect(remove, &QPushButton::clicked, this, [=, this] {
		const auto row = list->currentRow();
		if (canEdit() && row >= 0 && size_t(row) < _drafts.size()) {
			const auto i = begin(_drafts) + row;
			if (i->existingId) {
				_removed.push_back(i->name);
			}
			_drafts.erase(i);
			_changed = true;
			showList();
		}
	});
	connect(review, &QPushButton::clicked, this, [this] {
		if (canEdit() && _changed) {
			showReview({});
		}
	});
	add->setEnabled(canAdd());
	review->setEnabled(canEdit() && _changed);
	list->setCurrentRow(_drafts.empty() ? -1 : 0);
	selectionChanged(list->currentRow());
}

void EmergencyRulesPanel::edit(std::optional<size_t> index) {
	if (index ? (!canEdit() || *index >= _drafts.size()
		|| !SupportsRule(*_snapshot, _drafts[*index].rule)) : !canAdd()) {
		return;
	}
	_edited = index;
	const auto original = index ? _drafts[*index] : DraftRule();
	const auto layout = newPage(index ? u"Edit emergency rule"_q : u"Add emergency rule"_q);
	const auto form = new QFormLayout();
	_name = new QLineEdit(original.name);
	_name->setMaxLength(kRuleNameLength + 1);
	form->addRow(u"Rule name"_q, _name);
	_scope = new QComboBox();
	for (const auto scope : { Scope::SelectedAccounts, Scope::AllAccounts, Scope::CurrentInstallation }) {
		if (SupportsScope(*_snapshot, scope)) {
			_scope->addItem(ActionText(scope), int(scope));
		}
	}
	if (index) {
		_scope->setCurrentIndex(_scope->findData(int(original.rule.targetScope)));
	}
	form->addRow(u"Action"_q, _scope);
	AddText(layout, _snapshot->canRemoveInstallation
		? u"This installation supports automatic removal."_q
		: u"Automatic removal is unavailable for this installation."_q);
	_safeSet = new QComboBox();
	form->addRow(u"Safe set"_q, _safeSet);
	layout->addLayout(form);
	const auto accounts = AddScrollArea(layout);
	_fields.clear();
	for (const auto &account : _snapshot->accounts) {
		const auto fields = AccountFields{
			.affected = new QCheckBox(AccountText(account).replace('&', u"&&"_q)),
			.remote = new QComboBox(),
			.devices = new QListWidget(),
			.selected = index && original.rule.targetScope == Scope::SelectedAccounts
				&& Affects(original.rule, account.id),
		};
		fields.remote->setAccessibleName(u"Remote sessions for %1"_q.arg(AccountText(account)));
		fields.remote->addItem(RemoteText(Remote::None), int(Remote::None));
		if (account.canEndOtherSessions) {
			fields.remote->addItem(RemoteText(Remote::AllOtherSessions), int(Remote::AllOtherSessions));
		}
		if (!account.devices.empty()) {
			fields.remote->addItem(RemoteText(Remote::SelectedSessions), int(Remote::SelectedSessions));
		}
		const auto policy = PolicyFor(original.rule, account.id);
		if (policy) {
			fields.remote->setCurrentIndex(fields.remote->findData(int(policy->kind)));
		}
		fields.devices->setAccessibleName(u"Devices for %1"_q.arg(AccountText(account)));
		for (const auto &device : account.devices) {
			const auto item = new QListWidgetItem(DeviceText(device), fields.devices);
			item->setCheckState(policy && std::ranges::find(policy->selectedSessionIds, device.id)
				!= end(policy->selectedSessionIds) ? Qt::Checked : Qt::Unchecked);
		}
		accounts->addWidget(fields.affected);
		accounts->addWidget(fields.remote);
		accounts->addWidget(fields.devices);
		_fields.push_back(fields);
		connect(fields.affected, &QCheckBox::clicked, _page, [
				this,
				page = _page,
				row = _fields.size() - 1](bool checked) {
			if (page == _page) {
				_fields[row].selected = checked;
				refreshAccountFields();
			}
		});
		connect(fields.remote, &QComboBox::currentIndexChanged, this, [this] { refreshAccountFields(); });
	}
	connect(_scope, &QComboBox::currentIndexChanged, this, [this] { refreshAccountFields(); });
	refreshAccountFields();
	if (original.rule.safeProfileId.valid()) {
		const auto i = std::ranges::find(
			_snapshot->safeSets, original.rule.safeProfileId, &EmergencySafeSetChoice::id);
		if (i != end(_snapshot->safeSets)) {
			_safeSet->setCurrentIndex(_safeSet->findData(int(i - begin(_snapshot->safeSets))));
		}
	}
	const auto actions = new QHBoxLayout();
	const auto cancel = AddButton(actions, u"Cancel"_q);
	const auto done = AddButton(actions, u"Done"_q);
	layout->addLayout(actions);
	connect(cancel, &QPushButton::clicked, this, [this] { showList(); });
	connect(done, &QPushButton::clicked, this, [this] {
		if (auto draft = readEditor()) {
			if (_edited) {
				_drafts[*_edited] = std::move(*draft);
			} else {
				_drafts.push_back(std::move(*draft));
			}
			_changed = true;
			showList();
		}
	});
	_name->setFocus();
}

void EmergencyRulesPanel::refreshAccountFields() {
	const auto scope = Scope(_scope->currentData().toInt());
	auto rule = Rules::EmergencyRule{ .targetScope = scope };
	for (auto i = size_t(0); i != _fields.size(); ++i) {
		const auto &field = _fields[i];
		const auto selected = scope != Scope::SelectedAccounts || field.selected;
		field.affected->setEnabled(scope == Scope::SelectedAccounts);
		field.affected->setChecked(selected);
		if (scope == Scope::SelectedAccounts && selected) {
			rule.selectedAccountIds.push_back(_snapshot->accounts[i].id);
		}
		field.remote->setVisible(selected);
		field.devices->setVisible(selected
			&& Remote(field.remote->currentData().toInt()) == Remote::SelectedSessions);
	}
	const auto previous = _safeSet->currentData().toInt();
	_safeSet->clear();
	_safeSet->addItem(u"No safe set"_q, -1);
	for (auto i = size_t(0); i != _snapshot->safeSets.size(); ++i) {
		const auto &set = _snapshot->safeSets[i];
		if (SafeSetAllowed(set, rule)) {
			_safeSet->addItem(set.name, int(i));
		}
	}
	_safeSet->setCurrentIndex(std::max(0, _safeSet->findData(previous)));
	_safeSet->setEnabled(_safeSet->count() > 1);
}

std::optional<DraftRule> EmergencyRulesPanel::readEditor() {
	if (!canEdit()) {
		return std::nullopt;
	}
	auto draft = _edited ? _drafts[*_edited] : DraftRule();
	draft.name = _name->text().trimmed();
	if (draft.name.isEmpty() || draft.name.toUtf8().size() > kRuleNameLength) {
		_status->setText(u"Enter a shorter rule name."_q);
		return std::nullopt;
	}
	auto &rule = draft.rule;
	rule.targetScope = Scope(_scope->currentData().toInt());
	rule.action = (rule.targetScope == Scope::CurrentInstallation)
		? Rules::EmergencyAction::RemoveInstallation
		: Rules::EmergencyAction::ResetAccountData;
	rule.selectedAccountIds.clear();
	rule.remoteSessionPolicies.clear();
	for (auto i = size_t(0); i != _fields.size(); ++i) {
		const auto &field = _fields[i];
		const auto &account = _snapshot->accounts[i];
		if (rule.targetScope == Scope::SelectedAccounts) {
			if (!field.affected->isChecked()) {
				continue;
			}
			rule.selectedAccountIds.push_back(account.id);
		}
		auto policy = Rules::RemoteSessionPolicy{
			.accountId = account.id,
			.kind = Remote(field.remote->currentData().toInt()),
		};
		if (policy.kind == Remote::None) {
			continue;
		} else if (policy.kind == Remote::SelectedSessions) {
			for (auto j = 0; j != field.devices->count(); ++j) {
				if (field.devices->item(j)->checkState() == Qt::Checked) {
					policy.selectedSessionIds.push_back(account.devices[j].id);
				}
			}
		}
		rule.remoteSessionPolicies.push_back(std::move(policy));
	}
	const auto safe = _safeSet->currentData().toInt();
	rule.safeProfileId = (safe >= 0)
		? _snapshot->safeSets[safe].id
		: Rules::ProfileId();
	if (!SupportsRule(*_snapshot, rule)) {
		_status->setText(u"Select the accounts and devices for this rule."_q);
		return std::nullopt;
	}
	return draft;
}

void EmergencyRulesPanel::appendReview(QVBoxLayout *layout, const DraftRule &draft) {
	const auto &rule = draft.rule;
	AddText(layout, draft.name);
	AddText(layout, ActionText(rule.targetScope));
	if (!SupportsRule(*_snapshot, rule)) {
		AddText(layout, u"Unavailable with the current accounts and devices."_q);
	}
	AddText(layout, (rule.targetScope == Scope::CurrentInstallation)
		? u"Remove the app and clear its local account data when this rule is triggered."_q
		: u"Clear local data for the accounts listed below when this rule is triggered."_q);
	for (const auto &account : _snapshot->accounts) {
		if (!Affects(rule, account.id)) {
			continue;
		}
		const auto policy = PolicyFor(rule, account.id);
		AddText(layout, u"%1 — %2"_q.arg(
			AccountText(account), RemoteText(policy ? policy->kind : Remote::None)));
		if (policy && policy->kind == Remote::SelectedSessions) {
			for (const auto &id : policy->selectedSessionIds) {
				const auto i = std::ranges::find(account.devices, id, &EmergencyDeviceChoice::id);
				AddText(layout, (i == end(account.devices))
					? QString::fromStdString(id.value)
					: DeviceText(*i));
			}
		}
	}
	for (const auto &id : rule.selectedAccountIds) {
		if (std::ranges::find(_snapshot->accounts, id, &EmergencyAccountChoice::id)
			== end(_snapshot->accounts)) {
			AddText(layout, u"Account unavailable: %1"_q.arg(QString::fromStdString(id.value)));
		}
	}
	if (rule.targetScope == Scope::CurrentInstallation) {
		return;
	}
	const auto safe = std::ranges::find(
		_snapshot->safeSets, rule.safeProfileId, &EmergencySafeSetChoice::id);
	AddText(layout, (safe != end(_snapshot->safeSets))
		? u"Safe set: %1"_q.arg(safe->name)
		: rule.safeProfileId.valid()
		? u"Safe set unavailable"_q
		: u"After the reset, this passcode opens an empty set for signing in."_q);
}

void EmergencyRulesPanel::showReview(std::optional<size_t> single) {
	const auto supported = !single && canEdit() && std::ranges::all_of(
		_drafts, [&](const DraftRule &draft) { return SupportsRule(*_snapshot, draft.rule); });
	const auto layout = newPage(single
		? u"Rule review"_q
		: supported
		? u"Review the consequences before saving."_q
		: u"Some rules cannot be saved with the available accounts and devices."_q);
	const auto review = AddScrollArea(layout);
	if (!_drafts.empty()) {
		AddText(review, u"Set up emergency rules again after a reset."_q);
	}
	auto credentials = std::vector<RuleCredentials>();
	for (auto i = size_t(0); i != _drafts.size(); ++i) {
		if (single && *single != i) {
			continue;
		}
		const auto &draft = _drafts[i];
		appendReview(review, draft);
		if (supported) {
			const auto form = new QFormLayout();
			credentials.push_back({
				.passcode = addPassword(form, u"Emergency passcode"_q),
				.confirm = addPassword(form, u"Confirm emergency passcode"_q),
				.safePasscode = draft.rule.safeProfileId.valid()
					? addPassword(form, u"Safe set passcode"_q)
					: nullptr,
			});
			review->addLayout(form);
		}
	}
	if (!single) {
		for (const auto &name : _removed) {
			AddText(review, u"Remove rule: %1"_q.arg(name));
		}
	}
	const auto actions = new QHBoxLayout();
	const auto back = AddButton(actions, u"Back"_q);
	connect(back, &QPushButton::clicked, this, [this] { showList(); });
	if (supported) {
		const auto form = new QFormLayout();
		const auto master = addPassword(form, u"Re-enter master passcode"_q);
		layout->addLayout(form);
		const auto confirmed = new QCheckBox(u"I reviewed these outcomes."_q);
		layout->addWidget(confirmed);
		const auto save = AddButton(actions, u"Save rules"_q);
		save->setEnabled(false);
		connect(confirmed, &QCheckBox::toggled, save, &QPushButton::setEnabled);
		connect(save, &QPushButton::clicked, this, [=, this] {
			submitReview(confirmed->isChecked(), master, credentials);
		});
	}
	layout->addLayout(actions);
}

void EmergencyRulesPanel::submitReview(
		bool confirmed,
		QLineEdit *master,
		const std::vector<RuleCredentials> &fields) {
	if (!confirmed || !canEdit() || fields.size() != _drafts.size()) {
		return;
	}
	auto request = EmergencyRulesSaveRequest{
		.expectedTransactionId = _snapshot->transactionId,
		.masterPasscode = TakeInput(master),
		.outcomesConfirmed = confirmed,
	};
	const auto clear = gsl::finally([weak = QPointer<EmergencyRulesPanel>(this)] {
		if (weak) {
			weak->clearPasswords();
		}
	});
	const auto wipe = gsl::finally([&] {
		request.masterPasscode.fill(QChar(0));
		for (auto &entry : request.entries) {
			entry.emergencyPasscode.fill(QChar(0));
			entry.safeSetPasscode.fill(QChar(0));
		}
	});
	if (request.masterPasscode.isEmpty() || request.masterPasscode.size() > kPasscodeLength) {
		_status->setText(u"Enter the master passcode."_q);
		return;
	}
	request.entries.reserve(_drafts.size());
	for (auto i = size_t(0); i != _drafts.size(); ++i) {
		const auto &draft = _drafts[i];
		const auto &input = fields[i];
		auto &entry = request.entries.emplace_back(EmergencyRuleReplacement{
			.existingId = draft.existingId,
			.name = draft.name,
			.rule = draft.rule,
			.emergencyPasscode = TakeInput(input.passcode),
			.safeSetPasscode = input.safePasscode ? TakeInput(input.safePasscode) : QString(),
		});
		auto confirmation = TakeInput(input.confirm);
		const auto matches = confirmation == entry.emergencyPasscode;
		confirmation.fill(QChar(0));
		if (!matches || entry.emergencyPasscode.isEmpty()
			|| entry.emergencyPasscode.size() > kPasscodeLength) {
			_status->setText(u"Enter and confirm each emergency passcode."_q);
			return;
		} else if (input.safePasscode && (entry.safeSetPasscode.isEmpty()
			|| entry.safeSetPasscode.size() > kPasscodeLength)) {
			_status->setText(u"Enter the passcode for each selected safe set."_q);
			return;
		}
	}
	_busy = true;
	_page->setEnabled(false);
	_status->setText(u"Saving emergency rules…"_q);
	const auto weak = QPointer<EmergencyRulesPanel>(this);
	const auto save = _callbacks.save;
	save(std::move(request), [weak](Result result) {
		if (weak && weak->authorized()) {
			weak->saved(result);
		}
	});
}

void EmergencyRulesPanel::saved(Result result) {
	_busy = false;
	if (result == Result::Success || result == Result::Stale) {
		const auto lock = _callbacks.lock;
		lock(result);
		return;
	}
	_page->setEnabled(true);
	_status->setText(ResultText(result));
}

void EmergencyRulesPanel::leave() {
	if (!_busy && _callbacks.closed) {
		const auto closed = _callbacks.closed;
		closed();
	}
}

} // namespace

QWidget *CreateEmergencyRulesPanel(
		QWidget *parent,
		EmergencyRulesCallbacks callbacks) {
	Expects(callbacks.lock != nullptr);
	return new EmergencyRulesPanel(parent, std::move(callbacks));
}

} // namespace Window
