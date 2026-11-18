// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_rule_vault.h"
#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <optional>
#include <vector>

class QWidget;

namespace Window {

struct EmergencyDeviceChoice final {
	Ayu::EmergencyActions::SessionId id;
	QString label;
};

struct EmergencyAccountChoice final {
	Ayu::EmergencyActions::AccountId id;
	QString label;
	bool canEndOtherSessions = false;
	std::vector<EmergencyDeviceChoice> devices;
};

struct EmergencySafeSetChoice final {
	Ayu::EmergencyActions::ProfileId id;
	QString name;
	std::vector<Ayu::EmergencyActions::AccountId> accounts;
};

struct EmergencyRulesSnapshot final {
	QByteArray transactionId;
	bool canSave = false;
	bool canResetSelected = false;
	bool canResetAll = false;
	bool canRemoveInstallation = false;
	std::vector<EmergencyAccountChoice> accounts;
	std::vector<EmergencySafeSetChoice> safeSets;
	std::vector<Ayu::EmergencyActions::NamedEmergencyRule> entries;
};

struct EmergencyRuleReplacement final {
	std::optional<Ayu::EmergencyActions::EmergencyActionId> existingId;
	QString name;
	Ayu::EmergencyActions::EmergencyRule rule;
	QString emergencyPasscode;
	QString safeSetPasscode;
};

struct EmergencyRulesSaveRequest final {
	QByteArray expectedTransactionId;
	std::vector<EmergencyRuleReplacement> entries;
	QString masterPasscode;
	bool outcomesConfirmed = false;
};

enum class EmergencyRulesResult : uchar {
	Success,
	WrongMaster,
	PasswordInUse,
	CredentialsRejected,
	Stale,
	Unavailable,
	Failed,
};

using EmergencyRulesLoadDone = Fn<void(
	EmergencyRulesResult,
	std::optional<EmergencyRulesSnapshot>)>;
using EmergencyRulesSaveDone = Fn<void(EmergencyRulesResult)>;

struct EmergencyRulesCallbacks final {
	Fn<bool()> authorized;
	Fn<void(QString, EmergencyRulesLoadDone)> load;
	Fn<void(EmergencyRulesSaveRequest, EmergencyRulesSaveDone)> save;
	Fn<void()> closed;
	Fn<void(EmergencyRulesResult)> lock;
};

[[nodiscard]] QWidget *CreateEmergencyRulesPanel(
	QWidget *parent,
	EmergencyRulesCallbacks callbacks);

} // namespace Window
