// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/ui/settings/settings_other.h"

#include "lang_auto.h"
#include "ayu/ayu_settings.h"
#include "ayu/ui/settings/ayu_builder.h"
#include "ayu/ui/settings/settings_ayu_utils.h"
#include "ayu/ui/settings/settings_main.h"
#include "boxes/abstract_box.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "settings/settings_builder.h"
#include "settings/settings_common.h"
#include "styles/style_menu_icons.h"
#include "styles/style_settings.h"
#include "ui/boxes/confirm_box.h"
#include "ui/wrap/vertical_layout.h"
#include "window/window_session_controller.h"

#include <QFile>
#include <QSaveFile>

namespace Settings {

using namespace Builder;
using namespace AyuBuilder;

namespace {

void BuildCrashReporting(SectionBuilder &builder, AyuSectionBuilder &ayu) {
#ifndef TDESKTOP_DISABLE_AUTOUPDATE
	builder.addSkip();
	builder.addSubsectionTitle(tr::ayu_CategoryOther());

	ayu.addSettingToggle({
		.id = u"ayu/crashReporting"_q,
		.altIds = { u"ayu/crashlytics"_q },
		.title = tr::ayu_CrashReporting(),
		.getter = &AyuSettings::crashReporting,
		.setter = &AyuSettings::setCrashReporting,
		.icon = { &st::menuIconReport },
	});
	builder.addSkip();
	builder.addDividerText(tr::ayu_CrashReportingDescription());
#endif
}

void BuildOtherThings(SectionBuilder &builder) {
	const auto controller = builder.controller();

	builder.addSkip();
	builder.addButton({
		.id = u"ayu/exportSettings"_q,
		.title = tr::ayu_SettingsExport(),
		.onClick = [=] {
			FileDialog::GetWritePath(
				controller->widget(),
				tr::ayu_SettingsExport(tr::now),
				u"JSON files (*.json)"_q,
				u"sleepygram-settings.json"_q,
				crl::guard(controller, [=](QString &&path) {
					if (path.isEmpty()) {
						return;
					}
					auto file = QSaveFile(path);
					const auto data = AyuSettings::exportTransfer(
						controller->session().userId().bare);
					if (!file.open(QIODevice::WriteOnly)
						|| file.write(data) != data.size()
						|| !file.commit()) {
						controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
						return;
					}
					controller->showToast(tr::lng_box_done(tr::now));
				}));
		},
	});
	builder.addButton({
		.id = u"ayu/importSettings"_q,
		.title = tr::ayu_SettingsImport(),
		.onClick = [=] {
			FileDialog::GetOpenPath(
				controller->widget(),
				tr::ayu_SettingsImport(tr::now),
				u"JSON files (*.json);;All files (*)"_q,
				crl::guard(controller, [=](FileDialog::OpenResult &&result) {
					if (result.paths.isEmpty()) {
						return;
					}
					QFile file(result.paths.front());
					if (!file.open(QIODevice::ReadOnly)
						|| file.size() > 5 * 1024 * 1024) {
						controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
						return;
					}
					const auto data = file.read(5 * 1024 * 1024 + 1);
					if (file.error() != QFileDevice::NoError
						|| data.size() > 5 * 1024 * 1024) {
						controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
						return;
					}
					auto error = QString();
					const auto preview = AyuSettings::previewTransfer(
						data,
						controller->session().userId().bare,
						&error);
					if (preview.isEmpty()) {
						controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
						return;
					}
					controller->show(Ui::MakeConfirmBox({
						.text = tr::ayu_SettingsImportConfirmation(tr::now)
							+ u"\n\n"_q
							+ preview,
						.confirmed = [=](Fn<void()> &&close) {
							if (AyuSettings::applyTransfer(
									data,
									controller->session().userId().bare)) {
								controller->showToast(tr::ayu_SettingsImportSuccess(tr::now));
							} else {
								controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
							}
							close();
						},
						.confirmText = tr::ayu_SettingsImport(),
					}));
				}));
		},
	});
	builder.addSkip();
	builder.addButton({
		.id = u"ayu/registerUrlScheme"_q,
		.title = tr::ayu_RegisterURLScheme(),
		.icon = { &st::menuIconLink },
		.onClick = [=] {
			Core::Application::RegisterUrlScheme();
			controller->showToast(tr::lng_box_done(tr::now));
		},
	});
	builder.addButton({
		.id = u"ayu/resetSettings"_q,
		.title = tr::ayu_ResetSettings(),
		.icon = { &st::menuIconRestore },
		.onClick = [=] {
			controller->show(Ui::MakeConfirmBox({
				.text = tr::ayu_ResetSettingsConfirmation(tr::rich),
				.confirmed = [=](Fn<void()> &&close) {
					AyuSettings::reset();
					controller->showToast(tr::lng_box_done(tr::now));
					close();
				},
				.confirmText = tr::lng_box_yes(),
			}));
		},
	});
	builder.addSkip();
}

const auto kMeta = BuildHelper({
	.id = AyuOther::Id(),
	.parentId = AyuMain::Id(),
	.title = &tr::ayu_CategoryOther,
	.icon = &st::menuIconFave,
}, [](SectionBuilder &builder) {
	auto ayu = AyuSectionBuilder(builder);

	builder.addSkip();
	BuildCrashReporting(builder, ayu);
	BuildOtherThings(builder);
});

} // namespace

rpl::producer<QString> AyuOther::title() {
	return tr::ayu_CategoryOther();
}

AyuOther::AyuOther(
	QWidget *parent,
	not_null<Window::SessionController*> controller)
: Section(parent, controller) {
	setupContent();
}

void AyuOther::setupContent() {
	const auto content = Ui::CreateChild<Ui::VerticalLayout>(this);
	build(content, kMeta.build);
	Ui::ResizeFitChild(this, content);
}

Type AyuOtherId() {
	return AyuOther::Id();
}

} // namespace Settings
