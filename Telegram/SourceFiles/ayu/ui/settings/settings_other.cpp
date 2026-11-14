// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/ui/settings/settings_other.h"

#include "lang_auto.h"
#include "ayu/ayu_settings.h"
#include "ayu/data/messages_storage.h"
#include "ayu/data/archive_backup.h"
#include "ayu/features/chat_lock/chat_lock.h"
#include "ayu/ui/message_history/history_section.h"
#include "ayu/ui/settings/ayu_builder.h"
#include "ayu/ui/settings/settings_ayu_utils.h"
#include "ayu/ui/settings/settings_main.h"
#include "boxes/abstract_box.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "data/data_peer_id.h"
#include "data/data_session.h"
#include "main/main_session.h"
#include "settings/settings_builder.h"
#include "settings/settings_common.h"
#include "styles/style_menu_icons.h"
#include "styles/style_settings.h"
#include "ui/boxes/confirm_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/wrap/vertical_layout.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include "styles/style_boxes.h"
#include "styles/style_widgets.h"

#include <QFile>
#include <QInputDialog>
#include <QLineEdit>
#include <QSaveFile>
#include <QtCore/QDate>
#include <QtCore/QDateTime>

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

bool IsArchivedMessageLocked(
		not_null<Main::Session*> session,
		const AyuMessageBase &message) {
	const auto id = message.peerId;
	if (id <= 0) return false;
	const auto locked = [&](PeerId peer) {
		return Ayu::ChatLock::IsChatLocked(session, peer);
	};
	switch (message.peerType) {
	case 1: return locked(PeerId(UserId(id)));
	case 2: return locked(PeerId(ChatId(id)));
	case 3: return locked(PeerId(ChannelId(id)));
	default:
		return locked(PeerId(UserId(id)))
			|| locked(PeerId(ChatId(id)))
			|| locked(PeerId(ChannelId(id)));
	}
}

PeerData *FindArchivedPeer(
		Main::Session &session,
		const AyuMessageBase &message) {
	auto &data = session.data();
	const auto id = message.peerId;
	switch (message.peerType) {
	case 1:
		return data.peerLoaded(PeerId(UserId(id)));
	case 2:
		return data.peerLoaded(PeerId(ChatId(id)));
	case 3:
		return data.peerLoaded(PeerId(ChannelId(id)));
	default:
		if (message.dialogId > 0) {
			return data.peerLoaded(PeerId(UserId(id)));
		} else {
			const auto channel = data.peerLoaded(PeerId(ChannelId(id)));
			const auto chat = data.peerLoaded(PeerId(ChatId(id)));
			return (channel && !chat) ? channel : (chat && !channel) ? chat : nullptr;
		}
	}
}

void OpenArchivedMessage(
		not_null<Window::SessionController*> controller,
		AyuDatabase::ArchiveSearchResult result,
		const QString &searchQuery) {
	const auto &session = controller->session();
	if (IsArchivedMessageLocked(&controller->session(), result.message)) {
		return;
	}
	const auto peer = FindArchivedPeer(session, result.message);
	const auto window = session.tryResolveWindow();
	if (peer && window) {
		if (result.type == AyuDatabase::ArchiveSearchType::Edited) {
			window->showSection(std::make_shared<MessageHistory::SectionMemento>(
				peer,
				nullptr,
				result.message.topicId,
				false,
				result.message.messageId));
		} else {
			auto memento = std::make_shared<MessageHistory::SectionMemento>(
				peer,
				nullptr,
				result.message.topicId);
			memento->setSearchQuery(searchQuery);
			window->showSection(std::move(memento));
		}
		return;
	}
	controller->show(Ui::MakeInformBox(
		tr::ayu_ArchiveTextFallback(tr::now)
		+ u"\n\n"_q
		+ QString::fromStdString(result.message.text)));
}

void LoadArchiveSearchPage(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		not_null<Ui::VerticalLayout*> resultsLayout,
		QString query,
		AyuDatabase::ArchiveSearchType type,
		int dateFrom,
		int dateTo,
		std::optional<AyuDatabase::ArchiveSearchCursor> cursor,
		const std::shared_ptr<bool> &stale,
		Ui::LinkButton *loadMore = nullptr) {
	if (loadMore) {
		loadMore->setDisabled(true);
	}
	const auto weak = base::make_weak(box);
	const auto sessionId = controller->session().userId().bare
		& PeerId::kChatTypeMask;
	crl::async([=] {
		const auto page = AyuMessages::searchArchive(
			sessionId,
			query.toStdString(),
			type,
			dateFrom,
			dateTo,
			cursor,
			25);
		crl::on_main([=, page = std::move(page)]() mutable {
			if (!weak || *stale) {
				return;
			}
			if (page.empty() && !cursor) {
				resultsLayout->add(object_ptr<Ui::FlatLabel>(
					resultsLayout,
					tr::ayu_ArchiveSearchEmpty(tr::now),
					st::boxLabel),
					st::boxPadding);
				return;
			}
			for (const auto &entry : page) {
				if (IsArchivedMessageLocked(
						&controller->session(),
						entry.message)) {
					continue;
				}
				auto preview = QString::fromStdString(entry.message.text)
					.simplified();
				constexpr auto kPreviewLength = 120;
				if (preview.size() > kPreviewLength) {
					preview = preview.left(kPreviewLength) + u"…"_q;
				}
				const auto date = QDateTime::fromSecsSinceEpoch(
					entry.date).toLocalTime().date().toString(Qt::ISODate);
				const auto kind = (entry.type
					== AyuDatabase::ArchiveSearchType::Edited)
					? tr::ayu_ArchiveSearchEdited(tr::now)
					: tr::ayu_ArchiveSearchDeleted(tr::now);
				const auto label = kind + u"  ·  "_q + date + u"\n"_q + preview;
				const auto link = resultsLayout->add(
					object_ptr<Ui::LinkButton>(
						resultsLayout,
						label,
						st::boxLinkButton),
					st::boxRowPadding);
				link->setClickedCallback([=] {
					OpenArchivedMessage(controller, entry, query);
				});
			}
			if (page.size() == 25) {
				const auto &last = page.back();
				const auto nextCursor = AyuDatabase::ArchiveSearchCursor{
					.date = last.date,
					.type = last.type,
					.rowId = last.rowId,
				};
				const auto more = resultsLayout->add(
					object_ptr<Ui::LinkButton>(
						resultsLayout,
						tr::ayu_ArchiveSearchMore(tr::now),
						st::boxLinkButton),
					st::boxRowPadding);
				more->setClickedCallback([=] {
					LoadArchiveSearchPage(
						box,
						controller,
						resultsLayout,
						query,
						type,
						dateFrom,
						dateTo,
						nextCursor,
						stale,
						more);
				});
			}
		});
	});
}

void ArchiveSearchResultsBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		QString query,
		AyuDatabase::ArchiveSearchType type,
		int dateFrom,
		int dateTo) {
	box->setTitle(tr::ayu_ArchiveSearchTitle());
	box->setWidth(st::boxWideWidth);
	const auto accountId = controller->session().userId().bare
		& PeerId::kChatTypeMask;
	const auto stale = std::make_shared<bool>(false);
	Ayu::ChatLock::Changes() | rpl::on_next([=](Ayu::ChatLock::Change change) {
		if (change.accountId == uint64(accountId)) {
			*stale = true;
			box->closeBox();
		}
	}, box->lifetime());
	const auto resultsLayout = box->verticalLayout()->add(
		object_ptr<Ui::VerticalLayout>(box),
		st::boxPadding);
	LoadArchiveSearchPage(
		box,
		controller,
		resultsLayout,
		std::move(query),
		type,
		dateFrom,
		dateTo,
		std::nullopt,
		stale);
	box->addButton(tr::lng_box_done(), [=] { box->closeBox(); });
}

void ShowArchiveSearchBox(not_null<Window::SessionController*> controller) {
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(tr::ayu_ArchiveSearchTitle());
		box->setWidth(st::boxWideWidth);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			tr::ayu_ArchiveSearchDescription(tr::now),
			st::boxLabel), st::boxPadding);
		const auto query = box->addRow(object_ptr<Ui::InputField>(
			box,
			st::defaultInputField,
			Ui::InputField::Mode::SingleLine,
			tr::ayu_ArchiveSearchQuery()),
			st::boxPadding);
		const auto fromDate = box->addRow(object_ptr<Ui::InputField>(
			box,
			st::defaultInputField,
			Ui::InputField::Mode::SingleLine,
			tr::ayu_ArchiveSearchFromDate()),
			st::boxPadding);
		const auto toDate = box->addRow(object_ptr<Ui::InputField>(
			box,
			st::defaultInputField,
			Ui::InputField::Mode::SingleLine,
			tr::ayu_ArchiveSearchToDate()),
			st::boxPadding);
		const auto edited = box->addRow(object_ptr<Ui::Checkbox>(
			box,
			tr::ayu_ArchiveSearchEdited(tr::now),
			true,
			st::defaultBoxCheckbox), st::boxPadding);
		const auto deleted = box->addRow(object_ptr<Ui::Checkbox>(
			box,
			tr::ayu_ArchiveSearchDeleted(tr::now),
			true,
			st::defaultBoxCheckbox), st::boxPadding);
		box->addButton(tr::ayu_ArchiveSearchStart(), [=] {
			if (!edited->checked() && !deleted->checked()) {
				controller->show(Ui::MakeInformBox(
					tr::ayu_ArchiveSearchInvalidType(tr::now)));
				return;
			}
			const auto parseDate = [](QString value, bool endOfDay)
			-> std::optional<int> {
				value = value.trimmed();
				if (value.isEmpty()) {
					return 0;
				}
				const auto date = QDate::fromString(value, Qt::ISODate);
				if (!date.isValid()) {
					return std::nullopt;
				}
				const auto time = endOfDay
					? QTime(23, 59, 59)
					: QTime(0, 0, 0);
				return int(QDateTime(date, time, Qt::LocalTime).toSecsSinceEpoch());
			};
			const auto from = parseDate(fromDate->getLastText(), false);
			const auto till = parseDate(toDate->getLastText(), true);
			if (!from || !till || (*from && *till && *from > *till)) {
				controller->show(Ui::MakeInformBox(
					tr::ayu_ArchiveSearchInvalidDate(tr::now)));
				return;
			}
			const auto type = (edited->checked() && deleted->checked())
				? AyuDatabase::ArchiveSearchType::All
				: edited->checked()
				? AyuDatabase::ArchiveSearchType::Edited
				: AyuDatabase::ArchiveSearchType::Deleted;
			const auto search = query->getLastText().trimmed();
			box->closeBox();
			controller->show(Box(
				ArchiveSearchResultsBox,
				controller,
				search,
				type,
				*from,
				*till));
		});
	}));
}

void ExportArchiveBackup(
		not_null<Window::SessionController*> controller,
		Fn<void()> completed = nullptr) {
	const auto accountId = controller->session().userId().bare
		& PeerId::kChatTypeMask;
	const auto counts = AyuDatabase::archiveBackupCounts(accountId);
	controller->show(Ui::MakeConfirmBox({
		.text = tr::ayu_ArchiveBackupExportCounts(
			tr::now,
			lt_edited_count,
			counts.edited,
			lt_deleted_count,
			counts.deleted),
		.confirmed = [=](Fn<void()> &&close) {
			close();
			const auto password = QInputDialog::getText(
				controller->widget(),
				tr::ayu_ArchiveBackupPasswordTitle(tr::now),
				tr::ayu_ArchiveBackupPasswordPrompt(tr::now),
				QLineEdit::Password);
			if (password.isEmpty()) return;
			const auto confirm = QInputDialog::getText(
				controller->widget(),
				tr::ayu_ArchiveBackupPasswordTitle(tr::now),
				tr::ayu_ArchiveBackupPasswordConfirm(tr::now),
				QLineEdit::Password);
			if (password != confirm || password.toUtf8().size() < 8) {
				controller->showToast(tr::ayu_ArchiveBackupInvalidPassword(tr::now));
				return;
			}
			FileDialog::GetWritePath(
				controller->widget(),
				tr::ayu_ArchiveBackupExportTitle(tr::now),
				u"SleepyGram archive (*.sgarchive)"_q,
				u"sleepygram-archive.sgarchive"_q,
				crl::guard(controller, [=](QString &&path) {
					if (path.isEmpty()) return;
					const auto bytes = AyuArchiveBackup::Create(accountId, password);
					auto file = QSaveFile(path);
					if (bytes.isEmpty() || !file.open(QIODevice::WriteOnly)
						|| file.write(bytes) != bytes.size() || !file.commit()) {
						controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
						return;
					}
					if (completed) {
						completed();
					} else {
						controller->showToast(tr::lng_box_done(tr::now));
					}
				}));
		},
	}));
}

void ImportArchiveBackup(not_null<Window::SessionController*> controller) {
	const auto accountId = controller->session().userId().bare
		& PeerId::kChatTypeMask;
	FileDialog::GetOpenPath(
		controller->widget(),
		tr::ayu_ArchiveBackupImportTitle(tr::now),
		u"SleepyGram archive (*.sgarchive);;All files (*)"_q,
		crl::guard(controller, [=](FileDialog::OpenResult &&result) {
			if (result.paths.isEmpty()) return;
			QFile file(result.paths.front());
			if (!file.open(QIODevice::ReadOnly) || file.size() > 64 * 1024 * 1024) {
				controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
				return;
			}
			const auto bytes = file.read(64 * 1024 * 1024 + 1);
			if (file.error() != QFileDevice::NoError || bytes.size() > 64 * 1024 * 1024) {
				controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
				return;
			}
			const auto password = QInputDialog::getText(
				controller->widget(),
				tr::ayu_ArchiveBackupPasswordTitle(tr::now),
				tr::ayu_ArchiveBackupPasswordPrompt(tr::now),
				QLineEdit::Password);
			if (password.isEmpty()) return;
			const auto preview = AyuArchiveBackup::Read(bytes, accountId, password);
			if (!preview) {
				controller->showToast(tr::ayu_ArchiveBackupInvalidFile(tr::now));
				return;
			}
			controller->show(Ui::MakeConfirmBox({
				.text = tr::ayu_ArchiveBackupImportPreview(
					tr::now,
					lt_preview,
					preview->summary),
				.confirmed = [=](Fn<void()> &&close) {
					const auto imported = AyuArchiveBackup::Import(accountId, *preview);
					close();
					controller->showToast(imported.committed
						? tr::ayu_ArchiveBackupImportResult(
							tr::now,
							lt_added_count,
							imported.editedAdded + imported.deletedAdded,
							lt_skipped_count,
							imported.editedSkipped + imported.deletedSkipped)
						: tr::ayu_SettingsTransferFailure(tr::now));
				},
			}));
		}));
}

void ExportTransferSettings(
		not_null<Window::SessionController*> controller,
		Fn<void()> completed) {
	const auto accountId = controller->session().userId().bare;
	FileDialog::GetWritePath(
		controller->widget(),
		tr::ayu_SettingsExport(tr::now),
		u"JSON files (*.json)"_q,
		u"sleepygram-settings.json"_q,
		crl::guard(controller, [=](QString &&path) {
			if (path.isEmpty()) return;
			auto file = QSaveFile(path);
			const auto data = AyuSettings::exportTransfer(accountId);
			if (!file.open(QIODevice::WriteOnly)
				|| file.write(data) != data.size() || !file.commit()) {
				controller->showToast(tr::ayu_SettingsTransferFailure(tr::now));
				return;
			}
			completed();
		}));
}

void BuildOtherThings(SectionBuilder &builder) {
	const auto controller = builder.controller();

	builder.addButton({
		.id = u"ayu/archiveSearch"_q,
		.title = tr::ayu_ArchiveSearchTitle(),
		.onClick = [=] { ShowArchiveSearchBox(controller); },
	});

	builder.addSkip();
	builder.addButton({
		.id = u"ayu/accountTransferWizard"_q,
		.title = tr::ayu_AccountTransferTitle(),
		.onClick = [=] { ShowAccountTransferWizard(controller); },
	});
	builder.addButton({
		.id = u"ayu/archiveBackupExport"_q,
		.title = tr::ayu_ArchiveBackupExportTitle(),
		.onClick = [=] { ExportArchiveBackup(controller); },
	});
	builder.addButton({
		.id = u"ayu/archiveBackupImport"_q,
		.title = tr::ayu_ArchiveBackupImportTitle(),
		.onClick = [=] { ImportArchiveBackup(controller); },
	});
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

void ShowAccountTransferWizard(
		not_null<Window::SessionController*> controller) {
	controller->show(Ui::MakeConfirmBox({
		.text = tr::ayu_AccountTransferInstructions(tr::now),
		.confirmText = tr::ayu_AccountTransferPrepare(),
		.confirmed = [=](Fn<void()> &&close) {
			close();
			ExportTransferSettings(controller, [=] {
				ExportArchiveBackup(controller, [=] {
					controller->show(Ui::MakeInformBox(
						tr::ayu_AccountTransferComplete(tr::now)));
				});
			});
		},
	}));
}

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
