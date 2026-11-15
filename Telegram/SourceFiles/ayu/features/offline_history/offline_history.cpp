// This is the source code of AyuGram for Desktop.
#include "ayu/features/offline_history/offline_history.h"

#include "api/api_common.h"
#include "ayu/features/chat_lock/chat_lock.h"
#include "ayu/features/offline_history/offline_history_storage.h"
#include "core/application.h"
#include "core/file_location.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "data/data_file_origin.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_photo.h"
#include "data/data_photo_media.h"
#include "data/data_session.h"
#include "history/history_item.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "main/main_account.h"
#include "mtproto/sender.h"
#include "rpl/lifetime.h"
#include "storage/storage_account.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QPointer>
#include <QtCore/QLocale>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtGui/QCloseEvent>
#include <QtGui/QDesktopServices>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QVBoxLayout>

#include <algorithm>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace Ayu::OfflineHistory {
namespace {

constexpr auto kPageSize = 100;
constexpr auto kMaxPages = 100;
constexpr auto kMaxMessages = kPageSize * kMaxPages;
constexpr auto kDeviceLimit = int64(1024) * 1024 * 1024;
constexpr auto kMaxMessageTextLength = 16 * 1024;
constexpr auto kMaxTextBytes = int64(48) * 1024 * 1024;
constexpr auto kMaxAttachmentBytes = int64(25) * 1024 * 1024;

using Message = Storage::Message;
using Snapshot = Storage::Snapshot;
using Paths = Storage::Paths;

struct AttachmentTask {
	Storage::Attachment entry;
	DocumentData *document = nullptr;
	PhotoData *photo = nullptr;
};

using DialogKey = std::pair<uint64, PeerId>;
using Dialogs = std::map<DialogKey, QPointer<class OfflineHistoryDialog>>;

Dialogs &OpenDialogs() {
	static auto result = Dialogs();
	return result;
}

QString RootPath() {
	return cWorkingDir() + u"tdata/offline-history"_q;
}

bool PeerAllowsOffline(not_null<PeerData*> peer) {
	if (peer->isAyuNoForwards()) {
		return false;
	} else if (const auto channel = peer->asChannel()) {
		return channel->allowsForwarding();
	} else if (const auto chat = peer->asChat()) {
		return chat->allowsForwarding();
	}
	return true;
}

Paths PathsFor(not_null<Main::Session*> session, PeerId peerId) {
	return Storage::PathsFor(
		RootPath(),
		session->userId().bare,
		peerId);
}

QString FormatSnapshot(const Snapshot &snapshot) {
	auto result = QString();
	for (const auto &message : snapshot.messages) {
		const auto date = QLocale().toString(
			QDateTime::fromSecsSinceEpoch(message.date),
			QLocale::ShortFormat);
		result += u"[%1] %2\n%3\n\n"_q.arg(
			date,
			message.sender,
			message.text);
	}
	return result;
}

QVector<MTPMessage> MessagesFrom(const MTPmessages_Messages &result) {
	switch (result.type()) {
	case mtpc_messages_messages:
		return result.c_messages_messages().vmessages().v;
	case mtpc_messages_messagesSlice:
		return result.c_messages_messagesSlice().vmessages().v;
	case mtpc_messages_channelMessages:
		return result.c_messages_channelMessages().vmessages().v;
	case mtpc_messages_messagesNotModified:
		break;
	}
	return {};
}

class OfflineHistoryDialog final : public QDialog {
public:
	OfflineHistoryDialog(
		QWidget *parent,
		not_null<Main::Session*> session,
		not_null<PeerData*> peer)
	: QDialog(parent)
	, _session(session)
	, _peer(peer)
	, _accountId(session->userId().bare)
	, _paths(PathsFor(session, peer->id))
	, _api(&session->account().mtp()) {
		setWindowTitle(tr::lng_offline_history_title(tr::now)
			+ u" — "_q
			+ peer->name());
		setWindowFlag(Qt::Window, true);
		resize(760, 560);

		auto layout = new QVBoxLayout(this);
		_days = new QComboBox(this);
		_days->addItem(tr::lng_offline_history_one_day(tr::now), 1);
		_days->addItem(tr::lng_offline_history_three_days(tr::now), 3);
		_days->addItem(tr::lng_offline_history_seven_days(tr::now), 7);
		_days->setCurrentIndex(2);
		_includeAttachments = new QCheckBox(
			tr::lng_offline_history_media(tr::now),
			this);
		_status = new QLabel(this);
		_progress = new QProgressBar(this);
		_progress->setRange(0, kMaxMessages);
		_progress->setValue(0);
		_text = new QTextBrowser(this);
		_text->setReadOnly(true);
		_text->setOpenLinks(false);
		_text->setPlainText(tr::lng_offline_history_empty(tr::now));
		layout->addWidget(_days);
		layout->addWidget(_includeAttachments);
		layout->addWidget(_status);
		layout->addWidget(_progress);
		layout->addWidget(_text, 1);
		_attachmentsList = new QListWidget(this);
		_attachmentsList->setMaximumHeight(100);
		layout->addWidget(_attachmentsList);

		auto buttons = new QHBoxLayout();
		_save = new QPushButton(tr::lng_offline_history_save(tr::now), this);
		_delete = new QPushButton(tr::lng_offline_history_delete(tr::now), this);
		_openAttachment = new QPushButton(
			tr::lng_offline_history_open_attachment(tr::now),
			this);
		_close = new QPushButton(tr::lng_close(tr::now), this);
		buttons->addWidget(_save);
		buttons->addWidget(_delete);
		buttons->addWidget(_openAttachment);
		buttons->addStretch(1);
		buttons->addWidget(_close);
		layout->addLayout(buttons);

		connect(_save, &QPushButton::clicked, this, [=] { startOrResume(); });
		connect(_delete, &QPushButton::clicked, this, [=] { deleteSnapshot(); });
		connect(_openAttachment, &QPushButton::clicked, this, [=] {
			openSelectedAttachment();
		});
		connect(_attachmentsList, &QListWidget::itemDoubleClicked, this, [=] {
			openSelectedAttachment();
		});
		connect(_attachmentsList, &QListWidget::itemSelectionChanged, this, [=] {
			_openAttachment->setEnabled(
				_attachmentsList->currentRow() >= 0);
		});
		connect(_close, &QPushButton::clicked, this, [=] { close(); });
		Ayu::ChatLock::Changes() | rpl::filter([=](const Ayu::ChatLock::Change &change) {
			return (change.accountId == _accountId)
				&& (!change.peerId || change.peerId == _peer->id);
		}) | rpl::on_next([=](const Ayu::ChatLock::Change &) {
			if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
				Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			}
		}, _lockLifetime);
		_session->data().documentLoadProgress()
			| rpl::filter([=](not_null<DocumentData*> document) {
				return _activeDocument == document.get();
			})
			| rpl::on_next([=](not_null<DocumentData*>) {
				documentLoadChanged();
			}, _downloadLifetime);
		_session->data().photoLoadProgress()
			| rpl::filter([=](not_null<PhotoData*> photo) {
				return _activePhoto == photo.get();
			})
			| rpl::on_next([=](not_null<PhotoData*>) {
				photoLoadChanged();
			}, _downloadLifetime);
		loadSnapshot();
	}

	~OfflineHistoryDialog() override {
		cancelActiveAttachment();
	}

	void closeEvent(QCloseEvent *event) override {
		cancelActiveAttachment();
		QDialog::closeEvent(event);
	}

	void closeForLock() {
		++_generation;
		_running = false;
		cancelActiveAttachment();
		close();
	}

private:
	void loadSnapshot() {
		Storage::ReadAttachments(
			_paths,
			_accountId,
			_peer->id,
			&_attachments);
		refreshAttachmentList();
		const auto complete = Storage::ReadSnapshot(
			_paths.complete,
			_accountId,
			_peer->id,
			&_snapshot);
		const auto partial = Storage::ReadSnapshot(
			_paths.partial,
			_accountId,
			_peer->id,
			&_partial);
		if (complete) {
			_text->setPlainText(FormatSnapshot(_snapshot));
			_status->setText(tr::lng_offline_history_messages(
				tr::now,
				lt_count,
				int(_snapshot.messages.size())));
		} else if (partial) {
			_text->setPlainText(FormatSnapshot(_partial));
			_status->setText(tr::lng_offline_history_partial(tr::now));
			_progress->setValue(int(_partial.messages.size()));
		} else {
			_status->setText(tr::lng_offline_history_empty(tr::now));
			_text->setPlainText(QString());
		}
		_delete->setEnabled(complete || partial
			|| QFileInfo::exists(_paths.complete)
			|| QFileInfo::exists(_paths.partial)
			|| QFileInfo::exists(_paths.attachmentManifest));
	}

	void refreshAttachmentList() {
		_attachmentsList->clear();
		for (auto i = 0; i != int(_attachments.size()); ++i) {
			const auto &attachment = _attachments[i];
			_attachmentsList->addItem(
				QStringLiteral("%1 (%2 bytes)")
					.arg(attachment.name)
					.arg(attachment.size));
			_attachmentsList->item(i)->setData(Qt::UserRole, i);
		}
		_openAttachment->setEnabled(false);
	}

	void openSelectedAttachment() {
		const auto item = _attachmentsList->currentItem();
		if (!item) {
			return;
		}
		const auto index = item->data(Qt::UserRole).toInt();
		if (index < 0 || index >= int(_attachments.size())) {
			return;
		}
		const auto &attachment = _attachments[index];
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
			Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			return;
		}
		const auto path = QDir(_paths.attachmentDirectory)
			.filePath(attachment.fileName);
		const auto directoryInfo = QFileInfo(_paths.attachmentDirectory);
		const auto info = QFileInfo(path);
		if (directoryInfo.isDir() && !directoryInfo.isSymLink()
			&& info.isFile() && !info.isSymLink()
			&& info.size() == attachment.size) {
			QDesktopServices::openUrl(QUrl::fromLocalFile(info.absoluteFilePath()));
		}
	}

	void startOrResume() {
		if (_running) {
			return;
		}
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
			Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			return;
		}
		if (!PeerAllowsOffline(_peer)) {
			deleteSnapshot();
			_status->setText(tr::lng_offline_history_restricted(tr::now));
			return;
		}
		if (!Storage::ReadSnapshot(
				_paths.partial,
				_accountId,
				_peer->id,
				&_snapshot)) {
			const auto now = QDateTime::currentSecsSinceEpoch();
			const auto days = _days->currentData().toInt();
			_snapshot = Snapshot{
				.from = now - (days * 24 * 60 * 60),
				.to = now,
			};
		}
		_records = std::set<MsgId>();
		_textBytes = 0;
		_attachmentTasks.clear();
		_attachmentTaskKeys.clear();
		_attachmentIndex = 0;
		_attachmentSaved = 0;
		_attachmentLimitHit = false;
		_attachmentsEnabled = _includeAttachments->isChecked();
		_includeAttachments->setEnabled(false);
		for (const auto &message : _snapshot.messages) {
			_records.emplace(message.id);
			_textBytes += message.text.toUtf8().size();
		}
		_generation++;
		_running = true;
		_save->setEnabled(false);
		_days->setEnabled(false);
		_progress->setValue(int(_snapshot.messages.size()));
		_status->setText(tr::lng_offline_history_progress(
			tr::now,
			lt_count,
			int(_snapshot.messages.size())));
		requestNextPage();
	}

	void collectAttachment(HistoryItem *item) {
		const auto media = item->media();
		if (!media || _attachmentTasks.size() >= 10000) {
			return;
		}
		auto task = AttachmentTask();
		task.entry.messageId = item->id;
		if (const auto document = media->document()) {
			if (document->isNull()
				|| document->forbidsFileSave()
				|| document->size <= 0
				|| document->size > kMaxAttachmentBytes) {
				return;
			}
			task.document = document;
			task.entry.mediaId = document->id;
			task.entry.name = document->filename();
			if (task.entry.name.isEmpty()) {
				task.entry.name = u"File"_q;
			}
			auto suffix = QFileInfo(task.entry.name).suffix().toLower();
			if (suffix.isEmpty() || suffix.size() > 10
				|| !std::ranges::all_of(suffix, [](QChar ch) {
					return (ch >= QLatin1Char('a') && ch <= QLatin1Char('z'))
						|| (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'));
				})) {
				suffix = u"bin"_q;
			}
			task.entry.fileName = QStringLiteral("m-%1-d-%2.%3")
				.arg(item->id.bare)
				.arg(task.entry.mediaId)
				.arg(suffix);
			task.entry.size = document->size;
			task.entry.sourceSize = document->size;
		} else if (const auto photo = media->photo()) {
			const auto size = photo->imageByteSize(Data::PhotoSize::Large);
			if (photo->isNull()
				|| photo->hasVideo()
				|| size <= 0
				|| size > kMaxAttachmentBytes) {
				return;
			}
			task.photo = photo;
			task.entry.photo = true;
			task.entry.mediaId = photo->id;
			task.entry.name = u"Photo.jpg"_q;
			task.entry.fileName = QStringLiteral("m-%1-p-%2.jpg")
				.arg(item->id.bare)
				.arg(task.entry.mediaId);
			task.entry.size = size;
			task.entry.sourceSize = size;
		} else {
			return;
		}
		const auto key = task.entry.fileName;
		if (!_attachmentTaskKeys.emplace(key).second) {
			return;
		}
		const auto existing = std::ranges::find(_attachments, task.entry.fileName,
			&Storage::Attachment::fileName);
		if (existing != end(_attachments)) {
			const auto path = QDir(_paths.attachmentDirectory)
				.filePath(existing->fileName);
			if (existing->sourceSize == task.entry.sourceSize
				&& QFileInfo(path).isFile()
				&& QFileInfo(path).size() == existing->size) {
				return;
			}
			QFile::remove(path);
			_attachments.erase(existing);
		}
		_attachmentTasks.push_back(std::move(task));
	}

	void requestNextPage() {
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
			Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			return;
		}
		if (_snapshot.pages >= kMaxPages
			|| _snapshot.messages.size() >= kMaxMessages) {
			stopPartial(tr::lng_offline_history_partial(tr::now));
			return;
		}
		const auto offset = _snapshot.nextOffset;
		const auto generation = _generation;
		_api.request(MTPmessages_GetHistory(
			_peer->input(),
			MTP_int(offset),
			MTP_int(int(_snapshot.to)),
			MTP_int(0),
			MTP_int(kPageSize),
			MTP_int(0),
			MTP_int(0),
			MTP_long(0)
		)).done(crl::guard(this, [=](const MTPmessages_Messages &result) {
			if (generation == _generation) {
				processPage(result, offset);
			}
		})).fail(crl::guard(this, [=](const MTP::Error &) {
			if (generation == _generation) {
				stopPartial(tr::lng_offline_history_error(tr::now));
			}
		})).send();
	}

	void processPage(const MTPmessages_Messages &result, int32 offset) {
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
			Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			return;
		}
		if (!PeerAllowsOffline(_peer)) {
			deleteSnapshot();
			_status->setText(tr::lng_offline_history_restricted(tr::now));
			return;
		}
		const auto page = MessagesFrom(result);
		if (_peer->asChannel()) {
			_session->data().processExistingMessages(_peer->asChannel(), result);
		} else {
			_session->data().processExistingMessages(nullptr, result);
		}
		if (page.isEmpty()) {
			finishSnapshot();
			return;
		}
		++_snapshot.pages;
		auto oldest = MsgId();
		auto oldestDate = TimeId();
		auto reachedStart = false;
		auto reachedTextLimit = false;
		for (const auto &message : page) {
			const auto id = IdFromMessage(message);
			oldest = oldest ? std::min(oldest, id) : id;
			const auto item = _session->data().message(FullMsgId(_peer->id, id));
			if (!item) {
				continue;
			}
			oldestDate = oldestDate
				? std::min(oldestDate, item->date())
				: item->date();
			if (item->date() < _snapshot.from) {
				reachedStart = true;
				continue;
			}
			if (item->date() > _snapshot.to
				|| item->isEphemeral()
				|| item->isAyuNoForwards()
				|| _peer->isAyuNoForwards()
				|| (item->media() && item->media()->ttlSeconds())
				|| (item->from() && item->from()->isAyuNoForwards())) {
				continue;
			}
			if (_attachmentsEnabled) {
				collectAttachment(item);
			}
			const auto text = item->originalText().text;
			if (text.isEmpty()
				|| text.size() > kMaxMessageTextLength
				|| !_records.emplace(id).second) {
				continue;
			}
			const auto textBytes = text.toUtf8().size();
			if (_textBytes + textBytes > kMaxTextBytes) {
				_records.erase(id);
				reachedTextLimit = true;
				break;
			}
			_textBytes += textBytes;
			_snapshot.messages.push_back({
				.id = id,
				.date = item->date(),
				.sender = item->from()
					? item->from()->name()
					: _peer->name(),
				.text = text,
			});
		}
		if (!oldest || oldest == offset) {
			finishSnapshot();
			return;
		}
		_snapshot.nextOffset = oldest.bare;
		std::ranges::sort(_snapshot.messages, [](const Message &a, const Message &b) {
			return (a.date == b.date) ? (a.id < b.id) : (a.date < b.date);
		});
		const auto partialBytes = Storage::Serialize(
			_snapshot,
			_accountId,
			_peer->id);
		if (partialBytes.isEmpty() || !Storage::WriteAtomic(
				_paths.partial,
				partialBytes,
				_paths.root,
				kDeviceLimit,
				{})) {
			stopPartial(tr::lng_offline_history_limit(tr::now));
			return;
		}
		_text->setPlainText(FormatSnapshot(_snapshot));
		_progress->setValue(int(_snapshot.messages.size()));
		_status->setText(tr::lng_offline_history_progress(
			tr::now,
			lt_count,
			int(_snapshot.messages.size())));
		if (reachedTextLimit) {
			stopPartial(tr::lng_offline_history_limit(tr::now));
			return;
		}
		if (reachedStart
			|| oldestDate < _snapshot.from
			|| page.size() < kPageSize) {
			finishSnapshot();
		} else {
			requestNextPage();
		}
	}

	void finishSnapshot() {
		std::ranges::sort(_snapshot.messages, [](const Message &a, const Message &b) {
			return (a.date == b.date) ? (a.id < b.id) : (a.date < b.date);
		});
		const auto bytes = Storage::Serialize(
			_snapshot,
			_accountId,
			_peer->id);
		if (bytes.isEmpty() || !Storage::WriteAtomic(
				_paths.complete,
				bytes,
				_paths.root,
				kDeviceLimit,
				{ _paths.partial })) {
			stopPartial(tr::lng_offline_history_limit(tr::now));
			return;
		}
		QFile::remove(_paths.partial);
		_progress->setValue(int(_snapshot.messages.size()));
		_text->setPlainText(FormatSnapshot(_snapshot));
		_status->setText(tr::lng_offline_history_messages(
			tr::now,
			lt_count,
			int(_snapshot.messages.size())));
		if (_attachmentsEnabled && !_attachmentTasks.empty()) {
			_attachmentSaved = 0;
			_attachmentIndex = 0;
			_progress->setRange(0, int(_attachmentTasks.size()));
			_progress->setValue(0);
			startNextAttachment();
		} else {
			finishRun();
		}
	}

	bool candidateAllowed(const AttachmentTask &task) const {
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)
			|| !PeerAllowsOffline(_peer)) {
			return false;
		}
		const auto item = _session->data().message(
			FullMsgId(_peer->id, task.entry.messageId));
		if (!item
			|| item->isEphemeral()
			|| item->isAyuNoForwards()
			|| (item->media() && item->media()->ttlSeconds())
			|| (item->from() && item->from()->isAyuNoForwards())) {
			return false;
		}
		const auto media = item->media();
		return media
			&& (task.document
				? media->document() == task.document
					&& !task.document->forbidsFileSave()
				: media->photo() == task.photo);
	}

	void startNextAttachment() {
		while (_attachmentIndex < int(_attachmentTasks.size())) {
			if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
				Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
				return;
			}
			auto &task = _attachmentTasks[_attachmentIndex++];
			_progress->setValue(_attachmentIndex);
			_status->setText(tr::lng_offline_history_attachment_progress(
				tr::now,
				lt_current,
				QString::number(_attachmentIndex),
				lt_total,
				QString::number(int(_attachmentTasks.size()))));
			if (!candidateAllowed(task)) {
				continue;
			}
			const auto path = QDir(_paths.attachmentDirectory)
				.filePath(task.entry.fileName);
			const auto temporary = path + QStringLiteral(".part");
			QFile::remove(temporary);
			if (Storage::UsageBytes(_paths.root) + task.entry.sourceSize
				> kDeviceLimit) {
				_attachmentLimitHit = true;
				_status->setText(
					tr::lng_offline_history_attachment_limit(tr::now));
				finishRun();
				return;
			}
			if (!ensureAttachmentDirectory()) {
				continue;
			}
			_activeTask = &task;
			_activePath = path;
			_activeTemporary = temporary;
			if (task.document) {
				if (task.document->loading()
					|| task.document->forbidsFileSave()) {
					clearActiveAttachment();
					continue;
				}
				_activeDocument = task.document;
				_previousDocumentLocation = task.document->location(true);
				if (!_previousDocumentLocation.inMediaCache()
					&& !_previousDocumentLocation.check()) {
					_previousDocumentLocation = Core::FileLocation();
				}
				task.document->save(
					Data::FileOrigin(FullMsgId(
						_peer->id,
						task.entry.messageId)),
					temporary);
				QTimer::singleShot(0, this, [=] { documentLoadChanged(); });
				return;
			}
			if (task.photo->loading(Data::PhotoSize::Large)) {
				clearActiveAttachment();
				continue;
			}
			_activePhoto = task.photo;
			task.photo->createMediaView();
			task.photo->load(
				Data::PhotoSize::Large,
				Data::FileOrigin(FullMsgId(
					_peer->id,
					task.entry.messageId)));
			QTimer::singleShot(0, this, [=] { photoLoadChanged(); });
			return;
		}
		finishRun();
	}

	void documentLoadChanged() {
		const auto document = _activeDocument;
		if (!document || !_activeTask) {
			return;
		}
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
			Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			return;
		}
		if (document->loading()) {
			if (document->loadingFilePath() != _activeTemporary
				|| document->loadOffset() > kMaxAttachmentBytes) {
				failActiveAttachment();
			}
			return;
		}
		if (!candidateAllowed(*_activeTask)) {
			failActiveAttachment();
			return;
		}
		const auto size = QFileInfo(_activeTemporary).size();
		if (size <= 0 || size > kMaxAttachmentBytes
			|| size != _activeTask->entry.sourceSize) {
			failActiveAttachment();
			return;
		}
		promoteActiveAttachment(size);
	}

	void photoLoadChanged() {
		const auto photo = _activePhoto;
		if (!photo || !_activeTask) {
			return;
		}
		if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
			Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			return;
		}
		if (photo->loading(Data::PhotoSize::Large)) {
			if (photo->loadOffset() > kMaxAttachmentBytes) {
				failActiveAttachment();
			}
			return;
		}
		if (!candidateAllowed(*_activeTask)) {
			failActiveAttachment();
			return;
		}
		const auto media = photo->activeMediaView();
		if (!media || !media->image(Data::PhotoSize::Large)
			|| !media->saveToFile(_activeTemporary)) {
			failActiveAttachment();
			return;
		}
		const auto size = QFileInfo(_activeTemporary).size();
		if (size <= 0 || size > kMaxAttachmentBytes) {
			failActiveAttachment();
			return;
		}
		promoteActiveAttachment(size);
	}

	void promoteActiveAttachment(qint64 size) {
		Expects(_activeTask != nullptr);
		if (!candidateAllowed(*_activeTask)
			|| Storage::UsageBytes(_paths.root) > kDeviceLimit) {
			_attachmentLimitHit = true;
			failActiveAttachment();
			return;
		}
		QFile::remove(_activePath);
		if (!QFile::rename(_activeTemporary, _activePath)) {
			failActiveAttachment();
			return;
		}
			auto entry = _activeTask->entry;
		entry.size = size;
		_attachments.push_back(entry);
		const auto manifest = Storage::SerializeAttachments(
			_attachments,
			_accountId,
			_peer->id);
		if (manifest.isEmpty() || !Storage::WriteAtomic(
				_paths.attachmentManifest,
				manifest,
				_paths.root,
				kDeviceLimit)) {
			_attachments.pop_back();
			QFile::remove(_activePath);
			failActiveAttachment();
			return;
		}
		if (_activeDocument) {
			restoreDocumentLocation(
				_activeDocument,
				_previousDocumentLocation,
				_activeTemporary);
		}
		++_attachmentSaved;
		refreshAttachmentList();
		clearActiveAttachment();
		startNextAttachment();
	}

	void failActiveAttachment() {
		const auto document = _activeDocument;
		const auto photo = _activePhoto;
		const auto temporary = _activeTemporary;
		const auto previous = _previousDocumentLocation;
		clearActiveAttachment();
		if (document && document->loading()
			&& document->loadingFilePath() == temporary) {
			document->cancel();
		}
		if (document) {
			restoreDocumentLocation(document, previous, temporary);
		}
		if (photo && photo->loading(Data::PhotoSize::Large)) {
			photo->cancel();
		}
		QFile::remove(temporary);
		startNextAttachment();
	}

	void restoreDocumentLocation(
			DocumentData *document,
			const Core::FileLocation &previous,
			const QString &temporary) {
		if (!document || document->location(false).name() != temporary) {
			return;
		}
		const auto key = document->mediaKey();
		if (previous.inMediaCache()) {
			const auto location = Core::FileLocation::InMediaCacheLocation();
			document->setLocation(location);
			document->setLoadedInMediaCache(true);
			document->session().local().writeFileLocation(key, location);
		} else if (!previous.isEmpty()) {
			document->setLocation(previous);
			document->session().local().writeFileLocation(key, previous);
		} else {
			document->setLocation(Core::FileLocation::InMediaCacheLocation());
			document->setLoadedInMediaCache(false);
			document->session().local().removeFileLocation(key);
		}
	}

	bool ensureAttachmentDirectory() {
		const auto info = QFileInfo(_paths.attachmentDirectory);
		if (info.exists()) {
			return info.isDir() && !info.isSymLink();
		}
		return QDir().mkpath(_paths.attachmentDirectory)
			&& QFileInfo(_paths.attachmentDirectory).isDir()
			&& !QFileInfo(_paths.attachmentDirectory).isSymLink();
	}

	void clearActiveAttachment() {
		_activeDocument = nullptr;
		_activePhoto = nullptr;
		_activeTask = nullptr;
		_activePath.clear();
		_activeTemporary.clear();
		_previousDocumentLocation = Core::FileLocation();
	}

	void cancelActiveAttachment() {
		const auto document = _activeDocument;
		const auto photo = _activePhoto;
		const auto temporary = _activeTemporary;
		const auto previous = _previousDocumentLocation;
		clearActiveAttachment();
		if (document && document->loading()
			&& document->loadingFilePath() == temporary) {
			document->cancel();
		}
		if (photo && photo->loading(Data::PhotoSize::Large)) {
			photo->cancel();
		}
		if (document) {
			restoreDocumentLocation(document, previous, temporary);
		}
		QFile::remove(temporary);
	}

	void finishRun() {
		_running = false;
		_save->setEnabled(true);
		_days->setEnabled(true);
		_includeAttachments->setEnabled(true);
		_delete->setEnabled(true);
		_progress->setRange(0, kMaxMessages);
		_progress->setValue(int(_snapshot.messages.size()));
		if (_attachmentSaved) {
			_status->setText(tr::lng_offline_history_attachments_saved(
				tr::now,
				lt_count,
				_attachmentSaved));
		} else if (_attachmentLimitHit) {
			_status->setText(tr::lng_offline_history_attachment_limit(tr::now));
		} else {
			_status->setText(tr::lng_offline_history_messages(
				tr::now,
				lt_count,
				int(_snapshot.messages.size())));
		}
	}

	void stopPartial(const QString &status) {
		_running = false;
		_save->setEnabled(true);
		_days->setEnabled(true);
		_includeAttachments->setEnabled(true);
		_status->setText(status);
	}

	void deleteSnapshot() {
		++_generation;
		_running = false;
		cancelActiveAttachment();
		QFile::remove(_paths.complete);
		QFile::remove(_paths.partial);
		QFile::remove(_paths.attachmentManifest);
		const auto attachmentsDirectory = QFileInfo(_paths.attachmentDirectory);
		if (attachmentsDirectory.isSymLink()) {
			QFile::remove(_paths.attachmentDirectory);
		} else {
			QDir(_paths.attachmentDirectory).removeRecursively();
		}
		_snapshot = Snapshot();
		_partial = Snapshot();
		_attachments.clear();
		_attachmentTasks.clear();
		_attachmentTaskKeys.clear();
		_records.clear();
		refreshAttachmentList();
		_progress->setValue(0);
		_text->setPlainText(tr::lng_offline_history_empty(tr::now));
		_status->setText(tr::lng_offline_history_empty(tr::now));
		_save->setEnabled(true);
		_days->setEnabled(true);
		_includeAttachments->setEnabled(true);
		_delete->setEnabled(false);
	}

	not_null<Main::Session*> _session;
	not_null<PeerData*> _peer;
	const uint64 _accountId;
	const Paths _paths;
	MTP::Sender _api;
	QComboBox *_days = nullptr;
	QCheckBox *_includeAttachments = nullptr;
	QLabel *_status = nullptr;
	QProgressBar *_progress = nullptr;
	QTextBrowser *_text = nullptr;
	QListWidget *_attachmentsList = nullptr;
	QPushButton *_save = nullptr;
	QPushButton *_delete = nullptr;
	QPushButton *_openAttachment = nullptr;
	QPushButton *_close = nullptr;
	Snapshot _snapshot;
	Snapshot _partial;
	std::vector<Storage::Attachment> _attachments;
	std::vector<AttachmentTask> _attachmentTasks;
	std::set<QString> _attachmentTaskKeys;
	AttachmentTask *_activeTask = nullptr;
	DocumentData *_activeDocument = nullptr;
	PhotoData *_activePhoto = nullptr;
	QString _activePath;
	QString _activeTemporary;
	Core::FileLocation _previousDocumentLocation;
	std::set<MsgId> _records;
	rpl::lifetime _downloadLifetime;
	int64 _textBytes = 0;
	int _attachmentIndex = 0;
	int _attachmentSaved = 0;
	bool _attachmentLimitHit = false;
	rpl::lifetime _lockLifetime;
	int _generation = 0;
	bool _attachmentsEnabled = false;
	bool _running = false;
};

} // namespace

void Open(
		not_null<Window::SessionController*> controller,
		PeerId peerId) {
	const auto session = &controller->session();
	const auto peer = session->data().peerLoaded(peerId);
	if (!peer || Ayu::ChatLock::IsChatLocked(session, peerId)) {
		return;
	}
	if (!PeerAllowsOffline(peer)) {
		return;
	}
	const auto accountId = session->userId().bare;
	const auto key = DialogKey(accountId, peerId);
	if (const auto i = OpenDialogs().find(key); i != end(OpenDialogs())) {
		if (i->second) {
			i->second->showNormal();
			i->second->raise();
			i->second->activateWindow();
			return;
		}
	}
	auto dialog = new OfflineHistoryDialog(
		controller->window().widget().get(),
		session,
		peer);
	OpenDialogs()[key] = dialog;
	dialog->setAttribute(Qt::WA_DeleteOnClose);
	dialog->show();
}

void CloseForChat(uint64 accountId, PeerId peerId) {
	auto closing = std::vector<QPointer<OfflineHistoryDialog>>();
	for (auto i = OpenDialogs().begin(); i != OpenDialogs().end();) {
		if (i->first.first == accountId
			&& (!peerId || i->first.second == peerId)) {
			closing.push_back(i->second);
			i = OpenDialogs().erase(i);
		} else {
			++i;
		}
	}
	for (const auto dialog : closing) {
		if (dialog) {
			dialog->closeForLock();
		}
	}
}

} // namespace Ayu::OfflineHistory
