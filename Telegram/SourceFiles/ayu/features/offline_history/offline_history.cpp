// This is the source code of AyuGram for Desktop.
#include "ayu/features/offline_history/offline_history.h"

#include "api/api_common.h"
#include "ayu/features/chat_lock/chat_lock.h"
#include "ayu/features/offline_history/offline_history_storage.h"
#include "core/application.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "history/history_item.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "mtproto/sender.h"
#include "rpl/lifetime.h"
#include "window/window_session_controller.h"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QPointer>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
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

using Message = Storage::Message;
using Snapshot = Storage::Snapshot;
using Paths = Storage::Paths;

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
		const auto date = QDateTime::fromSecsSinceEpoch(message.date)
			.toString(Qt::DefaultLocaleShortDate);
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
		_status = new QLabel(this);
		_progress = new QProgressBar(this);
		_progress->setRange(0, kMaxMessages);
		_progress->setValue(0);
		_text = new QTextBrowser(this);
		_text->setReadOnly(true);
		_text->setOpenLinks(false);
		_text->setPlainText(tr::lng_offline_history_empty(tr::now));
		layout->addWidget(_days);
		layout->addWidget(_status);
		layout->addWidget(_progress);
		layout->addWidget(_text, 1);

		auto buttons = new QHBoxLayout();
		_save = new QPushButton(tr::lng_offline_history_save(tr::now), this);
		_delete = new QPushButton(tr::lng_offline_history_delete(tr::now), this);
		_close = new QPushButton(tr::lng_close(), this);
		buttons->addWidget(_save);
		buttons->addWidget(_delete);
		buttons->addStretch(1);
		buttons->addWidget(_close);
		layout->addLayout(buttons);

		connect(_save, &QPushButton::clicked, this, [=] { startOrResume(); });
		connect(_delete, &QPushButton::clicked, this, [=] { deleteSnapshot(); });
		connect(_close, &QPushButton::clicked, this, [=] { close(); });
		Ayu::ChatLock::Changes() | rpl::filter([=](const Ayu::ChatLock::Change &change) {
			return (change.accountId == _accountId)
				&& (!change.peerId || change.peerId == _peer->id);
		}) | rpl::on_next([=](const Ayu::ChatLock::Change &) {
			if (Ayu::ChatLock::IsChatLocked(_session, _peer->id)) {
				Ayu::OfflineHistory::CloseForChat(_accountId, _peer->id);
			}
		}, _lockLifetime);
		loadSnapshot();
	}

	void closeForLock() {
		++_generation;
		_running = false;
		close();
	}

private:
	void loadSnapshot() {
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
			|| QFileInfo::exists(_paths.partial));
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
				|| item->isNoForwards()
				|| item->isAyuNoForwards()
				|| _peer->isAyuNoForwards()
				|| (item->media() && item->media()->ttlSeconds())
				|| (item->from() && item->from()->isAyuNoForwards())) {
				continue;
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
		_running = false;
		_save->setEnabled(true);
		_days->setEnabled(true);
		_delete->setEnabled(true);
		_progress->setValue(int(_snapshot.messages.size()));
		_text->setPlainText(FormatSnapshot(_snapshot));
		_status->setText(tr::lng_offline_history_messages(
			tr::now,
			lt_count,
			int(_snapshot.messages.size())));
	}

	void stopPartial(const QString &status) {
		_running = false;
		_save->setEnabled(true);
		_days->setEnabled(true);
		_status->setText(status);
	}

	void deleteSnapshot() {
		++_generation;
		_running = false;
		QFile::remove(_paths.complete);
		QFile::remove(_paths.partial);
		_snapshot = Snapshot();
		_partial = Snapshot();
		_records.clear();
		_progress->setValue(0);
		_text->setPlainText(tr::lng_offline_history_empty(tr::now));
		_status->setText(tr::lng_offline_history_empty(tr::now));
		_save->setEnabled(true);
		_days->setEnabled(true);
		_delete->setEnabled(false);
	}

	not_null<Main::Session*> _session;
	not_null<PeerData*> _peer;
	const uint64 _accountId;
	const Paths _paths;
	MTP::Sender _api;
	QComboBox *_days = nullptr;
	QLabel *_status = nullptr;
	QProgressBar *_progress = nullptr;
	QTextBrowser *_text = nullptr;
	QPushButton *_save = nullptr;
	QPushButton *_delete = nullptr;
	QPushButton *_close = nullptr;
	Snapshot _snapshot;
	Snapshot _partial;
	std::set<MsgId> _records;
	int64 _textBytes = 0;
	rpl::lifetime _lockLifetime;
	int _generation = 0;
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
