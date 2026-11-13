/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "menu/menu_item_download_files.h"

#include "base/flat_set.h"
#include "base/unixtime.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "core/file_utilities.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "data/data_file_click_handler.h"
#include "data/data_photo.h"
#include "data/data_photo_media.h"
#include "data/data_session.h"
#include "history/history_inner_widget.h"
#include "history/history_item.h"
#include "history/view/history_view_list_widget.h" // HistoryView::SelectedItem.
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "mainwindow.h"
#include "storage/storage_account.h"
#include "ui/text/text_utilities.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/toast/toast.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/popup_menu.h"
#include "window/window_session_controller.h"
#include "window/window_controller.h"
#include "styles/style_chat_helpers.h"
#include "styles/style_menu_icons.h"
#include "styles/style_widgets.h"

#include <QFileInfo>
#include <QTimer>

namespace Menu {
namespace {

using Documents = std::vector<std::pair<not_null<DocumentData*>, FullMsgId>>;
using Photos = std::vector<std::pair<not_null<PhotoData*>, FullMsgId>>;

constexpr auto kBulkDownloadLimitPref = "bulk-download-limit";
constexpr auto kBulkDownloadLimits = { 1, 2, 3, 5 };

struct BulkSaveEntry {
	not_null<DocumentData*> document;
	FullMsgId origin;
	QString path;
	enum class State { Pending, Active, Saved, Failed, Cancelled } state
		= State::Pending;
};

struct BulkSaveQueue {
	std::vector<BulkSaveEntry> entries;
	int limit = 3;
	bool started = false;
	bool stopped = false;

	[[nodiscard]] int pending() const {
		return ranges::count(entries, BulkSaveEntry::State::Pending,
			&BulkSaveEntry::state);
	}
	[[nodiscard]] int running() const {
		return ranges::count(entries, BulkSaveEntry::State::Active,
			&BulkSaveEntry::state);
	}
	[[nodiscard]] int saved() const {
		return ranges::count(entries, BulkSaveEntry::State::Saved,
			&BulkSaveEntry::state);
	}
	[[nodiscard]] int failed() const {
		return ranges::count(entries, BulkSaveEntry::State::Failed,
			&BulkSaveEntry::state);
	}
	[[nodiscard]] int cancelled() const {
		return ranges::count(entries, BulkSaveEntry::State::Cancelled,
			&BulkSaveEntry::state);
	}
};

[[nodiscard]] QString BulkTargetKey(const QString &path) {
	return QFileInfo(path).fileName().normalized(
		QString::NormalizationForm_C).toCaseFolded();
}

[[nodiscard]] QString AvailableBulkTarget(
		const QString &path,
		const BulkSaveQueue &queue,
		const BulkSaveEntry *excluded) {
	auto used = base::flat_set<QString>();
	for (const auto &entry : queue.entries) {
		if (&entry != excluded) {
			used.emplace(BulkTargetKey(entry.path));
		}
	}
	if (!QFileInfo::exists(path) && !used.contains(BulkTargetKey(path))) {
		return path;
	}
	const auto info = QFileInfo(path);
	const auto extension = info.suffix().isEmpty()
		? QString()
		: ('.' + info.suffix());
	const auto stem = path.chopped(extension.size());
	for (auto i = 2;; ++i) {
		const auto candidate = stem + u" (%1)"_q.arg(i) + extension;
		if (!used.contains(BulkTargetKey(candidate))
			&& !QFileInfo::exists(candidate)) {
			return candidate;
		}
	}
}

[[nodiscard]] bool BulkSaveSucceeded(const BulkSaveEntry &entry) {
	const auto info = QFileInfo(entry.path);
	const auto actual = QFileInfo(entry.document->filepath(true));
	return info.exists()
		&& actual.absoluteFilePath() == info.absoluteFilePath()
		&& (!entry.document->size || info.size() == entry.document->size);
}

void RefreshBulkSaveQueue(
		const std::shared_ptr<BulkSaveQueue> &queue) {
	auto active = queue->running();
	for (auto &entry : queue->entries) {
		if (entry.state == BulkSaveEntry::State::Active
			&& !entry.document->loading()) {
			entry.state = BulkSaveSucceeded(entry)
				? BulkSaveEntry::State::Saved
				: BulkSaveEntry::State::Failed;
			--active;
		}
	}
	if (!queue->started || queue->stopped) {
		return;
	}
	for (auto &entry : queue->entries) {
		if (active >= queue->limit) {
			break;
		} else if (entry.state != BulkSaveEntry::State::Pending) {
			continue;
		} else if (entry.document->loading()) {
			entry.state = BulkSaveEntry::State::Failed;
			continue;
		}
		entry.path = AvailableBulkTarget(entry.path, *queue, &entry);
		entry.state = BulkSaveEntry::State::Active;
		++active;
		entry.document->save(entry.origin, entry.path);
		if (!entry.document->loading()) {
			entry.state = BulkSaveSucceeded(entry)
				? BulkSaveEntry::State::Saved
				: BulkSaveEntry::State::Failed;
			--active;
		}
	}
}

void ShowBulkSaveQueue(
		not_null<Window::SessionController*> controller,
		std::shared_ptr<BulkSaveQueue> queue) {
	controller->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(tr::ayu_BulkDownloadTitle());
		box->setWidth(st::boxWideWidth);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			tr::ayu_BulkDownloadLimit(tr::now),
			st::boxLabel));
		const auto status = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			st::boxLabel));
		const auto savedLimit = Core::App().settings().readPref<int>(
			kBulkDownloadLimitPref,
			3);
		auto selectedLimit = ranges::find(kBulkDownloadLimits, savedLimit);
		const auto defaultLimit = selectedLimit == end(kBulkDownloadLimits)
			? 3
			: *selectedLimit;
		const auto group = std::make_shared<Ui::RadiobuttonGroup>(defaultLimit);
		const auto limitChanged = box->lifetime().make_state<int>(defaultLimit);
		group->setChangedCallback([=](int value) {
			*limitChanged = value;
		});
		for (const auto count : kBulkDownloadLimits) {
			box->addRow(object_ptr<Ui::Radiobutton>(
				box,
				group,
				count,
				QString::number(count),
				st::defaultBoxCheckbox));
		}
		auto timer = new QTimer(box);
		timer->setInterval(250);
		const auto updateStatus = [=] {
			status->setText(tr::ayu_BulkDownloadProgress(
				tr::now,
				lt_saved,
				QString::number(queue->saved()),
				lt_total,
				QString::number(int(queue->entries.size())),
				lt_running,
				QString::number(queue->running()),
				lt_failed,
				QString::number(queue->failed()),
				lt_cancelled,
				QString::number(queue->cancelled())));
		};
		const auto updateButtons = [=] {
			box->clearButtons();
			if (!queue->started) {
				box->addButton(tr::ayu_BulkDownloadStart(), [=] {
					queue->limit = *limitChanged;
					Core::App().settings().writePref<int>(
						kBulkDownloadLimitPref,
						queue->limit);
					Core::App().saveSettingsDelayed();
					queue->started = true;
					RefreshBulkSaveQueue(queue);
					updateStatus();
				});
				box->addButton(tr::lng_cancel(), [=] {
					queue->stopped = true;
					timer->stop();
					box->closeBox();
				});
			} else if (!queue->stopped && queue->pending()) {
				box->addButton(tr::ayu_BulkDownloadStop(), [=] {
					queue->stopped = true;
					for (auto &entry : queue->entries) {
						if (entry.state == BulkSaveEntry::State::Pending) {
							entry.state = BulkSaveEntry::State::Cancelled;
						}
					}
				});
			} else if (queue->stopped && queue->running()) {
				box->addButton(tr::lng_close(), [=] {
					timer->stop();
					box->closeBox();
				});
			} else if (queue->failed() || queue->cancelled()
				|| queue->pending()) {
				box->addButton(tr::ayu_BulkDownloadRetry(), [=] {
					for (auto &entry : queue->entries) {
						if (entry.state == BulkSaveEntry::State::Failed
							|| entry.state == BulkSaveEntry::State::Cancelled) {
							entry.path = AvailableBulkTarget(
								entry.path,
								*queue,
								&entry);
							entry.state = BulkSaveEntry::State::Pending;
						}
					}
					queue->stopped = false;
					timer->start();
				});
				if (queue->running()) {
					box->addButton(tr::lng_close(), [=] {
						timer->stop();
						box->closeBox();
					});
				} else {
					box->addButton(tr::lng_close(), [=] { box->closeBox(); });
				}
			} else {
				box->addButton(tr::lng_close(), [=] {
					timer->stop();
					box->closeBox();
				});
			}
		};
		updateStatus();
		updateButtons();
		struct ObservedState {
			int running = 0;
			int pending = 0;
			int saved = 0;
			int failed = 0;
			int cancelled = 0;
			bool started = false;
			bool stopped = false;
		};
		auto observed = std::make_shared<ObservedState>(ObservedState{
			queue->running(),
			queue->pending(),
			queue->saved(),
			queue->failed(),
			queue->cancelled(),
			queue->started,
			queue->stopped,
		});
		QObject::connect(timer, &QTimer::timeout, box, [=] {
			RefreshBulkSaveQueue(queue);
			updateStatus();
			if (observed->running != queue->running()
				|| observed->pending != queue->pending()
				|| observed->saved != queue->saved()
				|| observed->failed != queue->failed()
				|| observed->cancelled != queue->cancelled()
				|| observed->started != queue->started
				|| observed->stopped != queue->stopped) {
				observed->running = queue->running();
				observed->pending = queue->pending();
				observed->saved = queue->saved();
				observed->failed = queue->failed();
				observed->cancelled = queue->cancelled();
				observed->started = queue->started;
				observed->stopped = queue->stopped;
				updateButtons();
			}
			if (queue->started && !queue->running() && !queue->pending()) {
				timer->stop();
			}
		});
		timer->start();
	}));
}

[[nodiscard]] bool Collected(
		HistoryItem *item,
		Documents &documents,
		Photos &photos) {
	if (!item) {
		return false;
	} else if (item->forbidsSaving()) {
		return true;
	} else if (const auto media = item->media()) {
		if (const auto photo = media->photo()) {
			photos.emplace_back(photo, item->fullId());
			return true;
		} else if (const auto document = media->document()) {
			documents.emplace_back(document, item->fullId());
			return true;
		}
	}
	return false;
}

void AddAction(
		not_null<Ui::PopupMenu*> menu,
		not_null<Window::SessionController*> controller,
		Documents &&documents,
		Photos &&photos,
		Fn<void()> callback) {
	const auto text = documents.empty()
		? tr::lng_context_save_images_selected(tr::now)
		: tr::lng_context_save_documents_selected(tr::now);
	const auto icon = documents.empty()
		? &st::menuIconSaveImage
		: &st::menuIconDownload;
	const auto shouldShowToast = documents.empty();

	const auto weak = base::make_weak(controller);
	const auto saveImages = [=](const QString &folderPath) {
		const auto controller = weak.get();
		if (!controller) {
			return;
		}
		const auto session = &controller->session();
		const auto downloadPath = folderPath.isEmpty()
			? Core::App().settings().downloadPath()
			: folderPath;
		const auto path = downloadPath.isEmpty()
			? File::DefaultDownloadPath(session)
			: (downloadPath == FileDialog::Tmp())
			? session->local().tempDirectory()
			: downloadPath;
		if (path.isEmpty()) {
			return;
		}
		QDir().mkpath(path);

		const auto showToast = !shouldShowToast
			? Fn<void(const QString &)>(nullptr)
			: [=](const QString &lastPath) {
				const auto filter = [lastPath](const auto ...) {
					File::ShowInFolder(lastPath);
					return false;
				};
				controller->showToast({
					.text = (photos.size() > 1
							? tr::lng_mediaview_saved_images_to
							: tr::lng_mediaview_saved_to)(
						tr::now,
						lt_downloads,
						tr::link(
							tr::lng_mediaview_downloads(tr::now),
							"internal:show_saved_message"),
						tr::marked),
					.filter = filter,
					.iconLottie = u"toast/save_to_gallery"_q,
					.iconLottieSize = st::toastLottieIconSize,
					.st = &st::defaultToast,
				});
			};

		auto views = std::vector<std::shared_ptr<Data::PhotoMedia>>();
		auto dates = std::vector<TimeId>();
		for (const auto &[photo, fullId] : photos) {
			if (const auto view = photo->createMediaView()) {
				view->wanted(Data::PhotoSize::Large, fullId);
				views.push_back(view);
				const auto photoDate = photo->date();
				const auto item = session->data().message(fullId);
				dates.push_back(photoDate
					? photoDate
					: (item ? item->date() : TimeId(0)));
			}
		}

		const auto finalCheck = [=] {
			for (const auto &[photo, _] : photos) {
				if (photo->loading()) {
					return false;
				}
			}
			return true;
		};

		const auto saveToFiles = [=] {
			const auto fullPath = [&](int i) {
				return filedialogDefaultName(
					u"photo_"_q + QString::number(i),
					u".jpg"_q,
					path);
			};
			auto lastPath = QString();
			for (auto i = 0; i < views.size(); i++) {
				lastPath = fullPath(i + 1);
				if (views[i]->saveToFile(lastPath) && dates[i] > 0) {
					auto f = QFile(lastPath);
					if (f.open(QIODevice::ReadWrite)) {
						const auto when = base::unixtime::parse(dates[i]);
						f.setFileTime(
							when,
							QFileDevice::FileModificationTime);
						f.setFileTime(
							when,
							QFileDevice::FileAccessTime);
					}
				}
			}
			if (showToast) {
				showToast(lastPath);
			}
		};

		if (finalCheck()) {
			saveToFiles();
		} else {
			auto lifetime = std::make_shared<rpl::lifetime>();
			session->downloaderTaskFinished(
			) | rpl::on_next([=]() mutable {
				if (finalCheck()) {
					saveToFiles();
					base::take(lifetime)->destroy();
				}
			}, *lifetime);
		}
	};
	const auto saveDocuments = [=](const QString &folderPath) {
		const auto nameKey = [](const QString &path) {
			return QFileInfo(path).fileName().normalized(
				QString::NormalizationForm_C).toCaseFolded();
		};
		const auto directory = QDir(folderPath);
		auto usedNames = base::flat_set<QString>();
		if (!folderPath.isEmpty()) {
			for (const auto &[document, origin] : documents) {
				const auto path = document->loadingFilePath();
				if (!path.isEmpty() && QFileInfo(path).absoluteDir() == directory) {
					usedNames.emplace(nameKey(path));
				}
			}
		}
		auto savedDocuments = base::flat_set<not_null<DocumentData*>>();
		auto queue = std::make_shared<BulkSaveQueue>();
		for (const auto &[document, origin] : documents) {
			if (!savedDocuments.emplace(document).second) {
				continue;
			}
			const auto already = document->filepath(true);
			if (!already.isEmpty()
				&& QFileInfo(already).absoluteDir() == directory) {
				continue;
			}
			const auto loading = document->loadingFilePath();
			if (!loading.isEmpty()
				&& QFileInfo(loading).absoluteDir() == directory) {
				usedNames.emplace(nameKey(loading));
				queue->entries.push_back({
					document,
					origin,
					loading,
					BulkSaveEntry::State::Active,
				});
				continue;
			}
			auto path = DocumentFileNameForSave(
				document,
				false,
				QString(),
				directory);
			if (path.isEmpty()) {
				continue;
			}
			if (usedNames.contains(nameKey(path))) {
				const auto info = QFileInfo(path);
				const auto suffix = info.suffix();
				const auto extension = suffix.isEmpty()
					? QString()
					: ('.' + suffix);
				const auto prefix = path.chopped(extension.size());
				for (auto i = 2;; ++i) {
					path = prefix + u" (%1)"_q.arg(i) + extension;
					if (!usedNames.contains(nameKey(path))
						&& !QFileInfo::exists(path)) {
						break;
					}
				}
			}
			usedNames.emplace(nameKey(path));
			queue->entries.push_back({ document, origin, path });
		}
		if (!queue->entries.empty()) {
			if (const auto strong = weak.get()) {
				ShowBulkSaveQueue(strong, std::move(queue));
			}
		}
	};

	menu->addAction(text, [=] {
		const auto save = [=](const QString &folderPath) {
			saveImages(folderPath);
			saveDocuments(folderPath);
			callback();
		};
		const auto controller = weak.get();
		if (!controller) {
			return;
		}
		if (Core::App().settings().askDownloadPath()) {
			const auto initialPath = [] {
				const auto path = Core::App().settings().downloadPath();
				if (!path.isEmpty() && path != FileDialog::Tmp()) {
					return path.left(path.size()
						- (path.endsWith('/') ? 1 : 0));
				}
				return QString();
			}();
			const auto handleFolder = [=](const QString &result) {
				if (!result.isEmpty()) {
					const auto folderPath = result.endsWith('/')
						? result
						: (result + '/');
					save(folderPath);
				}
			};
			FileDialog::GetFolder(
				controller->window().widget().get(),
				tr::lng_download_path_choose(tr::now),
				initialPath,
				handleFolder);
		} else {
			save(QString());
		}
	}, icon);
}

} // namespace

void AddDownloadFilesAction(
		not_null<Ui::PopupMenu*> menu,
		not_null<Window::SessionController*> window,
		const std::vector<HistoryView::SelectedItem> &selectedItems,
		not_null<HistoryView::ListWidget*> list) {
	if (selectedItems.empty()) {
		return;
	}
	auto docs = Documents();
	auto photos = Photos();
	for (const auto &selectedItem : selectedItems) {
		const auto &id = selectedItem.msgId;
		const auto item = window->session().data().message(id);

		if (!Collected(item, docs, photos)) {
			return;
		}
	}
	std::sort(docs.begin(), docs.end(), [](const auto &a, const auto &b) {
		return a.second < b.second;
	});
	std::sort(photos.begin(), photos.end(), [](const auto &a, const auto &b) {
		return a.second < b.second;
	});
	if (docs.empty() && photos.empty()) {
		return;
	}
	const auto done = [weak = base::make_weak(list)] {
		if (const auto strong = weak.get()) {
			strong->cancelSelection();
		}
	};
	AddAction(menu, window, std::move(docs), std::move(photos), done);
}

void AddDownloadFilesAction(
		not_null<Ui::PopupMenu*> menu,
		not_null<Window::SessionController*> window,
		const std::vector<not_null<HistoryItem*>> &items,
		not_null<HistoryInner*> list) {
	if (items.empty()) {
		return;
	}
	auto docs = Documents();
	auto photos = Photos();
	for (const auto &item : items) {
		if (!Collected(item, docs, photos)) {
			return;
		}
	}
	std::sort(docs.begin(), docs.end(), [](const auto &a, const auto &b) {
		return a.second < b.second;
	});
	std::sort(photos.begin(), photos.end(), [](const auto &a, const auto &b) {
		return a.second < b.second;
	});
	if (docs.empty() && photos.empty()) {
		return;
	}
	const auto done = [weak = base::make_weak(list)] {
		if (const auto strong = weak.get()) {
			strong->clearSelected();
		}
	};
	AddAction(menu, window, std::move(docs), std::move(photos), done);
}

} // namespace Menu
