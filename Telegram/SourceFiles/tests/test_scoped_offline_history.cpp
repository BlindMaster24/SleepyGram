// This is the source code of AyuGram for Desktop.
#include "ayu/features/offline_history/offline_history_scoped.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/details/storage_native_path.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>

namespace {

using namespace Ayu::OfflineHistory;
using namespace Ayu::OfflineHistory::Storage;

constexpr auto kOwner = quint64(901);
constexpr auto kPeer = PeerId(77);
constexpr auto kQuota = qint64(16 * 1024 * 1024);
int Failures = 0;

void Check(bool passed, const char *name) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
	Failures += !passed;
}

MTP::AuthKeyPtr Key(int fill) {
	auto data = MTP::AuthKey::Data();
	data.fill(gsl::byte(fill));
	return std::make_shared<MTP::AuthKey>(data);
}

QByteArray Read(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

bool Write(const QString &path, const QByteArray &bytes) {
	auto file = QFile(path);
	return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size();
}

struct Fixture final {
	QTemporaryDir directory;
	QString profile = QDir(directory.path()).canonicalPath();
	std::array<ScopedOfflineAccount, 2> scopes{
		ScopedOfflineAccount{ kOwner, profile + u"/profile-sets/accounts/"_q + QString(32, 'a'), Key(1) },
		ScopedOfflineAccount{ 902, profile + u"/profile-sets/accounts/"_q + QString(32, 'b'), Key(2) },
	};
	Paths legacy = PathsFor(profile + u"/offline-history"_q, kOwner, kPeer);
	Paths scoped;
	Attachment attachment{
		.messageId = MsgId(8),
		.mediaId = 123,
		.photo = false,
		.name = u"notes.txt"_q,
		.fileName = u"m-8-d-123.txt"_q,
		.size = 7,
		.sourceSize = 7,
	};
	QByteArray body = QByteArray("content");
	QByteArray complete;
	QByteArray partial;
	QByteArray manifest;

	bool setup() {
		if (!directory.isValid() || !QDir().mkpath(scopes[0].accountRoot)
			|| !QDir().mkpath(scopes[1].accountRoot)
			|| !QDir().mkpath(legacy.attachmentDirectory)) {
			return false;
		}
		scoped = ScopedPathsFor(scopes[0], kPeer);
		auto snapshot = Snapshot{
			.from = 1700000000,
			.to = 1700000007,
			.nextOffset = 7,
			.pages = 1,
			.messages = { {
				.id = MsgId(8),
				.date = TimeId(1700000001),
				.sender = u"sender"_q,
				.text = u"saved private history"_q,
			} },
		};
		complete = Serialize(snapshot, kOwner, kPeer);
		snapshot.nextOffset = 2;
		partial = Serialize(snapshot, kOwner, kPeer);
		manifest = SerializeAttachments({ attachment }, kOwner, kPeer);
		return !scoped.root.isEmpty()
			&& Write(legacy.complete, complete)
			&& Write(legacy.partial, partial)
			&& Write(legacy.attachmentManifest, manifest)
			&& Write(legacy.attachmentDirectory + '/' + attachment.fileName, body);
	}

	std::optional<OfflineRetirementInventory> stage() const {
		return StageLegacyOfflineHistory(profile, scopes);
	}
};

void CheckRoundTrip() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "temporary offline history fixture setup");
		return;
	}
	const auto plan = fixture.stage();
	Check(plan && plan->size() == 8, "proof enumerates exact source root, directories and all four files");
	if (!plan) {
		return;
	}
	const auto &scope = fixture.scopes[0];
	const auto &path = fixture.scoped;
	const auto oldAttachment = fixture.legacy.attachmentDirectory + '/' + fixture.attachment.fileName;
	const auto newAttachment = ScopedAttachmentPath(scope, path, fixture.attachment);
	Check(ReadScopedFile(scope, path.complete) == fixture.complete
		&& ReadScopedFile(scope, path.partial) == fixture.partial,
		"completed and resumable snapshots survive encrypted readback");
	Check(ReadScopedFile(scope, path.attachmentManifest) == fixture.manifest
		&& ReadScopedFile(scope, newAttachment) == fixture.body
		&& ScopedFilePresent(scope, newAttachment, fixture.body.size()),
		"manifest and payload both survive encrypted readback");
	Check(!Read(path.complete).contains("saved private history")
		&& !newAttachment.contains(fixture.attachment.fileName)
		&& !path.complete.contains(u"/77/"_q),
		"scoped disk filenames and record contents do not expose message IDs or plaintext");
	Check(Read(fixture.legacy.complete) == fixture.complete
		&& Read(fixture.legacy.partial) == fixture.partial
		&& Read(fixture.legacy.attachmentManifest) == fixture.manifest
		&& Read(oldAttachment) == fixture.body,
		"legacy records remain byte-identical before cutover");
	const auto sourceDigest = QCryptographicHash::hash(fixture.complete, QCryptographicHash::Sha256);
	Check(std::ranges::any_of(*plan, [&](const auto &entry) {
		return entry.relativePath == u"offline-history/901/77/history.json"_q
			&& entry.sha256 == sourceDigest;
	}), "retirement receipt binds exact legacy content");
	const auto before = Read(path.complete);
	Check(fixture.stage() && Read(path.complete) == before, "replay preserves already verified scoped ciphertext");
	auto wrong = scope;
	wrong.key = fixture.scopes[1].key;
	Check(!ReadScopedFile(wrong, path.complete)
		&& !ReadScopedFile(fixture.scopes[1], path.complete),
		"wrong key and other granted account are refused");
	const auto otherPeer = ScopedPathsFor(scope, PeerId(78));
	Check(QDir().mkpath(QFileInfo(otherPeer.complete).path())
		&& QFile::copy(path.complete, otherPeer.complete)
		&& !ReadScopedFile(scope, otherPeer.complete),
		"moving ciphertext to another peer or purpose fails authentication");
	Check(RemoveScopedPeer(scope, path)
		&& QFileInfo::exists(otherPeer.complete)
		&& QFileInfo::exists(fixture.legacy.complete),
		"explicit scoped deletion does not touch other peers or legacy");
}

void CheckRefusals() {
	auto fixture = Fixture();
	if (!fixture.setup()) {
		Check(false, "temporary refusal fixture setup");
		return;
	}
	const auto unknown = QFileInfo(fixture.legacy.complete).path() + u"/.unknown"_q;
	Check(!StageLegacyOfflineHistory(fixture.profile, std::span(fixture.scopes).subspan(1))
		&& !QFileInfo::exists(fixture.scoped.root),
		"source owners must appear in the authenticated input");
	Check(Write(unknown, "sensitive extra") && !fixture.stage()
		&& !QFileInfo::exists(fixture.scoped.root) && QFile::remove(unknown),
		"any extra source file blocks staging before scoped writes");
	const auto source = fixture.legacy.attachmentDirectory + '/' + fixture.attachment.fileName;
	Check(QFile::remove(source) && !fixture.stage() && !QFileInfo::exists(fixture.scoped.root),
		"manifest references must all be present");
	Check(Write(source, fixture.body), "restore temporary attachment");
#if !defined Q_OS_WIN
	const auto elsewhere = fixture.profile + u"/unrelated.bin"_q;
	auto error = std::error_code();
	if (QFile::rename(source, elsewhere)) {
		std::filesystem::create_symlink(
			::Storage::NativeFilePath(QFileInfo(elsewhere).filePath()),
			::Storage::NativeFilePath(QFileInfo(source).filePath()),
			error);
		Check(!error && !fixture.stage() && Read(elsewhere) == fixture.body,
			"symbolic link cannot bring unrelated files into offline receipt");
		Check(QFile::remove(source) && QFile::rename(elsewhere, source),
			"restore exact regular attachment after link fixture");
	} else {
		Check(false, "create isolated attachment link fixture");
	}
#endif
	Check(Write(fixture.legacy.partial, fixture.partial + ' ') && !fixture.stage(),
		"noncanonical source cannot normalize unknown data away");
	Check(Write(fixture.legacy.partial, fixture.partial) && fixture.stage(), "valid retry is staged");
	auto tampered = Read(fixture.scoped.complete);
	tampered[tampered.size() - 1] = char(tampered.back() ^ 1);
	Check(Write(fixture.scoped.complete, tampered)
		&& !ReadScopedFile(fixture.scopes[0], fixture.scoped.complete)
		&& !fixture.stage()
		&& !WriteScopedFile(fixture.scopes[0], fixture.scoped.complete, fixture.complete, kQuota)
		&& Read(fixture.scoped.complete) == tampered,
		"tampered scoped file blocks replay and remains intact");
	Check(!WriteScopedFile(
		fixture.scopes[0], fixture.legacy.partial, fixture.partial, kQuota),
		"runtime writer cannot address the legacy tree");
}

} // namespace

int main(int argc, char *argv[]) {
	const auto app = QCoreApplication(argc, argv);
	CheckRoundTrip();
	CheckRefusals();
	return Failures ? 1 : 0;
}
