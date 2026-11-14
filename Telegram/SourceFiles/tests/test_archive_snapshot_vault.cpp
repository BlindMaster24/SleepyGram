#include "ayu/data/archive_snapshot_vault.h"

#include <cstdio>
#include <cstring>

namespace {

using namespace Ayu::ArchiveSnapshotVault;
using Ayu::ProfileSets::AccountKey;

int failures = 0;

void Check(const char *name, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	failures += !condition;
}

AccountKey Key(quint64 low, char fill) {
	return {
		.id = { 7, low },
		.key = QByteArray(Ayu::ProfileSets::kAccountKeySize, fill),
	};
}

AyuDatabase::ArchiveBackupSnapshot Snapshot(ID owner) {
	auto edited = EditedMessage();
	edited.userId = owner;
	edited.dialogId = 1001;
	edited.peerId = 1001;
	edited.peerType = 1;
	edited.fromId = 2002;
	edited.topicId = 0;
	edited.messageId = 33;
	edited.date = 1'700'000'000;
	edited.editDate = 1'700'000'100;
	edited.flags = 5;
	edited.text = "old revision text";
	auto deleted = DeletedMessage();
	deleted.userId = owner;
	deleted.dialogId = 3003;
	deleted.peerId = 3003;
	deleted.peerType = 2;
	deleted.fromId = 4004;
	deleted.topicId = 0;
	deleted.messageId = 44;
	deleted.date = 1'700'000'200;
	deleted.editDate = 0;
	deleted.flags = 0;
	deleted.text = "deleted text";
	return { .edited = { edited }, .deleted = { deleted } };
}

void RoundTripBindsRowsToOneAccount() {
	const auto key = Key(1, 'A');
	auto error = Error::Malformed;
	const auto sealed = Seal(key, 555, Snapshot(555), &error);
	const auto opened = Open(key, 555, sealed, &error);
	Check("scoped-snapshot-roundtrip", !sealed.isEmpty() && opened
		&& error == Error::None
		&& opened->edited.size() == 1
		&& opened->edited.front().userId == 555
		&& opened->edited.front().text == "old revision text"
		&& opened->deleted.size() == 1
		&& opened->deleted.front().userId == 555
		&& opened->deleted.front().text == "deleted text");

	const auto otherProfileAccount = Open(Key(2, 'B'), 555, sealed, &error);
	Check("different-account-key-id-rejected", !otherProfileAccount
		&& error == Error::WrongAccount);
	auto wrongSecret = key;
	wrongSecret.key.fill('Z');
	const auto wrongKey = Open(wrongSecret, 555, sealed, &error);
	Check("wrong-account-secret-rejected", !wrongKey
		&& error == Error::AuthenticationFailed);
	const auto wrongArchiveAccount = Open(key, 556, sealed, &error);
	Check("different-archive-account-rejected", !wrongArchiveAccount
		&& error == Error::WrongAccount);

	auto tampered = sealed;
	tampered[tampered.size() - 1] = char(tampered.back() ^ 0x01);
	const auto tamperResult = Open(key, 555, tampered, &error);
	Check("tampered-snapshot-authentication-fails", !tamperResult
		&& error == Error::AuthenticationFailed);
}

void StagingRejectsRowsOutsideAllowedScope() {
	auto error = Error::None;
	const auto wrongOwner = Seal(Key(1, 'A'), 555, Snapshot(556), &error);
	Check("staging-rejects-row-owned-by-another-account", wrongOwner.isEmpty()
		&& error == Error::OutsideAccountScope);

	auto invalidKey = Key(1, 'A');
	invalidKey.key = QByteArray(3, 'x');
	const auto invalid = Seal(invalidKey, 555, Snapshot(555), &error);
	Check("invalid-account-key-rejected", invalid.isEmpty()
		&& error == Error::InvalidAccountKey);
}

} // namespace

int main() {
	RoundTripBindsRowsToOneAccount();
	StagingRejectsRowsOutsideAllowedScope();
	return failures ? 1 : 0;
}
