// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/scoped_account_clear.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <WebKit/WKWebsiteDataStore.h>

#include <dispatch/dispatch.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace Ayu::EmergencyActions {
namespace {

using Clock = std::chrono::steady_clock;
constexpr auto kDeadline = std::chrono::seconds(8);

NSData *Digest(std::span<const uint8_t> input) {
	auto result = std::array<uint8_t, 32>();
	auto size = unsigned(0);
	return (EVP_Digest(input.data(), input.size(), result.data(), &size,
			EVP_sha256(), nullptr) == 1 && size == result.size())
		? [NSData dataWithBytes:result.data() length:result.size()]
		: nil;
}

NSDictionary *ReceiptQuery(
		const InstallationId &installation,
		const OperationId &operation,
		std::string_view admission,
		const std::filesystem::path &root) {
	auto error = std::error_code();
	if (!installation.valid() || !operation.valid()
		|| admission.size() != 32 || !std::ranges::all_of(admission, [](char c) {
			return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
		})
		|| !root.is_absolute() || root.native().find('\0') != std::string::npos
		|| std::filesystem::canonical(root, error) != root || error) {
		return nil;
	}
	struct stat directory = {};
	if (lstat(root.c_str(), &directory) != 0 || !S_ISDIR(directory.st_mode)) {
		return nil;
	}
	const auto volume = std::to_string(directory.st_dev);
	const auto inode = std::to_string(directory.st_ino);
	auto name = std::string("SleepyGram macOS scoped WebView cleanup receipt v1");
	for (const auto part : { std::string_view(root.native()), std::string_view(volume),
			std::string_view(inode), std::string_view(installation.value),
			std::string_view(operation.value), admission }) {
		name += '\0';
		name += std::to_string(part.size());
		name += '\0';
		name += part;
	}
	const auto account = [Digest({ reinterpret_cast<const uint8_t*>(name.data()), name.size() })
		base64EncodedStringWithOptions:0];
	if (!account) {
		return nil;
	}
	return @{
		(id)kSecClass: (id)kSecClassGenericPassword,
		(id)kSecAttrService: @"com.sleepygram.desktop.scoped-webview-cleanup",
		(id)kSecAttrAccount: account,
		(id)kSecUseDataProtectionKeychain: @NO,
	};
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

struct KeychainHandle final {
	SecKeychainRef value = nullptr;
	~KeychainHandle() {
		if (value) {
			CFRelease(value);
		}
	}
};

class KeychainInteraction final {
public:
	[[nodiscard]] bool suspend() {
		auto enabled = Boolean(false);
		if (SecKeychainGetUserInteractionAllowed(&enabled) != errSecSuccess) {
			return false;
		} else if (!enabled) {
			return true;
		}
		_restore = (SecKeychainSetUserInteractionAllowed(false) == errSecSuccess);
		return _restore;
	}

	[[nodiscard]] bool restore() {
		if (_restore && SecKeychainSetUserInteractionAllowed(true) != errSecSuccess) {
			return false;
		}
		_restore = false;
		return true;
	}

	~KeychainInteraction() {
		if (_restore && SecKeychainSetUserInteractionAllowed(true) == errSecSuccess) {
			_restore = false;
		}
	}

private:
	bool _restore = false;

};

[[nodiscard]] bool KeychainPathMatches(
		SecKeychainRef keychain,
		const std::filesystem::path &path) {
	auto buffer = std::vector<char>(path.native().size() + 1);
	auto length = UInt32(buffer.size());
	return keychain && SecKeychainGetPath(keychain, &length, buffer.data()) == errSecSuccess
		&& std::string_view(buffer.data(), length) == path.native();
}

template <typename Callback>
bool WithLoginKeychain(
		const std::filesystem::path &dataRoot,
		bool adding,
		Callback &&callback) {
	if ([NSThread isMainThread]) {
		return false;
	}
	auto error = std::error_code();
	const auto home = [NSHomeDirectory() fileSystemRepresentation];
	const auto canonicalHome = home ? std::filesystem::canonical(home, error) : std::filesystem::path();
	if (canonicalHome.empty() || error) {
		return false;
	}
	const auto path = canonicalHome / "Library" / "Keychains" / "login.keychain-db";
	const auto relativeToData = path.lexically_relative(dataRoot);
	struct stat file = {};
	if (std::filesystem::canonical(path, error) != path || error
		|| lstat(path.c_str(), &file) != 0 || !S_ISREG(file.st_mode)
		|| file.st_uid != geteuid() || file.st_nlink != 1
		|| (!relativeToData.empty() && *relativeToData.begin() != "..")) {
		return false;
	}
	static auto mutex = std::mutex();
	const auto lock = std::lock_guard(mutex);
	auto interaction = KeychainInteraction();
	if (!interaction.suspend()) {
		return false;
	}
	auto login = KeychainHandle();
	auto status = SecKeychainStatus();
	if (SecKeychainOpen(path.c_str(), &login.value) != errSecSuccess
		|| !KeychainPathMatches(login.value, path)
		|| SecKeychainGetStatus(login.value, &status) != errSecSuccess
		|| !(status & kSecUnlockStateStatus) || !(status & kSecReadPermStatus)) {
		return false;
	}
	if (adding) {
		auto defaultKeychain = KeychainHandle();
		if (!(status & kSecWritePermStatus)
			|| SecKeychainCopyDefault(&defaultKeychain.value) != errSecSuccess
			|| !KeychainPathMatches(defaultKeychain.value, path)) {
			return false;
		}
	}
	const auto result = callback(login.value, path);
	return interaction.restore() && result;
}

bool AddReceipt(
		NSDictionary *query,
		NSData *digest,
		SecKeychainRef keychain,
		const std::filesystem::path &path) {
	const auto input = [NSMutableDictionary dictionaryWithDictionary:query];
	input[(id)kSecUseKeychain] = (id)keychain;
	input[(id)kSecValueData] = digest;
	input[(id)kSecReturnRef] = @YES;
	auto item = CFTypeRef(nullptr);
	const auto status = SecItemAdd((CFDictionaryRef)input, &item);
	auto result = (status == errSecDuplicateItem);
	if (item) {
		if (status == errSecSuccess && CFGetTypeID(item) == SecKeychainItemGetTypeID()) {
			const auto created = (SecKeychainItemRef)item;
			auto owner = KeychainHandle();
			result = SecKeychainItemCopyKeychain(created, &owner.value) == errSecSuccess
				&& KeychainPathMatches(owner.value, path);
			if (!result && SecKeychainItemDelete(created) != errSecSuccess) {
				result = false;
			}
		}
		CFRelease(item);
	}
	return result;
}

#pragma clang diagnostic pop

bool VerifyReceipt(NSDictionary *query, NSData *digest) {
	const auto lookup = [NSMutableDictionary dictionaryWithDictionary:query];
	lookup[(id)kSecReturnData] = @YES;
	lookup[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
	auto value = CFTypeRef(nullptr);
	const auto status = SecItemCopyMatching((CFDictionaryRef)lookup, &value);
	const auto matches = (status == errSecSuccess) && value
		&& (CFGetTypeID(value) == CFDataGetTypeID())
		&& [digest isEqualToData:(NSData*)value];
	if (value) {
		CFRelease(value);
	}
	return matches;
}

enum class ReceiptOperation { Bind, Verify, Retire };

bool ManageReceipt(
		ReceiptOperation action,
		const InstallationId &installation,
		const OperationId &operation,
		std::string_view admission,
		const std::filesystem::path &dataRoot,
		std::span<const uint8_t> encodedReceipt) {
	if (encodedReceipt.empty()) {
		return false;
	}
	@autoreleasepool {
		const auto query = ReceiptQuery(installation, operation, admission, dataRoot);
		const auto digest = Digest(encodedReceipt);
		return query && digest && WithLoginKeychain(dataRoot, action == ReceiptOperation::Bind,
			[&](SecKeychainRef keychain, const std::filesystem::path &path) {
				const auto scope = [NSMutableDictionary dictionaryWithDictionary:query];
				scope[(id)kSecMatchSearchList] = @[ (id)keychain ];
				if (action == ReceiptOperation::Bind && !AddReceipt(query, digest, keychain, path)) {
					return false;
				}
				return VerifyReceipt(scope, digest)
					&& (action != ReceiptOperation::Retire
						|| SecItemDelete((CFDictionaryRef)scope) == errSecSuccess);
			});
	}
}

class NamedCleanup final {
public:
	explicit NamedCleanup(std::span<const ScopedWebviewStoreId> ids)
	: ids(ids.begin(), ids.end()) {
	}

	[[nodiscard]] bool active() const {
		const auto lock = std::lock_guard(_mutex);
		return !_result && Clock::now() < _deadline;
	}

	void finish(EffectResult result) {
		const auto lock = std::lock_guard(_mutex);
		if (!_result && Clock::now() < _deadline) {
			_result = result;
			_done.notify_one();
		}
	}

	[[nodiscard]] EffectResult wait() {
		auto lock = std::unique_lock(_mutex);
		if (!_done.wait_until(lock, _deadline, [&] { return _result.has_value(); })) {
			_result = EffectResult::Unconfirmed;
		}
		return *_result;
	}

	const ScopedWebviewStoreIds ids;

private:
	const Clock::time_point _deadline = Clock::now() + kDeadline;
	mutable std::mutex _mutex;
	std::condition_variable _done;
	std::optional<EffectResult> _result;

};

NSUUID *ToUuid(const ScopedWebviewStoreId &id) {
	return [[[NSUUID alloc] initWithUUIDBytes:id.data()] autorelease];
}

API_AVAILABLE(macos(14.0))
void RemoveNext(std::shared_ptr<NamedCleanup> work, uint8_t pending, size_t next) {
	if (!work->active()) {
		return;
	}
	while (next != work->ids.size() && !(pending & (1U << next))) {
		++next;
	}
	if (next == work->ids.size()) {
		[WKWebsiteDataStore fetchAllDataStoreIdentifiers:^(NSArray<NSUUID*> *present) {
			const auto absent = present && std::ranges::none_of(work->ids, [&](const auto &id) {
				return [present containsObject:ToUuid(id)];
			});
			work->finish(absent ? EffectResult::ConfirmedSuccess : EffectResult::ConfirmedFailure);
		}];
		return;
	}
	[WKWebsiteDataStore removeDataStoreForIdentifier:ToUuid(work->ids[next])
		completionHandler:^(NSError *error) {
			if (error) {
				work->finish(EffectResult::ConfirmedFailure);
			} else {
				dispatch_async(dispatch_get_main_queue(), ^{
					RemoveNext(work, pending, next + 1);
				});
			}
		}];
}

void StartCleanup(const std::shared_ptr<NamedCleanup> &work) {
	if (!work->active()) {
		return;
	}
	if (@available(macOS 14.0, *)) {
		@try {
			@autoreleasepool {
				const auto store = [WKWebsiteDataStore nonPersistentDataStore];
				if (!store || store.isPersistent) {
					work->finish(EffectResult::ConfirmedFailure);
					return;
				}
				[WKWebsiteDataStore fetchAllDataStoreIdentifiers:^(NSArray<NSUUID*> *present) {
					if (!present) {
						work->finish(EffectResult::ConfirmedFailure);
						return;
					}
					auto pending = uint8_t(0);
					for (auto i = size_t(0); i != work->ids.size(); ++i) {
						if ([present containsObject:ToUuid(work->ids[i])]) {
							pending |= uint8_t(1U << i);
						}
					}
					RemoveNext(work, pending, 0);
				}];
			}
		} @catch (NSException *) {
			work->finish(EffectResult::ConfirmedFailure);
		}
	} else {
		work->finish(EffectResult::ConfirmedFailure);
	}
}

} // namespace

bool BindMacScopedWebviewRecoveryReceipt(
		const InstallationId &installation,
		const OperationId &operation,
		std::string_view admissionGeneration,
		const std::filesystem::path &dataRoot,
		std::span<const uint8_t> encodedReceipt) {
	return ManageReceipt(ReceiptOperation::Bind,
		installation, operation, admissionGeneration, dataRoot, encodedReceipt);
}

bool VerifyMacScopedWebviewRecoveryReceipt(
		const InstallationId &installation,
		const OperationId &operation,
		std::string_view admissionGeneration,
		const std::filesystem::path &dataRoot,
		std::span<const uint8_t> encodedReceipt) {
	return ManageReceipt(ReceiptOperation::Verify,
		installation, operation, admissionGeneration, dataRoot, encodedReceipt);
}

bool RetireMacScopedWebviewRecoveryReceipt(
		const InstallationId &installation,
		const OperationId &operation,
		std::string_view admissionGeneration,
		const std::filesystem::path &dataRoot,
		std::span<const uint8_t> encodedReceipt) {
	return ManageReceipt(ReceiptOperation::Retire,
		installation, operation, admissionGeneration, dataRoot, encodedReceipt);
}

EffectResult ClearMacScopedWebviewStores(std::span<const ScopedWebviewStoreId> ids) {
	if (ids.empty()) {
		return EffectResult::ConfirmedSuccess;
	} else if ([NSThread isMainThread] || !ValidScopedWebviewStoreIds(ids)) {
		return EffectResult::ConfirmedFailure;
	}
	const auto work = std::make_shared<NamedCleanup>(ids);
	dispatch_async(dispatch_get_main_queue(), ^{
		StartCleanup(work);
	});
	return work->wait();
}

} // namespace Ayu::EmergencyActions
