#!/usr/bin/env python3
"""Compile and exercise the production macOS permission wrapper in isolation."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Telegram/SourceFiles/platform/mac/specific_mac.mm"
MARKER = (
    "void RequestPermission(PermissionType type, "
    "Fn<void(PermissionStatus)> resultCallback) {"
)


def extract_request_permission(source: str) -> str:
    start = source.find(MARKER)
    if start < 0:
        raise RuntimeError("RequestPermission definition not found")

    opening = source.find("{", start)
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[start:offset + 1]
    raise RuntimeError("RequestPermission definition is unterminated")


HARNESS = r"""
#import <Foundation/Foundation.h>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

enum class PermissionStatus { Granted, CanRequest, Denied };
enum class PermissionType { Microphone, Camera };
template <typename T> using Fn = std::function<T>;
using AVMediaType = const char *;
static constexpr auto AVMediaTypeAudio = "audio";
static constexpr auto AVMediaTypeVideo = "video";
static bool gAvailable = true;
static bool gGranted = true;
static int gRequests = 0;
static AVMediaType gRequestedType = nullptr;
static std::vector<std::function<void()>> gMainQueue;

namespace crl {
template <typename Callback>
void on_main(Callback callback) {
	gMainQueue.push_back(std::move(callback));
}
} // namespace crl

@interface AVCaptureDevice : NSObject
+ (BOOL)respondsToSelector:(SEL)selector;
+ (void)requestAccessForMediaType:(AVMediaType)type completionHandler:(void (^)(BOOL))handler;
@end

@implementation AVCaptureDevice
+ (BOOL)respondsToSelector:(SEL)selector {
	return gAvailable;
}

+ (void)requestAccessForMediaType:(AVMediaType)type completionHandler:(void (^)(BOOL))handler {
	++gRequests;
	gRequestedType = type;
	handler(gGranted);
}
@end

void RequestPermission(PermissionType type, Fn<void(PermissionStatus)> resultCallback);

void Check(bool condition, const char *message) {
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		std::exit(1);
	}
}

void RunCase(
		const char *name,
		PermissionType type,
		bool apiAvailable,
		bool granted,
		PermissionStatus expected,
		const char *expectedMediaType) {
	gAvailable = apiAvailable;
	gGranted = granted;
	gRequests = 0;
	gRequestedType = nullptr;
	gMainQueue.clear();
	auto results = std::vector<PermissionStatus>();

	RequestPermission(type, [&](PermissionStatus result) {
		results.push_back(result);
	});
	if (apiAvailable) {
		Check(results.empty(), name);
		Check(gRequests == 1, "native request count");
		Check(std::string(gRequestedType) == expectedMediaType, "native media type");
	} else {
		Check(results.size() == 1, "legacy fallback callback count");
		Check(results.front() == PermissionStatus::Granted, "legacy fallback result");
		Check(gRequests == 0, "legacy fallback native request count");
	}

	auto callbacks = std::move(gMainQueue);
	gMainQueue.clear();
	for (const auto &callback : callbacks) {
		callback();
	}
	Check(results.size() == 1, name);
	Check(results.front() == expected, name);
	std::cout << "PASS: " << name << '\n';
}

"""

SUFFIX = r"""
int main() {
	RunCase("microphone grant", PermissionType::Microphone, true, true,
		PermissionStatus::Granted, "audio");
	RunCase("microphone denial", PermissionType::Microphone, true, false,
		PermissionStatus::Denied, "audio");
	RunCase("camera grant", PermissionType::Camera, true, true,
		PermissionStatus::Granted, "video");
	RunCase("camera denial", PermissionType::Camera, true, false,
		PermissionStatus::Denied, "video");
	RunCase("microphone legacy fallback", PermissionType::Microphone, false, false,
		PermissionStatus::Granted, "audio");
	RunCase("camera legacy fallback", PermissionType::Camera, false, false,
		PermissionStatus::Granted, "video");
}
"""


def main() -> int:
    if sys.platform != "darwin":
        print("SKIP: this isolated Objective-C++ test requires macOS")
        return 0
    compiler = shutil.which("clang++")
    if not compiler:
        raise RuntimeError("clang++ is required")

    function = extract_request_permission(SOURCE.read_text())
    with tempfile.TemporaryDirectory(prefix="mac-permission-test-") as directory:
        directory = Path(directory)
        harness = directory / "test.mm"
        binary = directory / "test"
        harness.write_text(HARNESS + function + SUFFIX)
        subprocess.run([
            compiler,
            "-std=c++20",
            "-fblocks",
            "-framework",
            "Foundation",
            str(harness),
            "-o",
            str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)
    return 0


if __name__ == "__main__":
	raise SystemExit(main())
