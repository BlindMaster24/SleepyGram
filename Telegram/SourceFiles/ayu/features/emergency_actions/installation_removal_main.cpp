// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/installation_removal_handoff.h"

#include <limits>
#include <string_view>

namespace {

using namespace Ayu::EmergencyActions;

template <typename Character>
std::optional<uint64_t> Number(std::basic_string_view<Character> value) {
	auto number = uint64_t(0);
	if (value.empty()) {
		return std::nullopt;
	}
	for (const auto ch : value) {
		if (ch < Character('0') || ch > Character('9')) {
			return std::nullopt;
		}
		const auto digit = uint64_t(ch - Character('0'));
		if (number > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
			return std::nullopt;
		}
		number = 10 * number + digit;
	}
	return number;
}

template <typename Character>
InstallationId Id(std::basic_string_view<Character> value) {
	if (value.size() > 128) {
		return {};
	}
	auto text = std::string();
	for (const auto ch : value) {
		if (ch < Character(32) || ch > Character(126)) {
			return {};
		}
		text.push_back(char(ch));
	}
	return InstallationId(std::move(text));
}

template <typename Character>
int RunHelper(
		std::basic_string_view<Character> installation,
		std::basic_string_view<Character> delay,
		InstallationRemovalProcessHandle parent) {
	const auto duration = Number(delay);
	return int((duration && *duration && *duration <= 300'000)
		? RunInstallationRemovalHandoff(
			Id(installation), parent, std::chrono::milliseconds(*duration), true)
		: InstallationRemovalResult::TicketRejected);
}

} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
	if (argc != 4) {
		return int(InstallationRemovalResult::TicketRejected);
	}
	const auto parent = Number(std::wstring_view(argv[3]));
	return (parent && *parent && *parent <= std::numeric_limits<uintptr_t>::max())
		? RunHelper(std::wstring_view(argv[1]), std::wstring_view(argv[2]), { uintptr_t(*parent) })
		: int(InstallationRemovalResult::TicketRejected);
}
#else
int main(int argc, char **argv) {
	return (argc == 3)
		? RunHelper(std::string_view(argv[1]), std::string_view(argv[2]), {})
		: int(InstallationRemovalResult::TicketRejected);
}
#endif
