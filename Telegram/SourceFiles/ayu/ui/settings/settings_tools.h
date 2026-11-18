// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#pragma once

namespace Window {
class SessionController;
} // namespace Window

namespace Settings {

namespace Builder {
class SectionBuilder;
} // namespace Builder

void BuildSleepyTools(Builder::SectionBuilder &builder);
void ShowAccountTransferWizard(not_null<Window::SessionController*> controller);

} // namespace Settings
