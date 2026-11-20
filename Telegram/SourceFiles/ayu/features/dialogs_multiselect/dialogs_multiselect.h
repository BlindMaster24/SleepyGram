#pragma once

#include "base/basic_types.h"
#include "base/required.h"

#include <vector>

class History;

namespace Ui {
class PopupMenu;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace Ayu::DialogsMultiSelect {

void FillMultiDialogsMenu(
	not_null<Window::SessionController*> controller,
	not_null<Ui::PopupMenu*> menu,
	std::vector<not_null<History*>> histories,
	Fn<void()> onDone);

} // namespace Ayu::DialogsMultiSelect
