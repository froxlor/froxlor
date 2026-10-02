<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */

namespace Froxlor\Settings;

use Froxlor\Database\Database;

class FroxlorVhostSettings
{

	/**
	 * @param bool $need_ssl
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public static function hasVhostContainerEnabled(bool $need_ssl = false): bool
	{
		$sel_stmt = Database::prepare("SELECT COUNT(*) as vcentries FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `vhostcontainer`= '1'" . ($need_ssl ? " AND `ssl` = '1'" : ""));
		$result = Database::pexecute_first($sel_stmt);
		if ($result) {
			return $result['vcentries'] > 0;
		}
		return false;
	}
}
