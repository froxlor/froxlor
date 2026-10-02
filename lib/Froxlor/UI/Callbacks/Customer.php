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

namespace Froxlor\UI\Callbacks;

use Froxlor\Settings;
use Froxlor\System\Markdown;

class Customer
{
	public static function isLocked(array $attributes): bool
	{
		return $attributes['fields']['loginfail_count'] >= Settings::Get('login.maxloginattempts')
			&& $attributes['fields']['lastlogin_fail'] > (time() - Settings::Get('login.deactivatetime'));
	}

	public static function hasNote(array $attributes): bool
	{
		$cleanNote = Markdown::cleanCustomNotes($attributes['fields']['custom_notes'] ?? "");
		return !empty($cleanNote);
	}
}
