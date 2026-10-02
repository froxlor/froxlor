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

use Froxlor\PhpHelper;
use Froxlor\Settings;

class Email
{
	public static function account(array $attributes)
	{
		return [
			'macro' => 'booleanWithInfo',
			'data' => [
				'checked' => $attributes['data'] != 0,
				'info' => $attributes['data'] != 0 ? PhpHelper::sizeReadable($attributes['fields']['mboxsize'], 'GiB', 'bi', '%01.' . (int)Settings::Get('panel.decimal_places') . 'f %s') : ''
			]
		];
	}

	public static function forwarderList(array $attributes)
	{
		$forwarders = explode(" ", $attributes['data']);
		if (($key = array_search($attributes['fields']['email_full'], $forwarders)) !== false) {
			unset($forwarders[$key]);
		}
		if (count($forwarders) > 0) {
			return implode("<br>", $forwarders);
		}
		return "";
	}
}
