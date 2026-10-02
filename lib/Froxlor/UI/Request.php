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

namespace Froxlor\UI;

use Froxlor\PhpHelper;
use voku\helper\AntiXSS;

class Request
{
	private static $cleaned = false;

	/**
	 * Get key from current $_GET or $_POST request.
	 *
	 * @param $key
	 * @param mixed|null $default
	 * @return mixed|string|null
	 */
	public static function any($key, $default = null)
	{
		self::cleanAll();

		return $_GET[$key] ?? $_POST[$key] ?? $default;
	}

	/**
	 * Get key from current $_GET request.
	 *
	 * @param $key
	 * @param mixed|null $default
	 * @return mixed|string|null
	 */
	public static function get($key, $default = null)
	{
		self::cleanAll();

		return $_GET[$key] ?? $default;
	}

	/**
	 * Get key from current $_POST request.
	 *
	 * @param $key
	 * @param mixed|null $default
	 * @return mixed|string|null
	 */
	public static function post($key, $default = null)
	{
		self::cleanAll();

		return $_POST[$key] ?? $default;
	}

	/**
	 * return complete $_POST array
	 *
	 * @return array
	 */
	public static function postAll()
	{
		self::cleanAll();

		return $_POST ?? [];
	}

	/**
	 * Check for xss attempts and clean important globals and
	 * unsetting every variable registered in $_REQUEST and as variable itself
	 */
	public static function cleanAll()
	{
		if (!self::$cleaned) {
			foreach ($_REQUEST as $key => $value) {
				if (isset($$key)) {
					unset($$key);
				}
			}
			unset($value);

			$antiXss = new AntiXSS();
			$antiXss->addNeverAllowedRegex([
				'{{(.*)}}' => ''
			]);

			// check $_GET
			PhpHelper::cleanGlobal($_GET, $antiXss);
			// check $_POST
			PhpHelper::cleanGlobal($_POST, $antiXss);
			// check $_COOKIE
			PhpHelper::cleanGlobal($_COOKIE, $antiXss);

			self::$cleaned = true;
		}
	}

	/**
	 * Check if key is existing in current request.
	 *
	 * @param $key
	 * @return bool|mixed
	 */
	public static function exist($key)
	{
		return (bool)$_GET[$key] ?? $_POST[$key] ?? false;
	}
}
