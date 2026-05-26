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

namespace Froxlor\Api;

class Response
{
	public static function jsonDataResponse($data = null, int $response_code = 200)
	{
		return self::jsonResponse(['data' => $data], $response_code);
	}

	public static function jsonResponse($data = null, int $response_code = 200)
	{
		if (!defined('TRAVIS_CI') || TRAVIS_CI == 0) {
			// Only set HTTP headers if not in CLI mode (e.g., PHPUnit tests)
			if (php_sapi_name() !== 'cli') {
				http_response_code($response_code);
			}
		}

		return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
	}

	public static function jsonErrorResponse($message = null, int $response_code = 400)
	{
		return self::jsonResponse(['message' => $message], $response_code);
	}
}
