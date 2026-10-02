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

namespace Froxlor\Http;

use Exception;
use Froxlor\Froxlor;

class HttpClient
{
	/**
	 * Executes simple GET request
	 *
	 * @param string $url
	 * @param bool $follow_location
	 * @param int $timeout
	 *
	 * @return bool|string
	 * @throws Exception
	 */
	public static function urlGet(string $url, bool $follow_location = true, int $timeout = 10)
	{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_USERAGENT, 'Froxlor/' . Froxlor::getVersion());
		if ($follow_location) {
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		}
		curl_setopt($ch, CURLOPT_TIMEOUT, (int)$timeout);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$output = curl_exec($ch);
		if ($output === false) {
			$e = curl_error($ch);
			throw new Exception("Curl error: " . $e);
		}
		return $output;
	}

	/**
	 * Downloads and stores a file from an url
	 *
	 * @param string $url
	 * @param string $target
	 *
	 * @return bool|string
	 * @throws Exception
	 */
	public static function fileGet(string $url, string $target)
	{
		$fh = fopen($target, 'w');
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_USERAGENT, 'Froxlor/' . Froxlor::getVersion());
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 50);
		// give curl the file pointer so that it can write to it
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FILE, $fh);
		$output = curl_exec($ch);
		if ($output === false) {
			$e = curl_error($ch);
			throw new Exception("Curl error: " . $e);
		}
		return $output;
	}
}
