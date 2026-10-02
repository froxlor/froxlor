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

use Exception;
use Froxlor\Database\Database;
use Froxlor\System\IPTools;

class FroxlorRPC
{
	/**
	 * validate a given request
	 *
	 * @param $request
	 * @return array
	 * @throws Exception
	 */
	public static function validateRequest($request): array
	{
		// make basic authentication
		if (!isset($_SERVER['PHP_AUTH_USER']) || !self::validateAuth($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
			if (@php_sapi_name() !== 'cli') {
				header('WWW-Authenticate: Basic realm="API"');
			}
			throw new Exception('Unauthenticated. Please provide api user credentials.', 401);
		}

		// check if present
		if (empty($request)) {
			throw new Exception('Empty request body.', 400);
		}

		// decode json request
		$decoded_request = json_decode($request, true);

		// is it valid?
		if (is_null($decoded_request)) {
			throw new Exception('Invalid JSON Format.', 400);
		}

		return self::validateBody($decoded_request);
	}

	/**
	 * validates the given api credentials
	 *
	 * @param string $key
	 * @param string $secret
	 *
	 * @return bool
	 */
	private static function validateAuth(string $key, string $secret): bool
	{
		$sel_stmt = Database::prepare(
			"
			SELECT ak.*, a.api_allowed as admin_api_allowed, c.api_allowed as cust_api_allowed, c.deactivated
			FROM `api_keys` ak
			LEFT JOIN `panel_admins` a ON a.adminid = ak.adminid
			LEFT JOIN `panel_customers` c ON c.customerid = ak.customerid
			WHERE `apikey` = :ak AND `secret` = :as
		"
		);
		$result = Database::pexecute_first($sel_stmt, [
			'ak' => $key,
			'as' => $secret
		], true, true);
		if ($result) {
			if ($result['apikey'] == $key && $result['secret'] == $secret && ($result['valid_until'] == -1 || $result['valid_until'] >= time()) && (($result['customerid'] == 0 && $result['admin_api_allowed'] == 1) || ($result['customerid'] > 0 && $result['cust_api_allowed'] == 1 && $result['deactivated'] == 0))) {
				// get user to check whether api call is allowed
				if (!empty($result['allowed_from'])) {
					// @todo allow specification and validating of whole subnets later
					$ip_list = explode(",", $result['allowed_from']);
					if (self::validateAllowedFrom($ip_list, $_SERVER['REMOTE_ADDR'])) {
						return true;
					}
				} else {
					return true;
				}
			}
		}
		throw new Exception('Invalid authorization credentials', 403);
	}

	/**
	 * validate if given remote_addr is within the list of allowed ip/ip-ranges
	 *
	 * @param array $allowed_from
	 * @param string $remote_addr
	 *
	 * @return bool
	 */
	public static function validateAllowedFrom(array $allowed_from, string $remote_addr): bool
	{
		// shorten IP for comparison
		$remote_addr = inet_ntop(inet_pton($remote_addr));
		// check for direct matches
		if (in_array($remote_addr, $allowed_from)) {
			return true;
		}
		// check for possible cidr ranges
		foreach ($allowed_from as $ip) {
			$ip_cidr = explode("/", $ip);
			if (count($ip_cidr) == 2 && IPTools::ip_in_range($ip_cidr, $remote_addr)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * validates the given command
	 *
	 * @param array $request
	 *
	 * @return array
	 * @throws Exception
	 */
	private static function validateBody($request)
	{
		// check command exists
		if (empty($request['command'])) {
			throw new Exception("Please provide a command.", 400);
		}

		$command = explode(".", $request['command']);

		if (count($command) != 2) {
			throw new Exception("The given command is invalid.", 400);
		}
		// simply check for file-existance, as we do not want to use our autoloader because this way
		// it will recognize non-api classes+methods as valid commands
		$apiclass = '\\Froxlor\\Api\\Commands\\' . $command[0];
		if (!class_exists($apiclass) || !@method_exists($apiclass, $command[1])) {
			throw new Exception("Unknown command", 400);
		}
		return [
			'command' => [
				'class' => $command[0],
				'method' => $command[1]
			],
			'params' => $request['params'] ?? null
		];
	}
}
