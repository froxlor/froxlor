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
use Froxlor\Http\RateLimiter;
use Froxlor\Settings;
use voku\helper\AntiXSS;

class Api
{
	protected array $headers;

	protected $request = null;

	/**
	 * Api constructor.
	 *
	 * @throws Exception
	 */
	public function __construct()
	{
		$this->headers = getallheaders();

		// set header for the response
		header("Accept: application/json");
		header("Content-Type: application/json");

		// check whether API interface is enabled after all
		if (Settings::Get('api.enabled') != 1) {
			throw new Exception('API is not enabled. Please contact the administrator if you think this is wrong.', 400);
		}

		RateLimiter::run();
	}

	/**
	 * @param mixed $request
	 *
	 * @return Api
	 */
	public function formatMiddleware($request): Api
	{
		// check auf RESTful api call
		$this->request = $request;

		$uri = parse_url($_SERVER["REQUEST_URI"], PHP_URL_QUERY);
		// map /module/command to internal request array if match
		if (!empty($uri) && preg_match("/^\/([a-z]+)\/([a-z]+)\/?/", $uri, $matches)) {
			$request = [];
			$request['command'] = ucfirst($matches[1]) . '.' . $matches[2];
			$request['params'] = !empty($this->request) ? json_decode($this->request, true) : null;
			$this->request = json_encode($request);
		}
		return $this;
	}

	/**
	 * Handle incoming api request to our backend.
	 *
	 * @throws Exception
	 */
	public function handle()
	{
		$request = $this->request;
		// validate content
		$request = FroxlorRPC::validateRequest($request);
		$request = (new AntiXSS())->xss_clean(
			$this->stripcslashesDeep($request)
		);

		// now actually do it
		$cls = "\\Froxlor\\Api\\Commands\\" . $request['command']['class'];
		$method = $request['command']['method'];
		$apiObj = new $cls([
			'apikey' => $_SERVER['PHP_AUTH_USER'],
			'secret' => $_SERVER['PHP_AUTH_PW']
		], $request['params']);

		// call the method with the params if any
		return $apiObj->$method();
	}

	/**
	 * API PHP error handler to always return a valid JSON response
	 *
	 * @param mixed $errno
	 * @param mixed $errstr
	 * @param mixed $errfile
	 * @param mixed $errline
	 * @return never
	 */
	public static function phpErrHandler($errno, $errstr, $errfile, $errline)
	{
		throw new Exception('Internal PHP error: #' . $errno . ' ' . $errstr /* . ' in ' . $errfile . ':' . $errline */, 500);
	}

	private function stripcslashesDeep($value)
	{
		return is_array($value) ? array_map([$this, 'stripcslashesDeep'], $value) : (!empty($value) ? stripcslashes($value) : $value);
	}
}
