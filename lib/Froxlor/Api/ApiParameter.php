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

abstract class ApiParameter
{

	/**
	 * array of parameters passed to the command
	 *
	 * @var array
	 */
	private $cmd_params = null;

	/**
	 *
	 * @param array|null $params
	 *            optional, array of parameters (var=>value) for the command
	 *
	 * @throws Exception
	 */
	public function __construct(?array $params = null)
	{
		if (!is_null($params)) {
			$params = $this->trimArray($params);
		}
		$this->cmd_params = $params;
	}

	/**
	 * run 'trim' function on an array recursively
	 *
	 * @param array $input
	 *
	 * @return string|array
	 */
	private function trimArray($input)
	{
		if ($input === '') {
			return "";
		}
		if (is_numeric($input) || is_null($input)) {
			return $input;
		}
		if (!is_array($input)) {
			return trim($input);
		}
		return array_map([
			$this,
			'trimArray'
		], $input);
	}

	/**
	 * get specific parameter which also has and unlimited-field
	 *
	 * @param string|null $param
	 *            parameter to get out of the request-parameter list
	 * @param string|null $ul_field
	 *            parameter to get out of the request-parameter list
	 * @param bool $optional
	 *            default: false
	 * @param mixed $default
	 *            value which is returned if optional=true and param is not set
	 *
	 * @return mixed
	 * @throws Exception
	 */
	protected function getUlParam(?string $param = null, ?string $ul_field = null, bool $optional = false, $default = 0)
	{
		$param_value = (int)$this->getParam($param, $optional, $default);
		$ul_field_value = $this->getBoolParam($ul_field, true, 0);
		if ($ul_field_value != '0') {
			$param_value = -1;
		}
		return $param_value;
	}

	/**
	 * get specific parameter from the parameter list;
	 * check for existence and != empty if needed.
	 * Maybe more in the future
	 *
	 * @param string|null $param
	 *            parameter to get out of the request-parameter list
	 * @param bool $optional
	 *            default: false
	 * @param mixed $default
	 *            value which is returned if optional=true and param is not set
	 *
	 * @return mixed
	 * @throws Exception
	 */
	protected function getParam(?string $param = null, bool $optional = false, $default = '')
	{
		// does it exist?
		if (!isset($this->cmd_params[$param])) {
			if ($optional === false) {
				// get module + function for better error-messages
				$inmod = $this->getModFunctionString();
				throw new Exception('Requested parameter "' . $param . '" could not be found for "' . $inmod . '"', 404);
			}
			return $default;
		}
		// is it empty? - test really on string, as value 0 is being seen as empty by php
		if (!is_array($this->cmd_params[$param]) && trim($this->cmd_params[$param]) === "") {
			if ($optional === false) {
				// get module + function for better error-messages
				$inmod = $this->getModFunctionString();
				throw new Exception('Requested parameter "' . $param . '" is empty where it should not be for "' . $inmod . '"', 406);
			}
			return '';
		}
		// everything else is fine
		return $this->cmd_params[$param];
	}

	/**
	 * returns "module::function()" for better error-messages (missing parameter etc.)
	 * makes debugging a lot more comfortable
	 *
	 * @param int $level
	 *            depth of backtrace, default 2
	 *
	 * @param int $max_level
	 * @param array|null $trace
	 *
	 * @return string
	 */
	private function getModFunctionString(int $level = 1, int $max_level = 5, $trace = null)
	{
		// which class called us
		$_class = get_called_class();
		if (empty($trace)) {
			// get backtrace
			$trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
		}
		// check class and function
		$class = $trace[$level]['class'];
		$func = $trace[$level]['function'];
		// is it the one we are looking for?
		if ($class != $_class && $level <= $max_level) {
			// check one level deeper
			return $this->getModFunctionString(++$level, $max_level, $trace);
		}
		return str_replace("Froxlor\\Api\\Commands\\", "", $class) . ':' . $func;
	}

	/**
	 * getParam wrapper for boolean parameter
	 *
	 * @param string|null $param
	 *            parameter to get out of the request-parameter list
	 * @param bool $optional
	 *            default: false
	 * @param mixed $default
	 *            value which is returned if optional=true and param is not set
	 *
	 * @return string
	 */
	protected function getBoolParam(?string $param = null, bool $optional = false, $default = false)
	{
		$_default = '0';
		if ($default) {
			$_default = '1';
		}
		$param_value = $this->getParam($param, $optional, $_default);
		if ($param_value && intval($param_value) != 0) {
			return '1';
		}
		return '0';
	}

	/**
	 * return list of all parameters
	 *
	 * @return array
	 */
	protected function getParamList()
	{
		return $this->cmd_params;
	}
}
