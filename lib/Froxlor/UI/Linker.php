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

class Linker
{
	private $protocol = '';
	private $username = '';
	private $password = '';
	private $hostname = '';
	private $port = 80;
	private $filename = 'index.php';
	private $args = [];

	public function __construct($file = 'index.php', $hostname = '', $protocol = '', $port = '', $username = '', $password = '')
	{
		// Set the basic parts of our URL
		$this->protocol = $protocol;
		$this->username = $username;
		$this->password = $password;
		$this->hostname = $hostname;
		$this->port = $port;
		$this->filename = $file;
	}

	public function __set($key, $value)
	{
		switch (strtolower($key)) {
			case 'protocol':
				$this->protocol = $value;
				break;
			case 'username':
				$this->username = $value;
				break;
			case 'password':
				$this->password = $value;
				break;
			case 'hostname':
				$this->hostname = $value;
				break;
			case 'port':
				$this->port = $value;
				break;
			case 'filename':
				$this->filename = $value;
				break;
			default:
				return false;
		}
		return true;
	}

	public function add($key, $value)
	{
		// Add a new value to our parameters (overwrite = enabled)
		$this->args[$key] = $value;
	}

	public function del($key)
	{
		// If the key exists in our array -> delete it
		if (isset($this->args[$key])) {
			unset($this->args[$key]);
		}
	}

	public function getLink()
	{
		$link = '';

		// Build the basic URL
		if (strlen($this->protocol) > 0 && strlen($this->hostname) > 0) {
			$link = $this->protocol . '://';
		}

		// Let's see if we shall use a username in the URL
		// This is only available if a hostname is used as well
		if (strlen($this->username) > 0 && strlen($this->hostname) > 0) {
			$link .= urlencode($this->username);

			// Maybe we even have to append a password?
			if ($this->password != '') {
				$link .= ':' . urlencode($this->password);
			}

			// At least a username was given, add the @ to allow appending the hostname
			$link .= '@';
		}

		// Add hostname, port and filename to the URL
		if (strlen($this->hostname) > 0) {
			$link .= $this->hostname;

			// A port may only be used if hostname is used as well
			if (strlen($this->port) > 0) {
				$link .= ':' . $this->port;
			}
		}

		// Overwrite $this->args with parameters of this function (if necessary)
		if (func_num_args() == 1 && is_array(func_get_arg(0))) {
			$arguments = func_get_arg(0);
			$this->args = array_merge($this->args, $arguments);
		}

		// temporary until frontcontroller exists
		// We got a section in the URL -> morph AREA and section into filename
		// @TODO: Remove this
		if (isset($this->args['section']) && strlen($this->args['section']) > 0) {
			$link .= AREA . '_' . $this->args['section'] . '.php';
			unset($this->args['section']);
		} else {
			// filename has a prefixed slash
			$link .= $this->filename;
		}

		// Let's see if we are done (no arguments in query)
		if (count($this->args) == 0) {
			return $link;
		}

		// We have parameters, add them with a "?"
		$link .= "?";

		// Loop through arguments and add them to the link
		foreach ($this->args as $key => $value) {
			// For all but the first argument, prepend "&amp;"
			if (substr($link, -1) != "?") {
				$link .= "&";
			}

			// Encode parameters and add them to the link
			$link .= urlencode($key) . ($value !== "" ? '=' . urlencode($value) : '');
		}

		// Reset our class for further use
		$this->delAll();
		return $link;
	}

	public function delAll()
	{
		// Just resetting the array
		$this->args = [];
	}
}
