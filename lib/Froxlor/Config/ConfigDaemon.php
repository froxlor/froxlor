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

namespace Froxlor\Config;

use Exception;
use Froxlor\Froxlor;
use Froxlor\Settings;
use SimpleXMLElement;

/**
 * Class ConfigDaemon
 *
 * Parses a distributions XML - file and gives access to the configuration
 * Not to be used directly
 */
class ConfigDaemon
{

	/**
	 * Human - readable title of this service
	 *
	 * @var string
	 */
	public $title;
	/**
	 * Whether this is the default daemon of the service-category
	 *
	 * @var boolean
	 */
	public $default;
	/**
	 * Holding the commands for this daemon
	 *
	 * @var array
	 */
	private $orders = [];
	/**
	 * Store the parsed SimpleXMLElement for usage
	 *
	 * @var SimpleXMLElement
	 */
	private $fullxml;
	/**
	 * Memorize if we already parsed the XML
	 *
	 * @var bool
	 */
	private $isparsed = false;
	/**
	 * Sub - area of the full - XML only holding the daemon - data we are interested in
	 *
	 * @var SimpleXMLElement
	 */
	private $daemon;
	/**
	 * xpath leading to this daemon in the full XML
	 *
	 * @var string
	 */
	private $xpath;
	/**
	 * cache of sql-data if used
	 */
	private $sqldata_cache = null;

	public function __construct($xml, $xpath)
	{
		$this->fullxml = $xml;
		$this->xpath = $xpath;
		$this->daemon = $this->fullxml->xpath($this->xpath);
		if (count($this->daemon) !== 1) {
			throw new Exception('XPath "' . $this->xpath . '" didn\'t return exactly one element');
		}
		$attributes = $this->daemon[0]->attributes();
		if ($attributes['title'] != '') {
			$this->title = $this->parseContent((string)$attributes['title']);
		}
		if (isset($attributes['default'])) {
			$this->default = ($attributes['default'] == true);
		}
	}

	/**
	 * Replace placeholders with content
	 *
	 * @param string $content
	 * @return string $content w/o placeholder
	 */
	private function parseContent($content)
	{
		$content = preg_replace_callback('/\{\{(.*)\}\}/Ui', function ($matches) {
			$match = null;
			if (preg_match('/^settings\.(.*)$/', $matches[1], $match)) {
				return Settings::Get($match[1]);
			} elseif (preg_match('/^lng\.(.*)(?:\.(.*)(?:\.(.*)))$/U', $matches[1], $match)) {
				if (isset($match[1]) && $match[1] != '' && isset($match[2]) && $match[2] != '' && isset($match[3]) && $match[3] != '') {
					return lng($match[1] . '.' . $match[2] . '.' . $match[3]);
				} elseif (isset($match[1]) && $match[1] != '' && isset($match[2]) && $match[2] != '') {
					return lng($match[1] . '.' . $match[2]);
				} elseif (isset($match[1]) && $match[1] != '') {
					return lng($match[1]);
				}
				return '';
			} elseif (preg_match('/^const\.(.*)$/', $matches[1], $match)) {
				return $this->returnDynamic($match[1]);
			} elseif (preg_match('/^sql\.(.*)$/', $matches[1], $match)) {
				if (is_null($this->sqldata_cache)) {
					// read in sql-data (if exists)
					if (file_exists(Froxlor::getInstallDir() . "/lib/userdata.inc.php")) {
						$sql = [];
						$sql_root = [];
						require Froxlor::getInstallDir() . "/lib/userdata.inc.php";
						unset($sql_root);
						$this->sqldata_cache = $sql;
					}
				}
				return isset($this->sqldata_cache[$match[1]]) ? $this->sqldata_cache[$match[1]] : '';
			}
		}, $content);
		return $content;
	}

	private function returnDynamic($key = null)
	{
		$dynamics = [
			'install_dir' => Froxlor::getInstallDir()
		];
		return $dynamics[$key] ?? '';
	}

	/**
	 * Get config for this daemon
	 *
	 * The returned array will be an array of array, each sub-array looking like this:
	 * array('type' => 'install|file|command', 'content' => '<TEXT>')
	 * If the type is "file", an additional "name" - element will be added to the array
	 * To configure a daemon, the steps in the array must be followed in order
	 *
	 * @return array
	 */
	public function getConfig()
	{
		$this->parse();
		return $this->orders;
	}

	/**
	 * Parse the XML and populate $this->orders
	 *
	 * @return bool
	 */
	private function parse()
	{
		// We only want to parse the stuff one time
		if ($this->isparsed == true) {
			return true;
		}

		$preparsed = [];
		// First: let's push everything into an array and expand all includes
		foreach ($this->daemon[0]->children() as $order) {
			switch ((string)$order->getName()) {
				case "install":
				case "file":
				case "command":
					// Normal stuff, just add it to the preparsed - array
					$preparsed[] = $order;
					break;
				case "include":
					// Includes, get the part we want via xpath
					$includes = $this->fullxml->xpath((string)$order);
					foreach ($includes[0] as $include) {
						// The "include" is also a child, so just skip it, would make a mess later
						if ((string)$include->getName() == 'include') {
							continue;
						}
						$preparsed[] = $include;
					}
					break;
					// The next 3 are groupings, <visibility> MUST come first in this to work properly
				case "commands":
				case "files":
				case "installs":
					// Hold the results
					$visibility = 1;
					foreach ($order->children() as $child) {
						switch ((string)$child->getName()) {
							case "visibility":
								$visibility += $this->checkVisibility($child);
								break;
							case "install":
							case "file":
							case "command":
								if ($visibility > 0) {
									$preparsed[] = $child;
								}
								break;
							case "include":
								// Includes, get the part we want via xpath
								$includes = $this->fullxml->xpath((string)$child);
								foreach ($includes[0] as $include) {
									// The "include" is also a child, so just skip it, would make a mess later
									if ((string)$include->getName() == 'include') {
										continue;
									}
									$preparsed[] = $include;
								}
								break;
						}
					}
					break;
			}
		}

		// Go through every preparsed order and evaluate what should happen to it
		foreach ($preparsed as $order) {
			$parsedorder = $this->parseOrder($order);
			// We got an array (= valid order) and the array already has a type -> add to stack
			if (is_array($parsedorder) && array_key_exists('type', $parsedorder)) {
				$this->orders[] = $parsedorder;
				// We got an array, but no type, means we got multiple orders back, at them to the stack one at a time
			} elseif (is_array($parsedorder)) {
				foreach ($parsedorder as $neworder) {
					$this->orders[] = $neworder;
				}
			}
		}

		// Switch flag to indicate we parsed our data
		$this->isparsed = true;
		return true;
	}

	/**
	 * Check if visibility should be changed
	 *
	 * @param SimpleXMLElement $order
	 * @return int 0|-1
	 */
	private function checkVisibility($order)
	{
		$attributes = [];
		foreach ($order->attributes() as $key => $value) {
			$attributes[(string)$key] = $this->parseContent(trim((string)$value));
		}

		$order = $this->parseContent(trim((string)$order));
		if (!array_key_exists('mode', $attributes)) {
			throw new Exception('"<visibility>' . $order . '</visibility>" is missing mode');
		}

		$return = 0;
		switch ($attributes['mode']) {
			case "isfile":
				if (!is_file($order)) {
					$return = -1;
				}
				break;
			case "notisfile":
				if (is_file($order)) {
					$return = -1;
				}
				break;
			case "isdir":
				if (!is_dir($order)) {
					$return = -1;
				}
				break;
			case "notisdir":
				if (is_dir($order)) {
					$return = -1;
				}
				break;
			case "false":
				if ($order == true) {
					$return = -1;
				}
				break;
			case "true":
				if ($order == false) {
					$return = -1;
				}
				break;
			case "notempty":
				if ($order == "") {
					$return = -1;
				}
				break;
			case "userexists":
				if (posix_getpwuid($order) === false) {
					$return = -1;
				}
				break;
			case "groupexists":
				if (posix_getgrgid($order) === false) {
					$return = -1;
				}
				break;
			case "usernotexists":
				if (is_array(posix_getpwuid($order))) {
					$return = -1;
				}
				break;
			case "groupnotexists":
				if (is_array(posix_getgrgid($order))) {
					$return = -1;
				}
				break;
			case "usernamenotexists":
				if (is_array(posix_getpwnam($order))) {
					$return = -1;
				}
				break;
			case "equals":
				$return = (isset($attributes['value']) && $attributes['value'] == $order ? 0 : -1);
				break;
		}
		return $return;
	}

	/**
	 * Parse a single order and return it in a format for easier usage
	 *
	 * @param
	 *            SimpleXMLElement object holding a single order from the distribution - XML
	 * @return array|string
	 */
	private function parseOrder($order)
	{
		$attributes = [];
		foreach ($order->attributes() as $key => $value) {
			$attributes[(string)$key] = (string)$value;
		}

		$parsedorder = '';
		switch ((string)$order->getName()) {
			case "file":
				$parsedorder = $this->parseFile($order, $attributes);
				break;
			case "command":
				$parsedorder = $this->parseCommand($order, $attributes);
				break;
			case "install":
				$parsedorder = $this->parseInstall($order, $attributes);
				break;
			default:
				throw new Exception('Invalid order: ' . (string)$order->getName());
		}

		return $parsedorder;
	}

	/**
	 * Parse a file - order and return it in a format for easier usage
	 *
	 * @param
	 *            SimpleXMLElement object holding a single file from the distribution - XML
	 * @return array|string
	 */
	private function parseFile($order, $attributes)
	{
		$visibility = 1;
		// No sub - elements, so the content can be returned directly
		if ($order->count() == 0) {
			$content = (string)$order;
		} else {
			// Hold the results
			foreach ($order->children() as $child) {
				switch ((string)$child->getName()) {
					case "visibility":
						$visibility += $this->checkVisibility($child);
						break;
					case "content":
						$content = (string)$child;
						break;
				}
			}
		}

		$return = [];
		// Check if the original file should be backupped
		// @TODO: Maybe have a backup - location somewhere central?
		// @TODO: Use IO - class
		if (array_key_exists('backup', $attributes)) {
			if (array_key_exists('mode', $attributes) && $attributes['mode'] == 'append') {
				$cmd = 'cp';
			} else {
				$cmd = 'mv';
			}
			$return[] = [
				'type' => 'command',
				'content' => '[ -f ' . $this->parseContent($attributes['name']) . ' ] && ' . $cmd . ' "' . $this->parseContent($attributes['name']) . '" "' . $this->parseContent($attributes['name']) . '.frx.bak"',
				'execute' => "pre"
			];
		}

		// Now the content of the file can be written
		if (isset($attributes['mode'])) {
			$return[] = [
				'type' => 'file',
				'content' => $this->parseContent($content),
				'name' => $this->parseContent($attributes['name']),
				'mode' => $this->parseContent($attributes['mode'])
			];
		} else {
			$return[] = [
				'type' => 'file',
				'content' => $this->parseContent($content),
				'name' => $this->parseContent($attributes['name'])
			];
		}

		// Let's check if the mode of the file should be changed
		if (array_key_exists('chmod', $attributes)) {
			$return[] = [
				'type' => 'command',
				'content' => 'chmod ' . $attributes['chmod'] . ' "' . $this->parseContent($attributes['name']) . '"',
				'execute' => "post"
			];
		}

		// Let's check if the owner of the file should be changed
		if (array_key_exists('chown', $attributes)) {
			$return[] = [
				'type' => 'command',
				'content' => 'chown ' . $attributes['chown'] . ' "' . $this->parseContent($attributes['name']) . '"',
				'execute' => "post"
			];
		}

		// If we have more than 1 element, we want to group this stuff for easier processing later
		if (count($return) > 1) {
			$return = [
				'type' => 'file',
				'subcommands' => $return,
				'name' => $this->parseContent($attributes['name'])
			];
		}

		if ($visibility > 0) {
			return $return;
		} else {
			return '';
		}
	}

	/**
	 * Parse a command - order and return it in a format for easier usage
	 *
	 * @param
	 *            SimpleXMLElement object holding a single command from the distribution - XML
	 * @return array|string
	 */
	private function parseCommand($order, $attributes)
	{
		// No sub - elements, so the content can be returned directly
		if ($order->count() == 0) {
			return [
				'type' => 'command',
				'content' => $this->parseContent(trim((string)$order))
			];
		}

		// Hold the results
		$visibility = 1;
		$content = '';
		foreach ($order->children() as $child) {
			switch ((string)$child->getName()) {
				case "visibility":
					$visibility += $this->checkVisibility($child);
					break;
				case "content":
					$content = trim((string)$child);
					break;
			}
		}

		if ($visibility > 0) {
			return [
				'type' => 'command',
				'content' => $this->parseContent($content)
			];
		} else {
			return '';
		}
	}

	/**
	 * Parse a install - order and return it in a format for easier usage
	 *
	 * @param
	 *            SimpleXMLElement object holding a single install from the distribution - XML
	 * @return array|string
	 */
	private function parseInstall($order, $attributes)
	{
		// No sub - elements, so the content can be returned directly
		if ($order->count() == 0) {
			return [
				'type' => 'install',
				'content' => $this->parseContent(trim((string)$order))
			];
		}

		// Hold the results
		$visibility = 1;
		$content = '';
		foreach ($order->children() as $child) {
			switch ((string)$child->getName()) {
				case "visibility":
					$visibility += $this->checkVisibility($child);
					break;
				case "content":
					$content = trim((string)$child);
					break;
			}
		}

		if ($visibility > 0) {
			return [
				'type' => 'install',
				'content' => $this->parseContent($content)
			];
		} else {
			return '';
		}
	}
}
