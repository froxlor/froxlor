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
use Froxlor\Settings;
use SimpleXMLElement;

/**
 * Class ConfigService
 *
 * Parses a distributions XML - file and gives access to the services within
 * Not to be used directly
 */
class ConfigService
{

	/**
	 * Human - readable title of this service
	 *
	 * @var string
	 */
	public $title;
	/**
	 * Holding the available daemons in this service
	 *
	 * @var array
	 */
	private $daemons = [];
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
	 * xpath leading to this service in the full XML
	 *
	 * @var string
	 */
	private $xpath;

	public function __construct($xml, $xpath)
	{
		$this->fullxml = $xml;
		$this->xpath = $xpath;
		$service = $this->fullxml->xpath($this->xpath);
		$attributes = $service[0]->attributes();
		if ($attributes['title'] != '') {
			$this->title = $this->parseContent((string)$attributes['title']);
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
			}
		}, $content);
		return $content;
	}

	public function getDaemons()
	{
		$this->parse();
		return $this->daemons;
	}

	/**
	 * Parse the XML and populate $this->daemons
	 *
	 * @return bool
	 */
	private function parse()
	{
		// We only want to parse the stuff one time
		if ($this->isparsed == true) {
			return true;
		}

		$daemons = $this->fullxml->xpath($this->xpath . '/daemon');
		foreach ($daemons as $daemon) {
			if ($daemon->getName() == 'comment') {
				continue;
			}
			$name = '';
			$nametag = '';
			$versiontag = '';
			foreach ($daemon->attributes() as $key => $value) {
				if ($key == 'name' && $name == '') {
					$name = (string)$value;
					$nametag = "[@name='" . $value . "']";
				} elseif ($key == 'name' && $name != '') {
					$name = (string)$value . '_' . $name;
					$nametag = "[@name='" . $value . "']";
				} elseif ($key == 'version' && $name == '') {
					$name = str_replace('.', '', $value);
					$versiontag = "[@version='" . $value . "']";
				} elseif ($key == 'version' && $name != '') {
					$name .= str_replace('.', '', $value);
					$versiontag = "[@version='" . $value . "']";
				}
			}
			if ($name == '') {
				throw new Exception('No name attribute for daemon');
			}
			$this->daemons[$name] = new ConfigDaemon($this->fullxml, $this->xpath . "/daemon" . $nametag . $versiontag);
		}

		// Switch flag to indicate we parsed our data
		$this->isparsed = true;
		return true;
	}
}
