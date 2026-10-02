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
use SimpleXMLElement;

/**
 * Class ConfigParser
 *
 * Parses a distributions XML - file and gives access to the configuration
 */
class ConfigParser
{

	/**
	 * Name of the distribution this configuration is for
	 *
	 * @var string
	 */
	public $distributionName = '';
	/**
	 * Codename of the distribution this configuration is for
	 *
	 * @var string
	 */
	public $distributionCodename = '';
	/**
	 * Version of the distribution this configuration is for
	 *
	 * @var string
	 */
	public $distributionVersion = '';
	/**
	 * Recommended editor
	 *
	 * @var string
	 */
	public $distributionEditor = '/bin/nano';
	/**
	 * Show if this configuration is deprecated
	 *
	 * @var bool
	 */
	public $deprecated = false;
	/**
	 * Holding the available services in the XML
	 *
	 * @var array
	 */
	private $services = [];
	/**
	 * Holding the available defaults in the XML
	 *
	 * @var array
	 */
	private $defaults = [];
	/**
	 * Store the parsed SimpleXMLElement for usage
	 *
	 * @var SimpleXMLElement
	 */
	private $xml;
	/**
	 * Memorize if we already parsed the XML
	 *
	 * @var bool
	 */
	private $isparsed = false;

	/**
	 * Constructor
	 *
	 * Initialize the XML - ConfigParser
	 *
	 * @param string $filename
	 *            filename of the froxlor - configurationfile
	 * @return void
	 */
	public function __construct($filename)
	{
		if (!is_readable($filename)) {
			throw new Exception('File not readable');
		}

		$this->xml = simplexml_load_file($filename);
		if ($this->xml === false) {
			$error = '';
			foreach (libxml_get_errors() as $error) {
				$error .= "\t" . $error->message;
			}
			throw new Exception($error);
		}

		// Let's see if we can find a <distribution> block in the XML
		$distribution = $this->xml->xpath('//distribution');

		// No distribution found - can't use this file
		if (!is_array($distribution)) {
			throw new Exception('Invalid XML, no distribution found');
		}

		// Search for attributes we understand
		foreach ($distribution[0]->attributes() as $key => $value) {
			switch ((string)$key) {
				case "name":
					$this->distributionName = (string)$value;
					break;
				case "version":
					$this->distributionVersion = (string)$value;
					break;
				case "codename":
					$this->distributionCodename = (string)$value;
					break;
				case "defaulteditor":
					$this->distributionEditor = (string)$value;
					break;
				case "deprecated":
					(string)$value == 'true' ? $this->deprecated = true : $this->deprecated = false;
					break;
			}
		}
	}

	/**
	 * Return all services defined by the XML
	 *
	 * The array will hold ConfigService - Objects for further handling
	 *
	 * @return array
	 */
	public function getServices()
	{
		// Let's parse this shit(!)
		$this->parseServices();

		// Return our carefully searched for services
		return $this->services;
	}

	/**
	 * Parse the XML and populate $this->services
	 *
	 * @return bool
	 */
	private function parseServices()
	{
		// We only want to parse the stuff one time
		if ($this->isparsed == true) {
			return true;
		}

		// Get all services
		$services = $this->xml->xpath('//services/service');
		foreach ($services as $service) {
			// We don't want comments
			if ($service->getName() == 'comment') {
				continue;
			}
			// Search the attributes for "type"
			foreach ($service->attributes() as $key => $value) {
				if ($key == 'type') {
					$this->services[(string)$value] = new ConfigService($this->xml, '//services/service[@type="' . (string)$value . '"]');
				}
			}
		}

		// Switch flag to indicate we parsed our data
		$this->isparsed = true;
		return true;
	}

	/**
	 * Return all defaults defined by the XML
	 *
	 * The array will hold ConfigDefaults - Objects for further handling
	 *
	 * @return array
	 */
	public function getDefaults()
	{
		// Let's parse this shit(!)
		$this->parseDefaults();

		// Return our carefully searched for defaults
		return $this->defaults;
	}

	/**
	 * Parse the XML and populate $this->services
	 *
	 * @return bool
	 */
	private function parseDefaults()
	{
		// We only want to parse the stuff one time
		if ($this->isparsed == true) {
			return true;
		}

		// Get all defaults
		$defaults = $this->xml->xpath('//defaults/default');
		foreach ($defaults as $default) {
			$this->defaults[] = $default;
		}

		// Switch flag to indicate we parsed our data
		$this->isparsed = true;
		return true;
	}

	/**
	 * return complete distribution string "Name [codename] [ (version)] [deprecated]
	 *
	 * @return string
	 */
	public function getCompleteDistroName(): string
	{
		// get distro-info
		$dist_display = $this->distributionName;
		if ($this->distributionCodename != '') {
			$dist_display .= " " . $this->distributionCodename;
		}
		if ($this->distributionVersion != '') {
			$dist_display .= " (" . $this->distributionVersion . ")";
		}
		if ($this->deprecated) {
			$dist_display .= " [deprecated]";
		}
		return $dist_display;
	}
}
