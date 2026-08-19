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

namespace Froxlor\Dns;

use Froxlor\Settings;

class DnsEntry
{
	public string $record;
	public int $ttl;
	public string $class = 'IN';
	public string $type;
	public int $priority;
	public ?string $content;

	/**
	 * @param string $record
	 * @param string $type
	 * @param string|null $content
	 * @param int $prio
	 * @param int $ttl
	 * @param string $class
	 */
	public function __construct(string $record = '', string $type = 'A', ?string $content = null, int $prio = 0, int $ttl = 0, string $class = 'IN')
	{
		$this->record = $record;
		$this->type = $type;
		$this->content = $content;
		$this->priority = $prio;
		$this->ttl = ($ttl <= 0 ? Settings::Get('system.defaultttl') : $ttl);
		$this->class = $class;
	}

	public function __toString()
	{
		$_content = $this->content;
		// check content length for txt records for bind9 (multiline)
		if (Settings::Get('system.dns_server') != 'pdns' && $this->type == 'TXT' && strlen($_content) >= 255) {
			// split string
			$_contentlines = str_split($_content, 254);
			// first line
			$_l = array_shift($_contentlines);
			// check for starting quote
			if (substr($_l, 0, 1) == '"') {
				$_l = substr($_l, 1);
			}
			$_content = '("' . $_l . '"' . PHP_EOL;
			$_l = array_pop($_contentlines);
			// check for ending quote
			if (substr($_l, -1) == '"') {
				$_l = substr($_l, 0, -1);
			}
			foreach ($_contentlines as $_cl) {
				// lines in between
				$_content .= "\t\t\t\t" . '"' . $_cl . '"' . PHP_EOL;
			}
			// last line
			$_content .= "\t\t\t\t" . '"' . $_l . '")';
		}
		return $this->record . "\t" . $this->ttl . "\t" . $this->class . "\t" . $this->type . "\t" . (($this->priority >= 0 && ($this->type == 'MX' || $this->type == 'SRV')) ? $this->priority . "\t" : "") . $_content . PHP_EOL;
	}
}
