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

class DnsZone
{
	public int $ttl;
	public string $origin;
	public string $serial;
	public ?array $records;

	/**
	 * @param int $ttl
	 * @param string $origin
	 * @param string $serial
	 * @param array|null $records
	 */
	public function __construct(int $ttl = 0, string $origin = '', string $serial = '', ?array $records = null)
	{
		$this->ttl = ($ttl <= 0 ? Settings::Get('system.defaultttl') : $ttl);
		$this->origin = $origin;
		$this->serial = $serial;
		$this->records = $records;
	}

	public function __toString()
	{
		$zone_file = "\$TTL " . $this->ttl . PHP_EOL;
		$zone_file .= "\$ORIGIN " . $this->origin . "." . PHP_EOL;
		if (!empty($this->records)) {
			foreach ($this->records as $record) {
				$zone_file .= (string)$record;
			}
		}
		return $zone_file;
	}
}
