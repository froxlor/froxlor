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

namespace Froxlor\Bulk;

use Exception;

/**
 * Class DomainBulkAction to mass-import domains for a given customer
 */
class DomainBulkAction extends BulkAction
{

	/**
	 * @param string $import_file
	 * @param array $userinfo
	 *
	 * @return DomainBulkAction
	 */
	public function __construct(?string $import_file = null, array $userinfo = [])
	{
		parent::__construct($import_file, $userinfo);
		$this->setApiCall('Domains.add');
	}

	/**
	 * import the parsed import file data with an optional separator other then semicolon
	 * and offset (maybe for header-line in csv or similar)
	 *
	 * @param string $separator
	 * @param int $offset
	 *
	 * @return array 'all' => amount of records processed, 'imported' => number of imported records
	 */
	public function doImport(string $separator = ";", int $offset = 0)
	{
		if ($this->userinfo['domains'] == "-1") {
			$dom_unlimited = true;
		} else {
			$dom_unlimited = false;
		}

		$domains_used = (int)$this->userinfo['domains_used'];
		$domains_avail = (int)$this->userinfo['domains'];

		if (!is_int($offset) || $offset < 0) {
			throw new Exception("Invalid offset specified");
		}

		try {
			$domain_array = $this->parseImportFile($separator);
		} catch (Exception $e) {
			throw $e;
		}

		if (count($domain_array) <= 0) {
			throw new Exception("No domains were read from the file.");
		}

		$global_counter = 0;
		$import_counter = 0;
		$note = '';
		foreach ($domain_array as $idx => $dom) {
			if ($idx >= $offset) {
				if ($dom_unlimited || (!$dom_unlimited && $domains_used < $domains_avail)) {
					$result = $this->importEntity($dom);
					if ($result) {
						$import_counter++;
						$domains_used++;
					}
				} else {
					$note .= 'You have reached your maximum allocation of domains (' . $domains_avail . ').';
					break;
				}
			}
			$global_counter++;
		}

		return [
			'all' => $global_counter,
			'imported' => $import_counter,
			'notice' => $note
		];
	}
}
