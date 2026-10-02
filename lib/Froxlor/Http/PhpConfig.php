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

namespace Froxlor\Http;

use Froxlor\Database\Database;
use PDO;

class PhpConfig
{

	/**
	 * returns an array of existing php-configurations
	 * in our database for the settings-array
	 *
	 * @return array
	 */
	public static function getPhpConfigs(): array
	{
		$configs_array = [];

		// check if table exists because this is used in a preconfig
		// where the tables possibly does not exist yet
		$results = Database::query("SHOW TABLES LIKE '" . TABLE_PANEL_PHPCONFIGS . "'");
		if (!$results) {
			$configs_array[1] = 'Default php.ini';
		} else {
			// get all configs
			$result_stmt = Database::query("SELECT * FROM `" . TABLE_PANEL_PHPCONFIGS . "`");
			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				if (!isset($configs_array[$row['id']]) && !in_array($row['id'], $configs_array)) {
					$configs_array[$row['id']] = html_entity_decode($row['description']);
				}
			}
		}
		return $configs_array;
	}
}
