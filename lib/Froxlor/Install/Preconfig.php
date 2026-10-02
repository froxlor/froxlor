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

namespace Froxlor\Install;

use Froxlor\Froxlor;
use Froxlor\Settings;

class Preconfig
{
	private $preconfig_data = [];

	/**
	 * returns whether there are preconfig items in an update
	 *
	 * @return bool
	 */
	public function hasPreConfig(): bool
	{
		return count($this->preconfig_data) > 0;
	}

	/**
	 * return all collected preconfig data
	 *
	 * @return array
	 */
	public function getData(): array
	{
		return $this->preconfig_data;
	}

	/**
	 * adds an preconfig result-array to the preconfig-data
	 *
	 * @param array $array
	 *
	 * @return void
	 */
	public function addToPreConfig(array $array)
	{
		if (isset($array['title']) && isset($array['fields']) && count($array['fields']) > 0) {
			$this->preconfig_data[] = $array;
		}
	}

	/**
	 * read in all preconfig files and build up data-array for admin_updates
	 */
	public function __construct()
	{
		$preconfigs = glob(Froxlor::getInstallDir() . '/install/updates/preconfig/*.php');

		if (!empty($preconfigs)) {
			$current_version = Settings::Get('panel.version');
			$current_db_version = Settings::Get('panel.db_version');
			if (empty($current_db_version)) {
				$current_db_version = "0";
			}
			foreach (array_reverse($preconfigs) as $preconfig_file) {
				$pconf = include $preconfig_file;
				$this->addToPreConfig($pconf);
			}
		}
	}

	/**
	 * Function getPreConfig
	 *
	 * outputs various form-field-arrays before the update process
	 * can be continued (asks for agreement whatever is being asked)
	 *
	 * @param bool $no_check
	 * @return array
	 */
	public static function getPreConfig(bool $no_check = false): array
	{
		$preconfig = new self();

		if ($preconfig->hasPreConfig()) {
			if (!$no_check) {
				$agree = [
					'title' => 'Check',
					'fields' => [
						'update_changesagreed' => ['mandatory' => true, 'type' => 'checkrequired', 'value' => 1, 'label' => '<strong>I have read the update notifications above and I am aware of the changes made to my system.</strong>'],
						'update_preconfig' => ['type' => 'hidden', 'value' => 1]
					]
				];
				$preconfig->addToPreConfig($agree);
			}
			return $preconfig->getData();
		}
		return [];
	}
}
