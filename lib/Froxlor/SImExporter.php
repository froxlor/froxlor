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

namespace Froxlor;

use Exception;
use Froxlor\Database\Database;
use Froxlor\UI\Form;
use Froxlor\Validate\Validate;
use PDO;

/**
 * Class SImExporter
 *
 * Import/Export settings to JSON
 */
class SImExporter
{
	/**
	 * settings which are not being exported
	 *
	 * @var array
	 */
	private static $no_export = [
		'panel.adminmail',
		'admin.show_news_feed',
		'system.lastaccountnumber',
		'system.lastguid',
		'system.ipaddress',
		'system.last_traffic_run',
		'system.hostname',
		'system.mysql_access_host',
		'system.lastcronrun',
		'system.defaultip',
		'system.defaultsslip',
		'system.last_tasks_run',
		'system.last_archive_run',
		'system.leprivatekey',
		'system.lepublickey',
		'system.updatecheck_data',
	];

	public static function export()
	{
		$settings_definitions = [];
		foreach (PhpHelper::loadConfigArrayDir(Froxlor::getInstallDir() . '/actions/admin/settings/')['groups'] as $group) {
			foreach ($group['fields'] as $field) {
				$settings_definitions[$field['settinggroup']][$field['varname']] = $field;
			}
		}

		$result_stmt = Database::query("
			SELECT * FROM `" . TABLE_PANEL_SETTINGS . "` ORDER BY `settingid` ASC
		");
		$_data = [];
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$index = $row['settinggroup'] . "." . $row['varname'];
			if (!in_array($index, self::$no_export)) {
				$_data[$index] = $row['value'];
			}

			if (array_key_exists($row['settinggroup'], $settings_definitions) && array_key_exists($row['varname'],
					$settings_definitions[$row['settinggroup']])) {
				// Export image file
				if ($settings_definitions[$row['settinggroup']][$row['varname']]['type'] === "image") {
					if ($row['value'] === "") {
						continue;
					}

					$_data[$index . '.image_data'] = base64_encode(file_get_contents(explode('?', $row['value'],
						2)[0]));
				}
			}
		}

		// add checksum for validation
		$_data['_sha'] = sha1(var_export($_data, true));
		$_export = json_encode($_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		if (!$_export) {
			throw new Exception("Error exporting settings: " . json_last_error_msg());
		}

		return $_export;
	}

	public static function import($json_str = null)
	{
		// decode data
		$_data = json_decode($json_str, true);
		if ($_data) {
			// get validity check data
			$_sha = isset($_data['_sha']) ? $_data['_sha'] : false;
			$_version = isset($_data['panel.version']) ? $_data['panel.version'] : false;
			$_dbversion = isset($_data['panel.db_version']) ? $_data['panel.db_version'] : false;
			// check if we have everything we need
			if (!$_sha || !$_version || !$_dbversion) {
				throw new Exception("Invalid froxlor settings data. Unable to import.");
			}
			// validate import file
			unset($_data['_sha']);
			// compare
			if ($_sha != sha1(var_export($_data, true))) {
				throw new Exception("SHA check of import data failed. Unable to import.");
			}
			// do not import version info - but we need that to possibly update settings
			// when there were changes in the variable-name or similar
			unset($_data['panel.version']);
			unset($_data['panel.db_version']);
			// validate we got ssl enabled ips when ssl is enabled
			// otherwise deactivate it
			if ($_data['system.use_ssl'] == 1) {
				$result_ssl_ipsandports_stmt = Database::prepare("
					SELECT COUNT(*) as count_ssl_ip FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl`='1'
				");
				$result = Database::pexecute_first($result_ssl_ipsandports_stmt);
				if ($result['count_ssl_ip'] <= 0) {
					// no ssl-ip -> deactivate
					$_data['system.use_ssl'] = 0;
					// deactivate other ssl-related settings
					$_data['system.leenabled'] = 0;
					$_data['system.le_froxlor_enabled'] = 0;
					$_data['system.le_froxlor_redirect'] = 0;
				}
			}

			$form_data = [];
			$image_data = [];
			// read in all current settings
			$current_settings = Settings::getAll();
			foreach ($current_settings as $setting_group => $setting) {
				foreach ($setting as $varname => $value) {
					// set all group/varname:values which are not in the import file
					if (!array_key_exists($setting_group . '.' . $varname, $_data)) {
						$_data[$setting_group . '.' . $varname] = $value;
					}
				}
			}
			// re-format the array-key for Form::processForm
			foreach ($_data as $key => $value) {
				$index_split = explode('.', $key, 3);
				if (!isset($current_settings[$index_split[0]][$index_split[1]])) {
					continue;
				}
				if (isset($index_split[2]) && $index_split[2] === 'image_data' && !empty($_data[$index_split[0] . '.' . $index_split[1]])) {
					$image_data[$key] = $value;
				} else {
					$form_data[str_replace(".", "_", $key)] = $value;
				}
			}

			// store new data
			$settings_data = PhpHelper::loadConfigArrayDir(Froxlor::getInstallDir() . '/actions/admin/settings/');
			Settings::loadSettingsInto($settings_data);

			if (Form::processForm($settings_data, $form_data, [], null, true)) {
				// save to DB
				Settings::Flush();

				// Process image_data and save it
				if (count($image_data) > 0) {
					foreach ($image_data as $index => $value) {
						$index_split = explode('.', $index, 3);
						$path = Froxlor::getInstallDir() . '/img/';
						if (!is_dir($path) && !mkdir($path, 0775)) {
							throw new Exception("img directory does not exist and cannot be created");
						}

						// Make sure we can write to the upload directory
						if (!is_writable($path)) {
							if (!chmod($path, 0775)) {
								throw new Exception("Cannot write to img directory");
							}
						}

						if (Validate::validateBase64Image($value)) {
							$img_data = base64_decode($value);
							$img_filename = explode('?', $_data[$index_split[0] . '.' . $index_split[1]], 2)[0];

							$spl = explode('.', $img_filename);
							$file_extension = strtolower(array_pop($spl));
							unset($spl);

							if (!in_array($file_extension, [
								'jpeg',
								'jpg',
								'png',
								'gif'
							])) {
								throw new Exception("Invalid file-extension, use one of: jpeg, jpg, png, gif");
							}
							$img_filename = 'img/' . bin2hex(random_bytes(16)) . '.' . $file_extension;
							file_put_contents(Froxlor::getInstallDir() . '/' . $img_filename, $img_data);
							$img_index = $index_split[0].'.'.$index_split[1];
							Settings::Set($img_index, $img_filename . '?v=' . time());
						}
					}
				}
				// all good
				return true;
			} else {
				throw new Exception("Importing settings failed");
			}
		}
		throw new Exception("Invalid JSON data: " . json_last_error_msg());
	}
}
