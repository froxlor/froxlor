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
use PDO;
use PDOStatement;

/**
 * Class Settings
 *
 * Interaction with settings from the db
 */
class Settings
{
	/**
	 * settings data
	 *
	 * @var array
	 */
	private static $data = null;

	/**
	 * local config overrides
	 *
	 * @var array
	 */
	private static $conf = null;

	/**
	 * changed and unsaved settings data
	 *
	 * @var array
	 */
	private static $updatedata = null;

	/**
	 * prepared statement for updating the
	 * settings table
	 *
	 * @var PDOStatement
	 */
	private static $updstmt = null;

	/**
	 * tests if a setting-value that i s a comma separated list contains an entry
	 *
	 * @param string $setting
	 *            a group and a varname separated by a dot (group.varname)
	 * @param string $entry
	 *            the entry that is expected to be in the list
	 *
	 * @return boolean true, if the list contains $entry
	 */
	public static function IsInList($setting = null, $entry = null)
	{
		self::init();
		$svalue = self::Get($setting);
		if ($svalue == null) {
			return false;
		}
		$slist = explode(",", $svalue);
		return in_array($entry, $slist);
	}

	/**
	 * private constructor, reads in all settings
	 */
	private static function init()
	{
		if (empty(self::$data)) {
			self::readSettings();
			self::readConfig();
			self::$updatedata = [];

			// prepare statement
			self::$updstmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_SETTINGS . "` SET `value` = :value
				WHERE `settinggroup` = :group AND `varname` = :varname
			");
		}
	}

	/**
	 * Read in all settings from the database
	 * and set the internal $_data array
	 */
	private static function readSettings()
	{
		$result_stmt = Database::query("
			SELECT `settingid`, `settinggroup`, `varname`, `value`
			FROM `" . TABLE_PANEL_SETTINGS . "`
		");
		self::$data = [];
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			self::$data[$row['settinggroup']][$row['varname']] = $row['value'];
		}
		return true;
	}

	/**
	 * Read in all config overrides from
	 * config/config.inc.php
	 */
	private static function readConfig()
	{
		// set defaults
		self::$conf = [
			'enable_webupdate' => false,
			'disable_otp_security_check' => false,
			'display_php_errors' => false,
		];

		$configfile = Froxlor::getInstallDir() . '/lib/config.inc.php';
		if (@file_exists($configfile) && is_readable($configfile)) {
			self::$conf = array_merge(self::$conf, include $configfile);
		}
		return true;
	}

	/**
	 * return a setting-value by its group and varname
	 *
	 * @param string $setting
	 *            a group and a varname separated by a dot (group.varname)
	 *
	 * @return mixed
	 */
	public static function Get($setting = null)
	{
		self::init();
		$sstr = explode(".", $setting);
		// no separator - do'h
		if (!isset($sstr[1])) {
			return null;
		}
		$result = null;
		if (isset(self::$data[$sstr[0]][$sstr[1]])) {
			$result = self::$data[$sstr[0]][$sstr[1]];
		}
		return $result;
	}

	/**
	 * update a setting / set a new value
	 *
	 * @param string $setting
	 *            a group and a varname separated by a dot (group.varname)
	 * @param string $value
	 * @param boolean $instant_save
	 *
	 * @return bool
	 */
	public static function Set($setting = null, $value = null, $instant_save = true)
	{
		self::init();
		// check whether the setting exists
		if (self::Get($setting) !== null) {
			// set new value in array
			$sstr = explode(".", $setting);
			if (!isset($sstr[1])) {
				return false;
			}
			self::$data[$sstr[0]][$sstr[1]] = $value;
			// should we store to db instantly?
			if ($instant_save) {
				self::storeSetting($sstr[0], $sstr[1], $value);
			} else {
				// set temporary data for usage
				if (!isset(self::$data[$sstr[0]]) || !is_array(self::$data[$sstr[0]])) {
					self::$data[$sstr[0]] = [];
				}
				self::$data[$sstr[0]][$sstr[1]] = $value;
				// set update-data when invoking Flush()
				if (!isset(self::$updatedata[$sstr[0]]) || !is_array(self::$updatedata[$sstr[0]])) {
					self::$updatedata[$sstr[0]] = [];
				}
				self::$updatedata[$sstr[0]][$sstr[1]] = $value;
			}
			return true;
		}
		return false;
	}

	/**
	 * update a value in the database
	 *
	 * @param string $group
	 * @param string $varname
	 * @param string $value
	 */
	private static function storeSetting($group = null, $varname = null, $value = null)
	{
		$upd_data = [
			'group' => $group,
			'varname' => $varname,
			'value' => $value
		];
		Database::pexecute(self::$updstmt, $upd_data);
	}

	/**
	 * add a new setting to the database (mainly used in updater)
	 *
	 * @param string $setting
	 *            a group and a varname separated by a dot (group.varname)
	 * @param string $value
	 *
	 * @return boolean
	 */
	public static function AddNew($setting = null, $value = null)
	{
		self::init();
		// first check if it doesn't exist
		if (self::Get($setting) === null) {
			// validate parameter
			$sstr = explode(".", $setting);
			if (!isset($sstr[1])) {
				return false;
			}
			// prepare statement
			$ins_stmt = Database::prepare("
					INSERT INTO `" . TABLE_PANEL_SETTINGS . "` SET
					`settinggroup` = :group,
					`varname` = :varname,
					`value` = :value
					");
			$ins_data = [
				'group' => $sstr[0],
				'varname' => $sstr[1],
				'value' => $value
			];
			Database::pexecute($ins_stmt, $ins_data);
			// also set new value to internal array and make it available
			self::$data[$sstr[0]][$sstr[1]] = $value;
			return true;
		}
		return false;
	}

	/**
	 * Store all un-saved changes to the database and
	 * re-read in all settings
	 */
	public static function Flush()
	{
		self::init();
		if (is_array(self::$updatedata) && count(self::$updatedata) > 0) {
			// save all un-saved changes to the settings
			foreach (self::$updatedata as $group => $vargroup) {
				foreach ($vargroup as $varname => $value) {
					self::storeSetting($group, $varname, $value);
				}
			}
			// now empty the array
			self::$updatedata = [];
			// re-read in all settings
			return self::readSettings();
		}
		return false;
	}

	/**
	 * forget all un-saved changes to settings
	 */
	public static function Stash()
	{
		self::init();
		// empty update array
		self::$updatedata = [];
		// re-read in all settings
		return self::readSettings();
	}

	public static function loadSettingsInto(&$settings_data)
	{
		if (is_array($settings_data) && isset($settings_data['groups']) && is_array($settings_data['groups'])) {
			// prepare for use in for-loop
			$row_stmt = Database::prepare("
				SELECT `settinggroup`, `varname`, `value`
				FROM `" . TABLE_PANEL_SETTINGS . "`
				WHERE `settinggroup` = :group AND `varname` = :varname
			");

			foreach ($settings_data['groups'] as $settings_part => $settings_part_details) {
				if (is_array($settings_part_details) && isset($settings_part_details['fields']) && is_array($settings_part_details['fields'])) {
					foreach ($settings_part_details['fields'] as $field_name => $field_details) {
						if (isset($field_details['settinggroup']) && isset($field_details['varname']) && isset($field_details['default'])) {
							// execute prepared statement
							$row = Database::pexecute_first($row_stmt, [
								'group' => $field_details['settinggroup'],
								'varname' => $field_details['varname']
							]);

							if (!empty($row)) {
								$varvalue = $row['value'];
							} else {
								$varvalue = $field_details['default'];
							}
						} else {
							$varvalue = false;
						}

						$settings_data['groups'][$settings_part]['fields'][$field_name]['value'] = $varvalue;
					}
				}
			}
		}
	}

	public static function refreshState(): void
	{
		self::$data = null;
		self::init();
	}

	public static function getAll(): array
	{
		self::init();
		return self::$data;
	}

	/**
	 * get value from config by identifier
	 * @throws Exception
	 */
	public static function Config(string $config)
	{
		self::init();
		$result = self::$conf[$config] ?? null;
		if (is_null($result)) {
			throw new Exception('Unknown local config name "' . $config . '"');
		}
		return $result;
	}
}
