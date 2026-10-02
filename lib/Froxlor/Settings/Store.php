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

namespace Froxlor\Settings;

use Exception;
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\Database\DbManager;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\System\IPTools;
use Froxlor\UI\Request;
use Froxlor\Validate\Validate;
use PDO;

class Store
{

	public static function storeSettingClearCertificates($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false
			&& is_array($fielddata)
			&& isset($fielddata['settinggroup'])
			&& $fielddata['settinggroup'] == 'system'
			&& isset($fielddata['varname'])
		) {
			if ($fielddata['varname'] == 'le_froxlor_enabled' && $newfieldvalue == '0') {
				Database::query("
					DELETE FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid` = '0'
				");
			} elseif ($fielddata['varname'] == 'froxloraliases' && $newfieldvalue != $fielddata['value']) {
				Database::query("
					UPDATE `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` SET `validtodate`= NULL WHERE `domainid` = '0'
				");
			}
		}

		return $returnvalue;
	}

	public static function storeSettingField($fieldname, $fielddata, $newfieldvalue)
	{
		if (is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] != '' && isset($fielddata['varname']) && $fielddata['varname'] != '') {
			if (Settings::Set($fielddata['settinggroup'] . '.' . $fielddata['varname'], $newfieldvalue) !== false) {
				/*
				 * when fielddata[cronmodule] is set, this means enable/disable a cronjob
				 */
				if (isset($fielddata['cronmodule']) && $fielddata['cronmodule'] != '') {
					Cronjob::toggleCronStatus($fielddata['cronmodule'], $newfieldvalue);
				}

				/*
				 * satisfy dependencies
				 */
				if (isset($fielddata['dependency']) && is_array($fielddata['dependency'])) {
					if ((int)$fielddata['dependency']['onlyif'] == (int)$newfieldvalue) {
						self::storeSettingField($fielddata['dependency']['fieldname'], $fielddata['dependency']['fielddata'], $newfieldvalue);
					}
				}

				return [
					$fielddata['settinggroup'] . '.' . $fielddata['varname'] => $newfieldvalue
				];
			} else {
				return false;
			}
		} else {
			return false;
		}
	}

	public static function storeSettingDefaultIp($fieldname, $fielddata, $newfieldvalue)
	{
		$defaultips_old = Settings::Get('system.defaultip');

		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'system' && isset($fielddata['varname']) && $fielddata['varname'] == 'defaultip') {
			self::updateStdSubdomainDefaultIp($newfieldvalue, $defaultips_old);
		}

		return $returnvalue;
	}

	private static function updateStdSubdomainDefaultIp($newfieldvalue, $defaultips_old)
	{
		// update standard-subdomain of customer if exists
		$customerstddomains_result_stmt = Database::prepare("
			SELECT `standardsubdomain` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `standardsubdomain` <> '0'
		");
		Database::pexecute($customerstddomains_result_stmt);

		$ids = [];
		while ($customerstddomains_row = $customerstddomains_result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$ids[] = (int)$customerstddomains_row['standardsubdomain'];
		}

		if (count($ids) > 0) {

			if (!empty($defaultips_old)) {
				// Delete the existing mappings linking to default IPs
				$del_stmt = Database::prepare("
					DELETE FROM `" . TABLE_DOMAINTOIP . "`
					WHERE `id_domain` IN (" . implode(', ', $ids) . ")
					AND `id_ipandports` IN (" . $defaultips_old . ")
				");
				Database::pexecute($del_stmt);
			}

			$defaultips_new = !empty($newfieldvalue) ? explode(",", $newfieldvalue) : [];
			if (count($defaultips_new) > 0) {

				// Insert the new mappings
				$ins_stmt = Database::prepare("
					INSERT INTO `" . TABLE_DOMAINTOIP . "`
					SET `id_domain` = :domainid, `id_ipandports` = :ipandportid
				");

				foreach ($ids as $id) {
					foreach ($defaultips_new as $defaultip_new) {
						Database::pexecute($ins_stmt, [
							'domainid' => $id,
							'ipandportid' => $defaultip_new
						]);
					}
				}
			}
		}
	}

	public static function storeSettingDefaultSslIp($fieldname, $fielddata, $newfieldvalue)
	{
		$defaultips_old = Settings::Get('system.defaultsslip');

		self::cleanIpSelection($defaultips_old);
		self::cleanIpSelection($newfieldvalue);

		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'system' && isset($fielddata['varname']) && $fielddata['varname'] == 'defaultsslip') {
			self::updateStdSubdomainDefaultIp($newfieldvalue, $defaultips_old);
		}

		return $returnvalue;
	}

	private static function cleanIpSelection(&$selection)
	{
		$selection_arr = array_filter(explode(',', $selection), function ($value) {
			return !empty($value);
		});
		$selection = implode(",", $selection_arr);
	}

	/**
	 * updates the setting for the default panel-theme
	 * and also the user themes (customers and admins) if
	 * the changing of themes is disallowed for them
	 *
	 * @param string $fieldname
	 * @param array $fielddata
	 * @param mixed $newfieldvalue
	 *
	 * @return boolean|array
	 */
	public static function storeSettingDefaultTheme($fieldname, $fielddata, $newfieldvalue)
	{
		// first save the setting itself
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'panel' && isset($fielddata['varname']) && $fielddata['varname'] == 'default_theme') {
			// now, if changing themes is disabled we manually set
			// the new theme (customers and admin, depending on settings)
			if (Settings::Get('panel.allow_theme_change_customer') == '0') {
				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `theme` = :theme
				");
				Database::pexecute($upd_stmt, [
					'theme' => $newfieldvalue
				]);
			}
			if (Settings::Get('panel.allow_theme_change_admin') == '0') {
				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_ADMINS . "` SET `theme` = :theme
				");
				Database::pexecute($upd_stmt, [
					'theme' => $newfieldvalue
				]);
			}
		}

		return $returnvalue;
	}

	public static function storeSettingFieldInsertBindTask($fieldname, $fielddata, $newfieldvalue)
	{
		// first save the setting itself
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false) {
			Cronjob::inserttask(TaskId::REBUILD_DNS);
		}
		return $returnvalue;
	}

	public static function storeSettingFieldInsertAntispamTask($fieldname, $fielddata, $newfieldvalue)
	{
		// first save the setting itself
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false) {
			Cronjob::inserttask(TaskId::REBUILD_RSPAMD);
		}
		return $returnvalue;
	}

	public static function storeSettingFieldInsertUpdateServicesTask($fieldname, $fielddata, $newfieldvalue)
	{
		// first save the setting itself
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false) {
			Cronjob::inserttask(TaskId::UPDATE_LE_SERVICES);
		}
		return $returnvalue;
	}

	public static function storeSettingHostname($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'system' && isset($fielddata['varname']) && ($fielddata['varname'] == 'hostname' || $fielddata['varname'] == 'stdsubdomain')) {
			$idna_convert = new IdnaWrapper();
			$newfieldvalue = $idna_convert->encode($newfieldvalue);

			if (($fielddata['varname'] == 'hostname' && Settings::Get('system.stdsubdomain') == '') || $fielddata['varname'] == 'stdsubdomain') {
				if ($fielddata['varname'] == 'stdsubdomain' && $newfieldvalue == '') {
					// clear field, reset stdsubdomain to system-hostname
					$oldhost = $idna_convert->encode(Settings::Get('system.stdsubdomain'));
					$newhost = $idna_convert->encode(Settings::Get('system.hostname'));
				} elseif ($fielddata['varname'] == 'stdsubdomain' && Settings::Get('system.stdsubdomain') == '') {
					// former std-subdomain was system-hostname
					$oldhost = $idna_convert->encode(Settings::Get('system.hostname'));
					$newhost = $newfieldvalue;
				} elseif ($fielddata['varname'] == 'stdsubdomain') {
					// std-subdomain just changed
					$oldhost = $idna_convert->encode(Settings::Get('system.stdsubdomain'));
					$newhost = $newfieldvalue;
				} elseif ($fielddata['varname'] == 'hostname' && Settings::Get('system.stdsubdomain') == '') {
					// system-hostname has changed and no system-stdsubdomain is not set
					$oldhost = $idna_convert->encode(Settings::Get('system.hostname'));
					$newhost = $newfieldvalue;
				}

				$customerstddomains_result_stmt = Database::prepare("
					SELECT `standardsubdomain` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `standardsubdomain` <> '0'
				");
				Database::pexecute($customerstddomains_result_stmt);

				$ids = [];

				while ($customerstddomains_row = $customerstddomains_result_stmt->fetch(PDO::FETCH_ASSOC)) {
					$ids[] = (int)$customerstddomains_row['standardsubdomain'];
				}

				if (count($ids) > 0) {
					$upd_stmt = Database::prepare("
						UPDATE `" . TABLE_PANEL_DOMAINS . "` SET
						`domain` = REPLACE(`domain`, :host, :newval)
						WHERE `id` IN ('" . implode(', ', $ids) . "')
					");
					Database::pexecute($upd_stmt, [
						'host' => $oldhost,
						'newval' => $newhost
					]);
				}
			}
		}

		return $returnvalue;
	}

	public static function storeSettingIpAddress($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'system' && isset($fielddata['varname']) && $fielddata['varname'] == 'ipaddress') {
			$mysql_access_host_array = array_map('trim', explode(',', Settings::Get('system.mysql_access_host')));
			$mysql_access_host_array[] = $newfieldvalue;
			$mysql_access_host_array = array_unique(PhpHelper::arrayTrim($mysql_access_host_array));
			DbManager::correctMysqlUsers($mysql_access_host_array);
			$mysql_access_host = implode(',', $mysql_access_host_array);
			Settings::Set('system.mysql_access_host', $mysql_access_host);
		}

		return $returnvalue;
	}

	public static function storeSettingMysqlAccessHost($fieldname, $fielddata, $newfieldvalue)
	{
		$ips = $newfieldvalue;
		// Convert cidr to netmask for mysql, if needed be
		if (strpos($ips, ',') !== false) {
			$ips = explode(',', $ips);
		}
		if (is_array($ips) && count($ips) > 0) {
			$newfieldvalue = [];
			foreach ($ips as $ip) {
				$org_ip = $ip;
				$ip_cidr = explode("/", $ip);
				if (count($ip_cidr) === 2) {
					$ip = $ip_cidr[0];
					if (strlen($ip_cidr[1]) <= 2) {
						$ip_cidr[1] = IPTools::cidr2NetmaskAddr($org_ip);
					}
					$newfieldvalue[] = $ip . '/' . $ip_cidr[1];
				} else {
					$newfieldvalue[] = $org_ip;
				}
			}
			$newfieldvalue = implode(',', $newfieldvalue);
		}
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'system' && isset($fielddata['varname']) && $fielddata['varname'] == 'mysql_access_host') {
			$mysql_access_host_array = array_map('trim', explode(',', $newfieldvalue));

			if (in_array('127.0.0.1', $mysql_access_host_array) && !in_array('localhost', $mysql_access_host_array)) {
				$mysql_access_host_array[] = 'localhost';
			}

			if (!in_array('127.0.0.1', $mysql_access_host_array) && in_array('localhost', $mysql_access_host_array)) {
				$mysql_access_host_array[] = '127.0.0.1';
			}

			// be aware that ipv6 addresses are enclosed in [ ] when passed here
			$mysql_access_host_array = array_map([
				'\\Froxlor\\Settings\\Store',
				'cleanMySQLAccessHost'
			], $mysql_access_host_array);

			$mysql_access_host_array = array_unique(PhpHelper::arrayTrim($mysql_access_host_array));
			$newfieldvalue = implode(',', $mysql_access_host_array);
			DbManager::correctMysqlUsers($mysql_access_host_array);
			$mysql_access_host = implode(',', $mysql_access_host_array);
			Settings::Set('system.mysql_access_host', $mysql_access_host);
		}

		return $returnvalue;
	}

	public static function storeSettingResetCatchall($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'catchall' && isset($fielddata['varname']) && $fielddata['varname'] == 'catchall_enabled' && $newfieldvalue == '0') {
			Database::query("
				UPDATE `" . TABLE_MAIL_VIRTUAL . "` SET `iscatchall` = '0' WHERE `iscatchall` = '1'
			");
		}

		return $returnvalue;
	}

	/**
	 * Whenever the webserver- / FCGID- or FPM-user gets updated
	 * we need to update ftp_groups accordingly
	 */
	public static function storeSettingWebserverFcgidFpmUser($fieldname, $fielddata, $newfieldvalue)
	{
		if (is_array($fielddata) && isset($fielddata['settinggroup']) && isset($fielddata['varname'])) {
			$update_user = null;

			// webserver
			if ($fielddata['settinggroup'] == 'system' && $fielddata['varname'] == 'httpuser') {
				$update_user = Settings::Get('system.httpuser');
			}

			// fcgid
			if ($fielddata['settinggroup'] == 'system' && $fielddata['varname'] == 'mod_fcgid_httpuser') {
				$update_user = Settings::Get('system.mod_fcgid_httpuser');
			}

			// webserver
			if ($fielddata['settinggroup'] == 'phpfpm' && $fielddata['varname'] == 'vhost_httpuser') {
				$update_user = Settings::Get('phpfpm.vhost_httpuser');
			}

			$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

			if ($returnvalue !== false) {
				/**
				 * only update if anything changed
				 */
				if ($update_user != null && $newfieldvalue != $update_user) {
					$upd_stmt = Database::prepare("UPDATE `" . TABLE_FTP_GROUPS . "` SET `members` = REPLACE(`members`, :olduser, :newuser)");
					Database::pexecute($upd_stmt, [
						'olduser' => $update_user,
						'newuser' => $newfieldvalue
					]);
				}
			}
		}

		return $returnvalue;
	}

	public static function storeSettingImage($fieldname, $fielddata)
	{
		if (isset($fielddata['settinggroup'], $fielddata['varname']) && is_array($fielddata) && $fielddata['settinggroup'] !== '' && $fielddata['varname'] !== '') {
			$save_to = null;
			$path = Froxlor::getInstallDir() . '/img/';
			$path = FileDir::makeCorrectDir($path);

			// New file?
			if (isset($_FILES[$fieldname]) && $_FILES[$fieldname]['tmp_name']) {
				// Make sure upload directory exists
				if (!is_dir($path) && !mkdir($path, 0775)) {
					throw new Exception("img directory does not exist and cannot be created");
				}

				// Make sure we can write to the upload directory
				if (!is_writable($path)) {
					if (!chmod($path, 0775)) {
						throw new Exception("Cannot write to img directory");
					}
				}

				// Make sure mime-type matches an image
				$image_content = file_get_contents($_FILES[$fieldname]['tmp_name']);
				$value = base64_encode($image_content);
				if (Validate::validateBase64Image($value)) {
					$img_filename = $_FILES[$fieldname]['name'];

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
					$filename = bin2hex(random_bytes(16)) . '.' . $file_extension;
					// Move file
					if (!move_uploaded_file($_FILES[$fieldname]['tmp_name'], $path . $filename)) {
						throw new Exception("Unable to save image to img folder");
					}
					$save_to = 'img/' . $filename . '?v=' . time();
				}
			}

			// Delete file?
			if ($fielddata['value'] !== "" && array_key_exists($fieldname . '_delete', $_POST) && Request::post($fieldname . '_delete')) {
				@unlink(Froxlor::getInstallDir() . '/' . explode('?', $fielddata['value'], 2)[0]);
				$save_to = '';
			}

			// Nothing changed
			if ($save_to === null) {
				return [
					$fielddata['settinggroup'] . '.' . $fielddata['varname'] => $fielddata['value']
				];
			}

			if (Settings::Set($fielddata['settinggroup'] . '.' . $fielddata['varname'], $save_to) === false) {
				return false;
			}

			return [
				$fielddata['settinggroup'] . '.' . $fielddata['varname'] => $save_to
			];
		}

		return false;
	}

	private static function cleanMySQLAccessHost($value)
	{
		if (substr($value, 0, 1) == '[' && substr($value, -1) == ']') {
			return substr($value, 1, -1);
		}
		return $value;
	}

	public static function storeSettingUpdateTrafficTool($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = self::storeSettingField($fieldname, $fielddata, $newfieldvalue);

		if ($returnvalue !== false && is_array($fielddata) && isset($fielddata['settinggroup']) && $fielddata['settinggroup'] == 'system' && isset($fielddata['varname']) && $fielddata['varname'] == 'traffictool' && $newfieldvalue != $fielddata['value']) {
			$oldpath = '/' . $fielddata['value'] . '/';
			$newpath = '/' . $newfieldvalue . '/';
			$sel_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_HTPASSWDS . "` WHERE `path` LIKE :oldpath");
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_HTPASSWDS . "` SET `path` = :newpath WHERE `id` = :id
			");
			Database::pexecute($sel_stmt, [
				'oldpath' => '%' . $oldpath
			]);
			while ($entry = $sel_stmt->fetch(\PDO::FETCH_ASSOC)) {
				$full_path = str_replace($oldpath, $newpath, $entry['path']);
				$eid = (int)$entry['id'];
				Database::pexecute($upd_stmt, [
					'newpath' => $full_path,
					'id' => $eid
				]);
			}
		}

		return $returnvalue;
	}
}
