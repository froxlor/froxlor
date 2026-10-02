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

namespace Froxlor\Validate;

use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Settings;
use Froxlor\UI\Request;

class Check
{

	const FORMFIELDS_PLAUSIBILITY_CHECK_OK = 0;

	const FORMFIELDS_PLAUSIBILITY_CHECK_ERROR = 1;

	const FORMFIELDS_PLAUSIBILITY_CHECK_QUESTION = 2;

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 */
	public static function checkFcgidPhpFpm($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		$returnvalue = [
			self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
		];

		$check_array = [
			'system_mod_fcgid' => [
				'other_post_field' => 'phpfpm_enabled',
				'other_enabled' => 'phpfpm.enabled',
				'other_enabled_lng' => 'phpfpmstillenabled',
				'deactivate' => [
					'phpfpm.enabled_ownvhost' => 0
				]
			],
			'phpfpm_enabled' => [
				'other_post_field' => 'system_mod_fcgid',
				'other_enabled' => 'system.mod_fcgid',
				'other_enabled_lng' => 'fcgidstillenabled',
				'deactivate' => [
					'system.mod_fcgid_ownvhost' => 0
				]
			]
		];

		// interface is to be enabled
		if ((int)$newfieldvalue == 1) {
			// check for POST value of the other field == 1 (active)
			if ((int)Request::post($check_array[$fieldname]['other_post_field'], 0) == 1) {
				// the other interface is activated already and STAYS activated
				if ((int)Settings::Get($check_array[$fieldname]['other_enabled']) == 1) {
					$returnvalue = [
						self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
						$check_array[$fieldname]['other_enabled_lng']
					];
				} else {
					// fcgid is being validated before fpm -> "ask" fpm about its state
					if ($fieldname == 'system_mod_fcgid_enabled') {
						$returnvalue = self::checkFcgidPhpFpm(
							'system_phpfpm_enabled',
							null,
							$check_array[$fieldname]['other_post_field'],
							null
						);
					} else {
						// not, bot are nogo
						$returnvalue = $returnvalue = [
							self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
							'fcgidandphpfpmnogoodtogether'
						];
					}
				}
			} elseif ((int)Settings::Get($check_array[$fieldname]['other_enabled']) == 1) {
				// not in the same POST so we still need to check whether the other one's enabled
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
					$check_array[$fieldname]['other_enabled_lng']
				];
			}
			if (in_array(self::FORMFIELDS_PLAUSIBILITY_CHECK_OK, $returnvalue)) {
				// be sure to deactivate the other one for the froxlor-vhost
				// to avoid having a settings-deadlock
				foreach ($check_array[$fieldname]['deactivate'] as $setting => $value) {
					Settings::Set($setting, $value, true);
				}
			}
		}

		return $returnvalue;
	}

	public static function checkMysqlAccessHost($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		$mysql_access_host_array = array_unique(array_map('trim', explode(',', $newfieldvalue)));

		foreach ($mysql_access_host_array as $host_entry) {
			if (Validate::validate_ip2(
					$host_entry,
					true,
					'invalidip',
					true,
					true,
					true,
					true,
					false
				) == false && Validate::validateDomain($host_entry) == false && Validate::validateLocalHostname($host_entry) == false && $host_entry != '%') {
				return [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
					'invalidmysqlhost',
					$host_entry
				];
			}
		}

		return [
			self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
		];
	}

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 */
	public static function checkHostname($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		if (0 == strlen(trim($newfieldvalue)) || Validate::validateDomain($newfieldvalue) === false) {
			return [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
				'invalidhostname'
			];
		} else {
			return [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
			];
		}
	}

	/**
	 * check whether an email account is to be deleted
	 * reference: #1519
	 *
	 * @param string $email_addr
	 *
	 * @return bool true if the domain is to be deleted, false otherwise
	 * @throws \Exception
	 */
	public static function checkMailAccDeletionState(string $email_addr): bool
	{
		// example data of task 7: a:2:{s:9:"loginname";s:4:"webX";s:5:"email";s:20:"deleteme@example.tld";}

		// check for task
		$result_tasks_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '7' AND `data` LIKE :emailaddr
		");
		Database::pexecute($result_tasks_stmt, [
			'emailaddr' => "%" . $email_addr . "%"
		]);
		$num_results = Database::num_rows();

		// is there a task for deleting this email account?
		if ($num_results > 0) {
			return true;
		}
		return false;
	}

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 * @throws \Exception
	 */
	public static function checkPathConflicts($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		if ((int)Settings::Get('system.mod_fcgid') == 1) {
			// fcgid-configdir has changed -> check against customer-doc-prefix
			if ($fieldname == "system_mod_fcgid_configdir") {
				$newdir = FileDir::makeCorrectDir($newfieldvalue);
				$cdir = FileDir::makeCorrectDir(Settings::Get('system.documentroot_prefix'));
			} elseif ($fieldname == "system_documentroot_prefix") {
				// customer-doc-prefix has changed -> check against fcgid-configdir
				$newdir = FileDir::makeCorrectDir($newfieldvalue);
				$cdir = FileDir::makeCorrectDir(Settings::Get('system.mod_fcgid_configdir'));
			}

			// neither dir can be within the other nor can they be equal
			if (substr($newdir, 0, strlen($cdir)) == $cdir || substr(
					$cdir,
					0,
					strlen($newdir)
				) == $newdir || $newdir == $cdir) {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
					'fcgidpathcannotbeincustomerdoc'
				];
			} else {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
				];
			}
		} else {
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
			];
		}

		return $returnvalue;
	}

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 */
	public static function checkPhpInterfaceSetting($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		$returnvalue = [
			self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
		];

		if ((int)Settings::Get('system.mod_fcgid') == 1) {
			// fcgid only works for apache
			if (strtolower($newfieldvalue) != 'apache2') {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
					'fcgidstillenableddeadlock'
				];
			}
		}

		return $returnvalue;
	}

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 */
	public static function checkUsername($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		if (!isset($allnewfieldvalues['customer_mysqlprefix'])) {
			$allnewfieldvalues['customer_mysqlprefix'] = Settings::Get('customer.mysqlprefix');
		}

		$returnvalue = [];
		if (Validate::validateUsername(
				$newfieldvalue,
				Settings::Get('panel.unix_names'),
				Database::getSqlUsernameLength() - strlen($allnewfieldvalues['customer_mysqlprefix'])
			) === true) {
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
			];
		} else {
			$errmsg = 'accountprefixiswrong';
			if ($fieldname == 'customer_mysqlprefix') {
				$errmsg = 'mysqlprefixiswrong';
			}
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
				$errmsg
			];
		}
		return $returnvalue;
	}

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 */
	public static function checkLocalGroup($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		if (empty($newfieldvalue) || $fielddata['value'] == $newfieldvalue) {
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
			];
		} elseif (function_exists('posix_getgrnam') && posix_getgrnam($newfieldvalue) == false) {
			if (Validate::validateUsername($newfieldvalue, Settings::Get('panel.unix_names'), 32)) {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
				];
			} else {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
					'local_group_invalid'
				];
			}
		} else {
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
				'local_group_exists'
			];
		}
		return $returnvalue;
	}

	public static function checkPgpPublicKeySetting($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		// if the field is empty, we don't need to check anything
		if ($newfieldvalue === '') {
			return [self::FORMFIELDS_PLAUSIBILITY_CHECK_OK];
		}

		// check if gnupg extension is loaded
		if (!extension_loaded('gnupg')) {
			return [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
				'gnupgextensionnotavailable'
			];
		}
		// check if the pgp public key is a valid key
		putenv('GNUPGHOME=' . sys_get_temp_dir());
		if (gnupg_import(gnupg_init(), $newfieldvalue) === false) {
			return [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
				'invalidpgppublickey'
			];
		}

		return [self::FORMFIELDS_PLAUSIBILITY_CHECK_OK];
	}

	/**
	 * @param $fieldname
	 * @param $fielddata
	 * @param $newfieldvalue
	 * @param $allnewfieldvalues
	 * @return array|int[]
	 * @throws \Exception
	 */
	public static function checkSystemUsername($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		if (empty($newfieldvalue) || $fielddata['value'] == $newfieldvalue) {
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
			];
		} elseif (function_exists('posix_getpwnam') && posix_getpwnam($newfieldvalue) == false) {
			$returnvalue = [
				self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
				'local_user_invalid'
			];
		} else {
			// user exists, but cannot be one of the froxlor-customers
			$sel_stmt = Database::prepare("SELECT COUNT(*) as numUsers FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname` = :username");
			$result = Database::pexecute_first($sel_stmt, [':username' => $newfieldvalue]);
			if ($result && $result['numUsers'] > 0) {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR,
					'local_user_isfroxloruser'
				];
			} else {
				$returnvalue = [
					self::FORMFIELDS_PLAUSIBILITY_CHECK_OK
				];
			}
		}
		return $returnvalue;
	}
}
