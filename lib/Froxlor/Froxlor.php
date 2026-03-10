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

use Froxlor\Database\Database;

final class Froxlor
{

	// Main version variable
	const VERSION = '2.3.5';

	// Database version (YYYYMMDDC where C is a daily counter)
	const DBVERSION = '202512280';

	// Distribution branding-tag (used for Debian etc.)
	const BRANDING = '';

	const DOCS_URL = 'https://docs.froxlor.org';

	/**
	 * return path to where froxlor is installed, e.g.
	 * /var/www/froxlor/
	 *
	 * @return string
	 */
	public static function getInstallDir(): string
	{
		return dirname(__DIR__, 2) . '/';
	}

	public static function getDocsUrl(): string
	{
		if (preg_match('/(.+)-(dev|beta|rc)\d+$/', self::VERSION)) {
			return self::DOCS_URL . '/dev/';
		}
		return self::DOCS_URL . '/v' . self::getShortVersion() . '/';
	}

	/**
	 * return basic version
	 *
	 * @return string
	 */
	public static function getVersion(): string
	{
		return self::VERSION;
	}

	/**
	 * return short basic version
	 *
	 * @return string
	 */
	public static function getShortVersion(): string
	{
		return explode(".", self::VERSION)[0] . '.' . explode(".", self::VERSION)[1];
	}

	/**
	 * return version + branding and database-version
	 *
	 * @return string
	 */
	public static function getVersionString(): string
	{
		return self::getFullVersion() . ' (' . self::DBVERSION . ')';
	}

	/**
	 * return version + branding
	 *
	 * @return string
	 */
	public static function getFullVersion(): string
	{
		return self::VERSION . self::BRANDING;
	}

	/**
	 * Function hasUpdates
	 *
	 * checks if a given version is not equal the current one
	 *
	 * @param string $to_check version to check, if empty current version is used
	 *
	 * @return bool true if version to check does not match, else false
	 */
	public static function hasUpdates(string $to_check = ''): bool
	{
		if (empty($to_check)) {
			$to_check = self::VERSION;
		}
		if (Settings::Get('panel.version') == null || Settings::Get('panel.version') != $to_check) {
			return true;
		}
		return false;
	}

	/**
	 * Function hasDbUpdates
	 *
	 * checks if a given database-version is not equal the current one
	 *
	 * @param string $to_check version to check, if empty current dbversion is used
	 *
	 * @return bool true if version to check does not match, else false
	 */
	public static function hasDbUpdates(string $to_check = ''): bool
	{
		if (empty($to_check)) {
			$to_check = self::DBVERSION;
		}
		if (Settings::Get('panel.db_version') == null || Settings::Get('panel.db_version') != $to_check) {
			return true;
		}
		return false;
	}

	/**
	 * Function isDatabaseVersion
	 *
	 * checks if a given database-version is the current one
	 *
	 * @param string $to_check version to check
	 *
	 * @return bool true if version to check matches, else false
	 */
	public static function isDatabaseVersion(string $to_check): bool
	{
		if (Settings::Get('panel.frontend') == 'froxlor' && Settings::Get('panel.db_version') == $to_check) {
			return true;
		}
		return false;
	}

	/**
	 * Function updateToDbVersion
	 *
	 * updates the panel.version field
	 * to the given value (no checks here!)
	 *
	 * @param string $new_version new-version
	 *
	 * @return bool true on success, else false
	 * @throws \Exception
	 */
	public static function updateToDbVersion(string $new_version): bool
	{
		if ($new_version != '') {
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_SETTINGS . "` SET `value` = :newversion
				WHERE `settinggroup` = 'panel' AND `varname` = 'db_version'");
			Database::pexecute($upd_stmt, [
				'newversion' => $new_version
			]);
			Settings::Set('panel.db_version', $new_version);
			return true;
		}
		return false;
	}

	/**
	 * Function updateToVersion
	 *
	 * updates the panel.version field
	 * to the given value (no checks here!)
	 *
	 * @param string $new_version new-version
	 *
	 * @return bool true on success, else false
	 * @throws \Exception
	 */
	public static function updateToVersion(string $new_version): bool
	{
		if ($new_version != '') {
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_SETTINGS . "` SET `value` = :newversion
				WHERE `settinggroup` = 'panel' AND `varname` = 'version'");
			Database::pexecute($upd_stmt, [
				'newversion' => $new_version
			]);
			Settings::Set('panel.version', $new_version);
			return true;
		}
		return false;
	}

	/**
	 * Function isFroxlor
	 *
	 * checks if the panel is froxlor
	 *
	 * @return bool true if panel is froxlor, else false
	 */
	public static function isFroxlor(): bool
	{
		if (Settings::Get('panel.frontend') !== null && Settings::Get('panel.frontend') == 'froxlor') {
			return true;
		}
		return false;
	}

	/**
	 * Function isFroxlorVersion
	 *
	 * checks if a given version is the
	 * current one (and panel is froxlor)
	 *
	 * @param string $to_check version to check
	 *
	 * @return bool true if version to check matches, else false
	 */
	public static function isFroxlorVersion(string $to_check): bool
	{
		if (Settings::Get('panel.frontend') == 'froxlor' && Settings::Get('panel.version') == $to_check) {
			return true;
		}
		return false;
	}

	/**
	 * generate safe unique session id
	 *
	 * @param int $length
	 * @return string
	 * @throws \Exception
	 */
	public static function genSessionId(int $length = 16): string
	{
		if ($length <= 8) {
			$length = 16;
		}
		if (function_exists('random_bytes')) {
			return bin2hex(random_bytes($length));
		}
		if (function_exists('mcrypt_create_iv') && defined('MCRYPT_DEV_URANDOM')) {
			return bin2hex(mcrypt_create_iv($length, MCRYPT_DEV_URANDOM));
		}
		if (function_exists('openssl_random_pseudo_bytes')) {
			return bin2hex(openssl_random_pseudo_bytes($length));
		}
		// if everything else fails, use unsafe fallback
		return md5(uniqid(microtime(), 1));
	}

	/**
	 * compare of froxlor versions
	 *
	 * @param string $a
	 * @param string $b
	 *
	 * @return int 0 if equal, 1 if a>b and -1 if b>a
	 */
	public static function versionCompare2(string $a, string $b): int
	{
		// split version into pieces and remove trailing .0
		$a = explode(".", $a);
		$b = explode(".", $b);

		self::parseVersionArray($a);
		self::parseVersionArray($b);

		while (count($a) != count($b)) {
			if (count($a) < count($b)) {
				$a[] = '0';
			} elseif (count($b) < count($a)) {
				$b[] = '0';
			}
		}

		foreach ($a as $depth => $aVal) {
			// iterate over each piece of A
			if (isset($b[$depth])) {
				// if B matches A to this depth, compare the values
				if ($aVal > $b[$depth]) {
					return 1; // A > B
				} elseif ($aVal < $b[$depth]) {
					return -1; // B > A
				}
				// an equal result is inconclusive at this point
			} else {
				// if B does not match A to this depth, then A comes after B in sort order
				return 1; // so A > B
			}
		}
		// at this point, we know that to the depth that A and B extend to, they are equivalent.
		// either the loop ended because A is shorter than B, or both are equal.
		return (count($a) < count($b)) ? -1 : 0;
	}

	/**
	 * @param array|null $arr
	 * @return void
	 */
	private static function parseVersionArray(?array &$arr)
	{
		// -dev or -beta or -rc ?
		if (stripos($arr[count($arr) - 1], '-') !== false) {
			$x = explode("-", $arr[count($arr) - 1]);
			$arr[count($arr) - 1] = $x[0];
			if (stripos($x[1], 'rc') !== false) {
				$arr[] = '-1';
				$arr[] = '2'; // dev < beta < rc
				// number of rc
				$arr[] = substr($x[1], 2);
			} else {
				if (stripos($x[1], 'beta') !== false) {
					$arr[] = '-1';
					$arr[] = '1'; // dev < beta < rc
					// number of beta
					$arr[] = substr($x[1], 3);
				} else {
					if (stripos($x[1], 'dev') !== false) {
						$arr[] = '-1';
						$arr[] = '0'; // dev < beta < rc
						// number of dev
						$arr[] = substr($x[1], 3);
					}
				}
			}
		}
	}
}
