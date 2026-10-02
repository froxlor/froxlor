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

use Exception;
use ZipArchive;
use Froxlor\Froxlor;
use Froxlor\Settings;
use Froxlor\Http\HttpClient;

class AutoUpdate
{
	// define update-uri
	const UPDATE_URI = "https://version.froxlor.org/froxlor/api/v2/";
	const RELEASE_URI = "https://autoupdate.froxlor.org/froxlor-{version}.zip";
	const CHECKSUM_URI = "https://autoupdate.froxlor.org/froxlor-{version}.zip.sha256";

	const ERR_NOZIPEXT = 2;
	const ERR_COULDNOTSTORE = 4;
	const ERR_ZIPNOTFOUND = 7;
	const ERR_COULDNOTEXTRACT = 8;
	const ERR_CHKSUM_MISMATCH = 9;
	const ERR_MINPHP = 10;

	private static $latestversion = "";

	private static $lasterror = "";

	/**
	 * returns status about whether there is a newer version
	 *
	 * 0 = no new version available
	 * 1 = new version available
	 * -1 = remote error message
	 * >1 = local error message
	 *
	 * @return int
	 */
	public static function checkVersion(): int
	{
		$result = self::checkPrerequisites();

		if ($result == 0) {
			try {
				$channel = '';
				if (Settings::Get('system.update_channel') == 'testing') {
					$channel = '/testing';
				} elseif (Settings::Get('system.update_channel') == 'nightly') {
					if (empty(Froxlor::BRANDING) || substr(Froxlor::BRANDING, 0, 1) == '-') {
						$channel = '/nightly.0000000';
					} else {
						$channel = '/' . substr(Froxlor::BRANDING, 1);
					}
				}
				$latestversion = HttpClient::urlGet(self::UPDATE_URI . Froxlor::VERSION . $channel, true, 3);
			} catch (Exception $e) {
				self::$lasterror = "Version-check currently unavailable, please try again later";
				return -1;
			}

			self::$latestversion = json_decode($latestversion, true);

			if (self::$latestversion) {
				if (!empty(self::$latestversion['error']) && self::$latestversion['error']) {
					$result = -1;
					self::$lasterror = self::$latestversion['message'];
				} elseif (isset(self::$latestversion['has_latest']) && self::$latestversion['has_latest'] == false) {
					$result = 1;
				}
			}
		}
		return $result;
	}

	public static function downloadZip(string $newversion)
	{
		// define files to get
		$toLoad = str_replace('{version}', $newversion, self::RELEASE_URI);
		$toCheck = str_replace('{version}', $newversion, self::CHECKSUM_URI);

		// check for local destination folder
		if (!is_dir(Froxlor::getInstallDir() . '/updates/')) {
			mkdir(Froxlor::getInstallDir() . '/updates/');
		}

		// name archive
		$localArchive = Froxlor::getInstallDir() . '/updates/' . basename($toLoad);

		// remove old archive
		if (file_exists($localArchive)) {
			@unlink($localArchive);
		}

		// get archive data
		try {
			HttpClient::fileGet($toLoad, $localArchive);
		} catch (Exception $e) {
			return self::ERR_COULDNOTSTORE;
		}

		// validate the integrity of the downloaded file
		$_shouldsum = HttpClient::urlGet($toCheck);
		if (!empty($_shouldsum)) {
			$_t = explode(" ", $_shouldsum);
			$shouldsum = $_t[0];
		} else {
			$shouldsum = null;
		}
		$filesum = hash_file('sha256', $localArchive);

		if ($filesum != $shouldsum) {
			return self::ERR_CHKSUM_MISMATCH;
		}

		return basename($localArchive);
	}

	public static function extractZip(string $localArchive): int
	{
		if (!file_exists($localArchive)) {
			return self::ERR_ZIPNOTFOUND;
		}
		// decompress from zip
		$zip = new ZipArchive();
		$res = $zip->open($localArchive);
		if ($res === true) {
			$zip->extractTo(Froxlor::getInstallDir());
			$zip->close();
			// success - remove unused archive
			@unlink($localArchive);
			// reset cached version check
			Settings::Set('system.updatecheck_data', '');
			// wait a bit before we redirect to be sure
			sleep(3);
			return 0;
		}
		return self::ERR_COULDNOTEXTRACT;
	}

	private static function checkPrerequisites(): int
	{
		if (!extension_loaded('zip')) {
			return self::ERR_NOZIPEXT;
		}
		if (version_compare("7.4.0", PHP_VERSION, ">=")) {
			return self::ERR_MINPHP;
		}
		return 0;
	}

	public static function getLastError(): string
	{
		return self::$lasterror ?? "";
	}

	public static function getFromResult(string $index)
	{
		return self::$latestversion[$index] ?? "";
	}
}
