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
use Froxlor\FileDir;

/**
 * Class frxDirectory handles directory actions and gives information
 * about a given directory in connections with its usage in froxlor
 */
class Directory
{

	/**
	 * directory string
	 *
	 * @var string
	 */
	private $dir = null;

	/**
	 * class constructor, optionally set directory
	 *
	 * @param string $dir
	 */
	public function __construct(?string $dir = null)
	{
		$this->dir = $dir;
	}

	/**
	 * check whether the directory has options set in panel_htaccess
	 *
	 * @return bool
	 */
	public function hasUserOptions(): bool
	{
		$uo_stmt = Database::prepare("
			SELECT COUNT(`id`) as `usropts` FROM `" . TABLE_PANEL_HTACCESS . "` WHERE `path` = :dir
		");
		$uo_res = Database::pexecute_first($uo_stmt, [
			'dir' => FileDir::makeCorrectDir($this->dir)
		]);
		if ($uo_res && isset($uo_res['usropts'])) {
			return $uo_res['usropts'] > 0;
		}
		return false;
	}

	/**
	 * check whether the directory is protected using panel_htpasswd
	 *
	 * @return bool
	 */
	public function isUserProtected(): bool
	{
		$up_stmt = Database::prepare("
			SELECT COUNT(`id`) as `usrprot` FROM `" . TABLE_PANEL_HTPASSWDS . "` WHERE `path` = :dir
		");
		$up_res = Database::pexecute_first($up_stmt, [
			'dir' => FileDir::makeCorrectDir($this->dir)
		]);
		if ($up_res && isset($up_res['usrprot'])) {
			return $up_res['usrprot'] > 0;
		}
		return false;
	}

	/**
	 * Checks if a given directory is valid for multiple configurations
	 * or should rather be used as a single file
	 *
	 * @param bool $ifexists also check whether file/dir exists
	 *
	 * @return bool true if usable as dir, false otherwise
	 */
	public function isConfigDir(bool $ifexists = false): bool
	{
		if (is_null($this->dir)) {
			trigger_error(__CLASS__ . '::' . __FUNCTION__ . ' has been called with a null value', E_USER_WARNING);
			return false;
		}

		if (file_exists($this->dir)) {
			if (is_dir($this->dir)) {
				$returnval = true;
			} else {
				$returnval = false;
			}
		} else {
			if (!$ifexists) {
				if (substr($this->dir, -1) == '/') {
					$returnval = true;
				} else {
					$returnval = false;
				}
			} else {
				$returnval = false;
			}
		}
		return $returnval;
	}
}
