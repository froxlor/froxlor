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

namespace Froxlor\Cron\Http\Php;

use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use Froxlor\FileDir;
use Froxlor\PhpHelper;
use Froxlor\Settings;

class Fcgid
{

	/**
	 * Domain-Data array
	 *
	 * @var array
	 */
	private $domain = [];

	/**
	 * Admin-Date cache array
	 *
	 * @var array
	 */
	private $admin_cache = [];

	/**
	 * main constructor
	 */
	public function __construct($domain)
	{
		$this->domain = $domain;
	}

	/**
	 * create fcgid-starter-file
	 *
	 * @param array $phpconfig
	 */
	public function createConfig($phpconfig)
	{
		// create starter
		$starter_file = "#!/bin/sh\n\n";
		$starter_file .= "#\n";
		$starter_file .= "# starter created/changed on " . date("Y.m.d H:i:s") . " for domain '" . $this->domain['domain'] . "' with id #" . $this->domain['id'] . " from php template '" . $phpconfig['description'] . "' with id #" . $phpconfig['id'] . "\n";
		$starter_file .= "# Do not change anything in this file, it will be overwritten by the Froxlor Cronjob!\n";
		$starter_file .= "#\n\n";
		$starter_file .= "umask " . $phpconfig['mod_fcgid_umask'] . "\n";
		$starter_file .= "PHPRC=" . escapeshellarg($this->getConfigDir()) . "\n";
		$starter_file .= "export PHPRC\n";

		// set number of processes for one domain
		if ((int)$this->domain['mod_fcgid_starter'] != -1) {
			$starter_file .= "PHP_FCGI_CHILDREN=" . (int)$this->domain['mod_fcgid_starter'] . "\n";
		} else {
			if ((int)$phpconfig['mod_fcgid_starter'] != -1) {
				$starter_file .= "PHP_FCGI_CHILDREN=" . (int)$phpconfig['mod_fcgid_starter'] . "\n";
			} else {
				$starter_file .= "PHP_FCGI_CHILDREN=" . (int)Settings::Get('system.mod_fcgid_starter') . "\n";
			}
		}

		$starter_file .= "export PHP_FCGI_CHILDREN\n";

		// set number of maximum requests for one domain
		if ((int)$this->domain['mod_fcgid_maxrequests'] != -1) {
			$starter_file .= "PHP_FCGI_MAX_REQUESTS=" . (int)$this->domain['mod_fcgid_maxrequests'] . "\n";
		} else {
			if ((int)$phpconfig['mod_fcgid_maxrequests'] != -1) {
				$starter_file .= "PHP_FCGI_MAX_REQUESTS=" . (int)$phpconfig['mod_fcgid_maxrequests'] . "\n";
			} else {
				$starter_file .= "PHP_FCGI_MAX_REQUESTS=" . (int)Settings::Get('system.mod_fcgid_maxrequests') . "\n";
			}
		}

		$starter_file .= "export PHP_FCGI_MAX_REQUESTS\n";

		// Set Binary
		$starter_file .= "exec " . $phpconfig['binary'] . " -c " . escapeshellarg($this->getConfigDir()) . "\n";

		// remove +i attribute, so starter can be overwritten
		if (file_exists($this->getStarterFile())) {
			FileDir::removeImmutable($this->getStarterFile());
		}

		$starter_file_handler = fopen($this->getStarterFile(), 'w');
		fwrite($starter_file_handler, $starter_file);
		fclose($starter_file_handler);
		FileDir::safe_exec('chmod 750 ' . escapeshellarg($this->getStarterFile()));
		FileDir::safe_exec('chown ' . $this->domain['guid'] . ':' . $this->domain['guid'] . ' ' . escapeshellarg($this->getStarterFile()));
		FileDir::setImmutable($this->getStarterFile());
	}

	/**
	 * fcgid-config directory
	 *
	 * @param boolean $createifnotexists
	 *            create the directory if it does not exist
	 *
	 * @return string the directory
	 */
	public function getConfigDir($createifnotexists = true)
	{
		$configdir = FileDir::makeCorrectDir(Settings::Get('system.mod_fcgid_configdir') . '/' . $this->domain['loginname'] . '/' . $this->domain['domain'] . '/');

		if (!is_dir($configdir) && $createifnotexists) {
			FileDir::safe_exec('mkdir -p ' . escapeshellarg($configdir));
			FileDir::safe_exec('chmod 0755 ' . escapeshellarg(dirname($configdir)));
			FileDir::safe_exec('chmod 0755 ' . escapeshellarg($configdir));
			FileDir::safe_exec('chown ' . $this->domain['guid'] . ':' . $this->domain['guid'] . ' ' . escapeshellarg($configdir));
		}

		return $configdir;
	}

	/**
	 * return path of php-starter file
	 *
	 * @return string the directory
	 */
	public function getStarterFile()
	{
		$starter_filename = FileDir::makeCorrectFile($this->getConfigDir() . '/php-fcgi-starter');
		return $starter_filename;
	}

	/**
	 * create customized php.ini
	 *
	 * @param array $phpconfig
	 */
	public function createIniFile($phpconfig)
	{
		$openbasedir = '';
		$openbasedirc = ';';

		if ($this->domain['openbasedir'] == '1') {
			$openbasedirc = '';
			$_phpappendopenbasedir = '';

			$_custom_openbasedir = explode(':', Settings::Get('system.mod_fcgid_peardir'));
			foreach ($_custom_openbasedir as $cobd) {
				$_phpappendopenbasedir .= Domain::appendOpenBasedirPath($cobd);
			}

			$_custom_openbasedir = explode(':', Settings::Get('system.phpappendopenbasedir'));
			foreach ($_custom_openbasedir as $cobd) {
				$_phpappendopenbasedir .= Domain::appendOpenBasedirPath($cobd);
			}

			if ($this->domain['openbasedir_path'] == '0' && strstr($this->domain['documentroot'], ":") === false) {
				$openbasedir = Domain::appendOpenBasedirPath($this->domain['documentroot'], true);
			} else if ($this->domain['openbasedir_path'] == '2' && strpos(dirname($this->domain['documentroot']).'/', $this->domain['customerroot']) !== false) {
				$openbasedir = Domain::appendOpenBasedirPath(dirname($this->domain['documentroot']).'/', true);
			} else {
				$openbasedir = Domain::appendOpenBasedirPath($this->domain['customerroot'], true);
			}

			$openbasedir .= Domain::appendOpenBasedirPath($this->getTempDir());
			$openbasedir .= $_phpappendopenbasedir;
		} else {
			$openbasedir = 'none';
			$openbasedirc = ';';
		}

		$admin = $this->getAdminData($this->domain['adminid']);
		$php_ini_variables = [
			'SAFE_MODE' => 'Off', // keep this for compatibility, just in case
			'PEAR_DIR' => Settings::Get('system.mod_fcgid_peardir'),
			'TMP_DIR' => $this->getTempDir(),
			'CUSTOMER_EMAIL' => $this->domain['email'],
			'ADMIN_EMAIL' => $admin['email'],
			'DOMAIN' => $this->domain['domain'],
			'CUSTOMER' => $this->domain['loginname'],
			'ADMIN' => $admin['loginname'],
			'OPEN_BASEDIR' => $openbasedir,
			'OPEN_BASEDIR_C' => $openbasedirc,
			'OPEN_BASEDIR_GLOBAL' => Settings::Get('system.phpappendopenbasedir'),
			'DOCUMENT_ROOT' => FileDir::makeCorrectDir($this->domain['documentroot']),
			'CUSTOMER_HOMEDIR' => FileDir::makeCorrectDir($this->domain['customerroot'])
		];

		// insert a small header for the file
		$phpini_file = ";\n";
		$phpini_file .= "; php.ini created/changed on " . date("Y.m.d H:i:s") . " for domain '" . $this->domain['domain'] . "' with id #" . $this->domain['id'] . " from php template '" . $phpconfig['description'] . "' with id #" . $phpconfig['id'] . "\n";
		$phpini_file .= "; Do not change anything in this file, it will be overwritten by the Froxlor Cronjob!\n";
		$phpini_file .= ";\n\n";
		$phpini_file .= PhpHelper::replaceVariables($phpconfig['phpsettings'], $php_ini_variables);
		$phpini_file = str_replace('"none"', 'none', $phpini_file);
		// $phpini_file = preg_replace('/\"+/', '"', $phpini_file);
		$phpini_file_handler = fopen($this->getIniFile(), 'w');
		fwrite($phpini_file_handler, $phpini_file);
		fclose($phpini_file_handler);
		FileDir::safe_exec('chown root:0 ' . escapeshellarg($this->getIniFile()));
		FileDir::safe_exec('chmod 0644 ' . escapeshellarg($this->getIniFile()));
	}

	/**
	 * fcgid-temp directory
	 *
	 * @param boolean $createifnotexists
	 *            create the directory if it does not exist
	 *
	 * @return string the directory
	 */
	public function getTempDir($createifnotexists = true)
	{
		$tmpdir = FileDir::makeCorrectDir(Settings::Get('system.mod_fcgid_tmpdir') . '/' . $this->domain['loginname'] . '/');

		if (!is_dir($tmpdir) && $createifnotexists) {
			FileDir::safe_exec('mkdir -p ' . escapeshellarg($tmpdir));
			FileDir::safe_exec('chown -R ' . $this->domain['guid'] . ':' . $this->domain['guid'] . ' ' . escapeshellarg($tmpdir));
			FileDir::safe_exec('chmod 0750 ' . escapeshellarg($tmpdir));
		}

		return $tmpdir;
	}

	/**
	 * return the admin-data of a specific admin
	 *
	 * @param int $adminid
	 *            id of the admin-user
	 *
	 * @return array
	 */
	private function getAdminData($adminid)
	{
		$adminid = intval($adminid);

		if (!isset($this->admin_cache[$adminid])) {
			$stmt = Database::prepare("
					SELECT `email`, `loginname` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `adminid` = :id");
			$this->admin_cache[$adminid] = Database::pexecute_first($stmt, [
				'id' => $adminid
			]);
		}
		return $this->admin_cache[$adminid];
	}

	/**
	 * return path of php.ini file
	 *
	 * @return string full with path file-name
	 */
	public function getIniFile()
	{
		$phpini_filename = FileDir::makeCorrectFile($this->getConfigDir() . '/php.ini');
		return $phpini_filename;
	}
}
