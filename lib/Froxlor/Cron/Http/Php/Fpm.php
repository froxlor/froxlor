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
use InvalidArgumentException;

class Fpm
{

	/**
	 * Domain-Data array
	 *
	 * @var array
	 */
	private $domain = [];

	/**
	 * fpm config
	 *
	 * @var array
	 */
	private $fpm_cfg = [];

	/**
	 * Admin-Date cache array
	 *
	 * @var array
	 */
	private $admin_cache = [];

	/**
	 * defines what can be used for pool-config from php.ini
	 * Mostly taken from http://php.net/manual/en/ini.list.php
	 *
	 * @var array
	 */
	private $ini = [];

	/**
	 * main constructor
	 */
	public function __construct($domain)
	{
		if (!isset($domain['fpm_config_id']) || empty($domain['fpm_config_id'])) {
			$domain['fpm_config_id'] = 1;
		}
		$this->domain = $domain;
		$this->readFpmConfig($domain['fpm_config_id']);
		$this->buildIniMapping();
	}

	private function readFpmConfig($fpm_config_id)
	{
		$stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_FPMDAEMONS . "` WHERE `id` = :id");
		$this->fpm_cfg = Database::pexecute_first($stmt, [
			'id' => $fpm_config_id
		]);
	}

	private function buildIniMapping()
	{
		$this->ini = [
			'php_flag' => array_map('trim', explode("\n", Settings::Get('phpfpm.ini_flags'))),
			'php_value' => array_map('trim', explode("\n", Settings::Get('phpfpm.ini_values'))),
			'php_admin_flag' => array_map('trim', explode("\n", Settings::Get('phpfpm.ini_admin_flags'))),
			'php_admin_value' => array_map('trim', explode("\n", Settings::Get('phpfpm.ini_admin_values')))
		];
	}

	/**
	 * create a dummy fpm pool config with minimal configuration
	 * (this is used whenever a config directory is empty but needs at least one pool to startup/restart)
	 *
	 * @param string $configdir
	 */
	public static function createDummyPool($configdir)
	{
		if (!is_dir($configdir)) {
			FileDir::safe_exec('mkdir -p ' . escapeshellarg($configdir));
		}
		$config = FileDir::makeCorrectFile($configdir . '/dummy.conf');
		$dummy = "[dummy]
user = " . Settings::Get('system.httpuser') . "
listen = /run/" . md5($configdir) . "-fpm.sock
pm = static
pm.max_children = 1
";
		file_put_contents($config, $dummy);
	}

	/**
	 * create fpm-pool config
	 *
	 * @param array $phpconfig
	 */
	public function createConfig($phpconfig)
	{
		$fh = @fopen($this->getConfigFile(), 'w');

		if ($fh) {
			if ($phpconfig['override_fpmconfig'] == 1) {
				$this->fpm_cfg['pm'] = $phpconfig['pm'];
				$this->fpm_cfg['max_children'] = $phpconfig['max_children'];
				$this->fpm_cfg['start_servers'] = $phpconfig['start_servers'];
				$this->fpm_cfg['min_spare_servers'] = $phpconfig['min_spare_servers'];
				$this->fpm_cfg['max_spare_servers'] = $phpconfig['max_spare_servers'];
				$this->fpm_cfg['max_requests'] = $phpconfig['max_requests'];
				$this->fpm_cfg['idle_timeout'] = $phpconfig['idle_timeout'];
				$this->fpm_cfg['limit_extensions'] = $phpconfig['limit_extensions'];
			}

			$fpm_pm = $this->fpm_cfg['pm'];
			$fpm_children = (int)$this->fpm_cfg['max_children'];
			$fpm_start_servers = (int)$this->fpm_cfg['start_servers'];
			$fpm_min_spare_servers = (int)$this->fpm_cfg['min_spare_servers'];
			$fpm_max_spare_servers = (int)$this->fpm_cfg['max_spare_servers'];
			$fpm_requests = (int)$this->fpm_cfg['max_requests'];
			$fpm_process_idle_timeout = (int)$this->fpm_cfg['idle_timeout'];
			$fpm_limit_extensions = $this->fpm_cfg['limit_extensions'];
			$fpm_custom_config = $this->fpm_cfg['custom_config'];

			if ($fpm_children == 0) {
				$fpm_children = 1;
			}

			$fpm_config = ';PHP-FPM configuration for "' . $this->domain['domain'] . '" created on ' . date("Y.m.d H:i:s") . "\n";
			$fpm_config .= '[' . $this->domain['domain'] . ']' . "\n";
			$fpm_config .= 'listen = ' . $this->getSocketFile() . "\n";
			if ($this->domain['loginname'] == 'froxlor.panel') {
				$fpm_config .= 'listen.owner = ' . $this->domain['guid'] . "\n";
				$fpm_config .= 'listen.group = ' . $this->domain['guid'] . "\n";
			} else {
				$fpm_config .= 'listen.owner = ' . $this->domain['loginname'] . "\n";
				$fpm_config .= 'listen.group = ' . $this->domain['loginname'] . "\n";
			}
			// see #1418 why this is 0660
			$fpm_config .= 'listen.mode = 0660' . "\n";

			if ($this->domain['loginname'] == 'froxlor.panel') {
				$fpm_config .= 'user = ' . $this->domain['guid'] . "\n";
				$fpm_config .= 'group = ' . $this->domain['guid'] . "\n";
			} else {
				$fpm_config .= 'user = ' . $this->domain['loginname'] . "\n";
				$fpm_config .= 'group = ' . $this->domain['loginname'] . "\n";
			}

			$fpm_config .= 'pm = ' . $fpm_pm . "\n";
			$fpm_config .= 'pm.max_children = ' . $fpm_children . "\n";

			if ($fpm_pm == 'dynamic') {
				// honor max_children
				if ($fpm_children < $fpm_min_spare_servers) {
					$fpm_min_spare_servers = $fpm_children;
				}
				if ($fpm_children < $fpm_max_spare_servers) {
					$fpm_max_spare_servers = $fpm_children;
				}
				// failsafe, refs #955
				if ($fpm_start_servers < $fpm_min_spare_servers) {
					$fpm_start_servers = $fpm_min_spare_servers;
				}
				if ($fpm_start_servers > $fpm_max_spare_servers) {
					$fpm_start_servers = $fpm_max_spare_servers;
				}
				$fpm_config .= 'pm.start_servers = ' . $fpm_start_servers . "\n";
				$fpm_config .= 'pm.min_spare_servers = ' . $fpm_min_spare_servers . "\n";
				$fpm_config .= 'pm.max_spare_servers = ' . $fpm_max_spare_servers . "\n";
			} elseif ($fpm_pm == 'ondemand') {
				$fpm_config .= 'pm.process_idle_timeout = ' . $fpm_process_idle_timeout . "\n";
			}

			$fpm_config .= 'pm.max_requests = ' . $fpm_requests . "\n";
			$fpm_config .= 'request_terminate_timeout = ' . $phpconfig['fpm_reqterm'] . "\n";

			// possible slowlog configs
			if ($phpconfig['fpm_slowlog'] == '1') {
				$this->durationCompare($phpconfig['fpm_reqterm'], $phpconfig['fpm_reqslow']);
				$fpm_config .= 'request_slowlog_timeout = ' . $phpconfig['fpm_reqslow'] . "\n";
				$slowlog = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . '/' . $this->domain['loginname'] . '-php-slow.log');
				$fpm_config .= 'slowlog = ' . $slowlog . "\n";
				$fpm_config .= 'catch_workers_output = yes' . "\n";
			}

			$fpm_config .= ';chroot = ' . FileDir::makeCorrectDir($this->domain['documentroot']) . "\n";
			$fpm_config .= 'security.limit_extensions = ' . $fpm_limit_extensions . "\n";

			$tmpdir = FileDir::makeCorrectDir(Settings::Get('phpfpm.tmpdir') . '/' . $this->domain['loginname'] . '/');
			if (!is_dir($tmpdir)) {
				$this->getTempDir();
			}

			$env_path = Settings::Get('phpfpm.envpath');
			if (!empty($env_path)) {
				$fpm_config .= 'env[PATH] = ' . $env_path . "\n";
			}
			$fpm_config .= 'env[TMP] = ' . $tmpdir . "\n";
			$fpm_config .= 'env[TMPDIR] = ' . $tmpdir . "\n";
			$fpm_config .= 'env[TEMP] = ' . $tmpdir . "\n";

			$openbasedir = '';
			if ($this->domain['loginname'] != 'froxlor.panel') {
				if ($this->domain['openbasedir'] == '1') {
					$_phpappendopenbasedir = '';
					$_custom_openbasedir = explode(':', Settings::Get('phpfpm.peardir'));
					foreach ($_custom_openbasedir as $cobd) {
						$_phpappendopenbasedir .= Domain::appendOpenBasedirPath($cobd);
					}

					$_custom_openbasedir = explode(':', Settings::Get('system.phpappendopenbasedir'));
					foreach ($_custom_openbasedir as $cobd) {
						$_phpappendopenbasedir .= Domain::appendOpenBasedirPath($cobd);
					}

					if ($this->domain['openbasedir_path'] == '0' && strstr($this->domain['documentroot'], ":") === false) {
						$openbasedir = Domain::appendOpenBasedirPath($this->domain['documentroot'], true);
					} else if ($this->domain['openbasedir_path'] == '2' && strpos(dirname($this->domain['documentroot']) . '/', $this->domain['customerroot']) !== false) {
						$openbasedir = Domain::appendOpenBasedirPath(dirname($this->domain['documentroot']) . '/', true);
					} else {
						$openbasedir = Domain::appendOpenBasedirPath($this->domain['customerroot'], true);
					}

					$openbasedir .= Domain::appendOpenBasedirPath($this->getTempDir());
					$openbasedir .= $_phpappendopenbasedir;
				}
			}

			$fpm_config .= 'php_admin_value[upload_tmp_dir] = ' . FileDir::makeCorrectDir(Settings::Get('phpfpm.tmpdir') . '/' . $this->domain['loginname'] . '/') . "\n";

			$admin = $this->getAdminData($this->domain['adminid']);
			$php_ini_variables = [
				'SAFE_MODE' => 'Off', // keep this for compatibility, just in case
				'PEAR_DIR' => Settings::Get('phpfpm.peardir'),
				'TMP_DIR' => $this->getTempDir(),
				'CUSTOMER_EMAIL' => $this->domain['email'],
				'ADMIN_EMAIL' => $admin['email'],
				'DOMAIN' => $this->domain['domain'],
				'CUSTOMER' => $this->domain['loginname'],
				'ADMIN' => $admin['loginname'],
				'OPEN_BASEDIR' => $openbasedir,
				'OPEN_BASEDIR_C' => '',
				'OPEN_BASEDIR_GLOBAL' => Settings::Get('system.phpappendopenbasedir'),
				'DOCUMENT_ROOT' => FileDir::makeCorrectDir($this->domain['documentroot']),
				'CUSTOMER_HOMEDIR' => FileDir::makeCorrectDir($this->domain['customerroot'])
			];

			$phpini = PhpHelper::replaceVariables($phpconfig['phpsettings'], $php_ini_variables);
			$phpini_array = explode("\n", $phpini);

			$fpm_config .= "\n\n";
			foreach ($phpini_array as $inisection) {
				$is = explode("=", trim($inisection), 2);
				if (empty($is[0])) {
					continue;
				}
				foreach ($this->ini as $sec => $possibles) {
					if (in_array(trim($is[0]), $possibles)) {
						// check explicitly for open_basedir
						if (trim($is[0]) == 'open_basedir' && $openbasedir == '') {
							continue;
						}
						$fpm_config .= $sec . '[' . trim($is[0]) . '] = ' . trim($is[1] ?? '') . "\n";
					}
				}
			}

			// now check if 'sendmail_path' has not been set in the custom-php.ini
			// if not we use our fallback-default as usual
			if (strpos($fpm_config, 'php_admin_value[sendmail_path]') === false) {
				$fpm_config .= 'php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f postmaster@' . $this->domain['domain'] . "\n";
			}

			// check for session.save_path, whether it has been specified by the user, if not, set a default
			if (strpos($fpm_config, 'php_value[session.save_path]') === false && strpos($fpm_config, 'php_admin_value[session.save_path]') === false) {
				$fpm_config .= 'php_admin_value[session.save_path] = ' . $this->getTempDir() . "\n";
			}

			// append custom phpfpm configuration
			if (!empty($fpm_custom_config)) {
				$fpm_config .= "\n; Custom Configuration\n";
				$fpm_config .= PhpHelper::replaceVariables($fpm_custom_config, $php_ini_variables);
			}

			fwrite($fh, $fpm_config, strlen($fpm_config));
			fclose($fh);
		}
	}

	/**
	 * fpm-config file
	 *
	 * @param boolean $createifnotexists
	 *            create the directory if it does not exist
	 *
	 * @return string the full path to the file
	 */
	public function getConfigFile($createifnotexists = true)
	{
		$configdir = $this->fpm_cfg['config_dir'];
		$config = FileDir::makeCorrectFile($configdir . '/' . $this->domain['domain'] . '.conf');

		if (!is_dir($configdir) && $createifnotexists) {
			FileDir::safe_exec('mkdir -p ' . escapeshellarg($configdir));
		}

		return $config;
	}

	/**
	 * return path of fpm-socket file
	 *
	 * @param boolean $createifnotexists
	 *            create the directory if it does not exist
	 *
	 * @return string the full path to the socket
	 */
	public function getSocketFile($createifnotexists = true)
	{
		$socketdir = FileDir::makeCorrectDir(Settings::Get('phpfpm.fastcgi_ipcdir'));
		// add fpm-config-id to filename, so it's unique for the fpm-daemon and doesn't interfere with running configs when reuilding
		$socket_filename = $socketdir . '/' . $this->domain['fpm_config_id'] . '-' . $this->domain['loginname'] . '-' . $this->domain['domain'] . '-php-fpm.socket';
		if (strlen($socket_filename) > 100) {
			// respect the unix socket-length limitation
			$socket_filename = $socketdir . '/' . $this->domain['fpm_config_id'] . '-' . $this->domain['loginname'] . '-' . $this->domain['id'] . '-php-fpm.socket';
			if (strlen($socket_filename) > 100) {
				// even a long loginname it seems
				$socket_filename = $socketdir . '/' . $this->domain['fpm_config_id'] . '-' . $this->domain['guid'] . '-' . $this->domain['id'] . '-php-fpm.socket';
			}
		}
		$socket = strtolower(FileDir::makeCorrectFile($socket_filename));

		if (!is_dir($socketdir) && $createifnotexists) {
			FileDir::safe_exec('mkdir -p ' . escapeshellarg($socketdir));
			FileDir::safe_exec('chown -R ' . Settings::Get('system.httpuser') . ':' . Settings::Get('system.httpgroup') . ' ' . escapeshellarg($socketdir));
		}

		return $socket;
	}

	/**
	 * fpm-temp directory
	 *
	 * @param boolean $createifnotexists
	 *            create the directory if it does not exist
	 *
	 * @return string the directory
	 */
	public function getTempDir($createifnotexists = true)
	{
		$tmpdir = FileDir::makeCorrectDir(Settings::Get('phpfpm.tmpdir') . '/' . $this->domain['loginname'] . '/');

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
	 * this is done via createConfig as php-fpm defines
	 * the ini-values/flags in its pool-config
	 *
	 * @param string $phpconfig
	 */
	public function createIniFile($phpconfig)
	{
		return;
	}

	/**
	 * fastcgi-fakedirectory directory
	 *
	 * @param boolean $createifnotexists
	 *            create the directory if it does not exist
	 *
	 * @return string the directory
	 */
	public function getAliasConfigDir($createifnotexists = true)
	{
		// ensure default...
		if (Settings::Get('phpfpm.aliasconfigdir') == null) {
			Settings::Set('phpfpm.aliasconfigdir', '/var/www/php-fpm');
		}

		$configdir = FileDir::makeCorrectDir(Settings::Get('phpfpm.aliasconfigdir') . '/' . $this->domain['loginname'] . '/' . $this->domain['domain'] . '/');
		if (!is_dir($configdir) && $createifnotexists) {
			FileDir::safe_exec('mkdir -p ' . escapeshellarg($configdir));
			FileDir::safe_exec('chown ' . $this->domain['guid'] . ':' . $this->domain['guid'] . ' ' . escapeshellarg($configdir));
		}

		return $configdir;
	}

	/**
	 * 'request_slowlog_timeout' can't be greater than 'request_terminate_timeout'
	 *
	 * @param $request_terminate_timeout
	 * @param $request_slowlog_timeout
	 * @return void
	 */
	private function durationCompare(&$request_terminate_timeout, &$request_slowlog_timeout)
	{
		$to_seconds = function ($str) {
			if (!preg_match('/^([0-9]+)([smhd])?$/', $str, $matches)) {
				throw new InvalidArgumentException("Invalid format: $str");
			}
			$value = (int)$matches[1];
			$unit = $matches[2] ?? 's';

			switch ($unit) {
				case 'm':
					return $value * 60;
				case 'h':
					return $value * 3600;
				case 'd':
					return $value * 86400;
				default:
					return $value;
			}
		};

		$aSec = $to_seconds($request_terminate_timeout);
		$bSec = $to_seconds($request_slowlog_timeout);

		if ($bSec > $aSec) {
			$request_slowlog_timeout = $request_terminate_timeout;
		}
	}
}
