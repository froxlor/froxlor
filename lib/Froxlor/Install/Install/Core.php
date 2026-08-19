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

namespace Froxlor\Install\Install;

use Exception;
use Froxlor\Config\ConfigParser;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use PDO;
use PDOException;
use PDOStatement;

/**
 * Installation of the froxlor core database and set settings.
 */
class Core
{
	protected array $validatedData;

	public function __construct(array $validatedData)
	{
		$this->validatedData = $validatedData;
	}

	/**
	 * no missing fields or data -> perform actual install
	 *
	 * @return void
	 * @throws Exception
	 */
	public function doInstall(bool $create_ud_str = true)
	{
		$options = [
			'PDO::MYSQL_ATTR_INIT_COMMAND' => 'SET names utf8'
		];

		if (!empty($this->validatedData['mysql_ssl_ca_file'])) {
			$options[PDO::MYSQL_ATTR_SSL_CA] = $this->validatedData['mysql_ssl_ca_file'];
			$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)$this->validatedData['mysql_ssl_verify_server_certificate'];
		}

		$dsn = "mysql:host=" . $this->validatedData['mysql_host'] . ";";
		try {
			$db_root = new PDO($dsn, $this->validatedData['mysql_root_user'], $this->validatedData['mysql_root_pass'], $options);
		} catch (PDOException $e) {
			// login failed; try to log in without passwd
			try {
				$db_root = new PDO($dsn, $this->validatedData['mysql_root_user'], '', $options);
				// set the given password
				$passwd_stmt = $db_root->prepare("
					SET PASSWORD = PASSWORD(:passwd)
				");
				$passwd_stmt->execute([
					'passwd' => $this->validatedData['mysql_root_pass']
				]);
			} catch (PDOException $e) {
				// login has failed; with and without password
				throw new Exception(lng('install.errors.privileged_sql_connection_failed'), 0, $e);
			}
		}

		$version_server = $db_root->getAttribute(PDO::ATTR_SERVER_VERSION);
		$sql_mode = 'NO_ENGINE_SUBSTITUTION';
		if (version_compare($version_server, '8.0.11', '<')) {
			$sql_mode .= ',NO_AUTO_CREATE_USER';
		}
		$db_root->exec('SET sql_mode = "' . $sql_mode . '"');

		// ok, if we are here, the database connection is up and running
		// check for existing pdo and create backup if so
		$this->backupExistingDatabase($db_root);
		// create unprivileged user and the database itself
		$this->createDatabaseAndUser($db_root);
		// importing data to new database
		$this->importDatabaseData();

		// create DB object for new database
		$options = [
			'PDO::MYSQL_ATTR_INIT_COMMAND' => 'SET names utf8'
		];

		if (!empty($this->validatedData['mysql_ssl_ca_file']) && isset($this->validatedData['mysql_ssl_verify_server_certificate'])) {
			$options[PDO::MYSQL_ATTR_SSL_CA] = $this->validatedData['mysql_ssl_ca_file'];
			$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)$this->validatedData['mysql_ssl_verify_server_certificate'];
		}

		$pdo = $this->getUnprivilegedPdo();

		// change settings accordingly
		$this->doSettings($pdo);
		// create entries
		$this->doDataEntries($pdo);
		// create JSON array for config-services
		$this->createJsonArray($pdo);
		if ($create_ud_str) {
			$this->createUserdataParamStr();
		}
	}

	/**
	 * @throws Exception
	 */
	public function getUnprivilegedPdo(): PDO
	{
		$options = [
			'PDO::MYSQL_ATTR_INIT_COMMAND' => 'SET names utf8'
		];

		if (!empty($this->validatedData['mysql_ssl_ca_file'])) {
			$options[PDO::MYSQL_ATTR_SSL_CA] = $this->validatedData['mysql_ssl_ca_file'];
			$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)$this->validatedData['mysql_ssl_verify_server_certificate'];
		}

		$dsn = "mysql:host=" . $this->validatedData['mysql_host'] . ";dbname=" . $this->validatedData['mysql_database'] . ";";
		try {
			$pdo = new PDO($dsn, $this->validatedData['mysql_unprivileged_user'], $this->validatedData['mysql_unprivileged_pass'], $options);
			$version_server = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);
			$sql_mode = 'NO_ENGINE_SUBSTITUTION';
			if (version_compare($version_server, '8.0.11', '<')) {
				$sql_mode .= ',NO_AUTO_CREATE_USER';
			}
			$pdo->exec('SET sql_mode = "' . $sql_mode . '"');
			return $pdo;
		} catch (PDOException $e) {
			throw new Exception(lng('install.errors.unexpected_database_error', [$e->getMessage()]), 0, $e);
		}
	}

	/**
	 * Check if an old database exists and back it up if necessary
	 *
	 * @param object $db_root
	 * @return void
	 * @throws Exception
	 */
	private function backupExistingDatabase(object &$db_root)
	{
		// check for existing of former database
		$stmt = $db_root->prepare("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = :database");
		$stmt->execute([
			'database' => $this->validatedData['mysql_database']
		]);
		$rows = $db_root->query("SELECT FOUND_ROWS()")->fetchColumn();

		// backup tables if exist
		if ($rows > 0) {
			if (!$this->validatedData['mysql_force_create']) {
				throw new Exception(lng('install.errors.database_already_exiting'));
			}

			// create temporary backup-filename
			$filename = "/tmp/froxlor_backup_" . date('YmdHi') . ".sql";

			// look for mysqldump
			$section = 'mysqldump';
			if (file_exists("/usr/bin/mysqldump")) {
				$mysql_dump = '/usr/bin/mysqldump';
			} elseif (file_exists("/usr/local/bin/mysqldump")) {
				$mysql_dump = '/usr/local/bin/mysqldump';
			} elseif (file_exists("/usr/bin/mariadb-dump")) {
				$mysql_dump = '/usr/bin/mariadb-dump';
				$section = 'mariadb-dump';
			}

			// create temporary .cnf file
			$cnffilename = "/tmp/froxlor_dump.cnf";
			$dumpcnf = "[".$section."]" . PHP_EOL . "password=\"" . $this->validatedData['mysql_root_pass'] . "\"" . PHP_EOL;
			file_put_contents($cnffilename, $dumpcnf);

			// make the backup
			if (isset($mysql_dump)) {
				$command = $mysql_dump . " --defaults-extra-file=" . $cnffilename . " " . escapeshellarg($this->validatedData['mysql_database']) . " -u " . escapeshellarg($this->validatedData['mysql_root_user']) . " --result-file=" . $filename;
				$output = [];
				exec($command, $output);
				@unlink($cnffilename);
				if (stristr(implode(" ", $output), "error")) {
					throw new Exception(lng('install.errors.mysqldump_backup_failed'));
				} elseif (!file_exists($filename)) {
					throw new Exception(lng('install.errors.sql_backup_file_missing'));
				}
			} else {
				throw new Exception(lng('install.errors.backup_binary_missing'));
			}
		}
	}

	/**
	 * Create database and database-user
	 *
	 * @param object $db_root
	 * @return void
	 * @throws Exception
	 */
	private function createDatabaseAndUser(object &$db_root)
	{
		$this->validatedData['mysql_access_host'] = $this->validatedData['mysql_host'];

		// so first we have to delete the database and
		// the user given for the unpriv-user if they exit
		$del_stmt = $db_root->prepare("DELETE FROM `mysql`.`user` WHERE `User` = :user AND `Host` = :accesshost");
		$del_stmt->execute([
			'user' => $this->validatedData['mysql_unprivileged_user'],
			'accesshost' => $this->validatedData['mysql_access_host']
		]);

		$del_stmt = $db_root->prepare("DELETE FROM `mysql`.`db` WHERE `User` = :user AND `Host` = :accesshost");
		$del_stmt->execute([
			'user' => $this->validatedData['mysql_unprivileged_user'],
			'accesshost' => $this->validatedData['mysql_access_host']
		]);

		$del_stmt = $db_root->prepare("DELETE FROM `mysql`.`tables_priv` WHERE `User` = :user AND `Host` =:accesshost");
		$del_stmt->execute([
			'user' => $this->validatedData['mysql_unprivileged_user'],
			'accesshost' => $this->validatedData['mysql_access_host']
		]);

		$del_stmt = $db_root->prepare("DELETE FROM `mysql`.`columns_priv` WHERE `User` = :user AND `Host` = :accesshost");
		$del_stmt->execute([
			'user' => $this->validatedData['mysql_unprivileged_user'],
			'accesshost' => $this->validatedData['mysql_access_host']
		]);

		$del_stmt = $db_root->prepare("DROP DATABASE IF EXISTS `" . str_replace('`', '', $this->validatedData['mysql_database']) . "`;");
		$del_stmt->execute();

		$db_root->query("FLUSH PRIVILEGES;");

		// we have to create a new user and database for the froxlor unprivileged mysql access
		$ins_stmt = $db_root->prepare("CREATE DATABASE `" . str_replace('`', '', $this->validatedData['mysql_database']) . "` CHARACTER SET=utf8 COLLATE=utf8_general_ci");
		$ins_stmt->execute();


		$mysql_access_host_array = array_map('trim', explode(',', $this->validatedData['mysql_access_host']));

		if (in_array('127.0.0.1', $mysql_access_host_array) && !in_array('localhost', $mysql_access_host_array)) {
			$mysql_access_host_array[] = 'localhost';
		}
		if (!in_array('127.0.0.1', $mysql_access_host_array) && in_array('localhost', $mysql_access_host_array)) {
			$mysql_access_host_array[] = '127.0.0.1';
		}
		if (!empty($this->validatedData['serveripv4']) && !in_array($this->validatedData['serveripv4'], $mysql_access_host_array)) {
			$mysql_access_host_array[] = $this->validatedData['serveripv4'];
		}
		if (!empty($this->validatedData['serveripv6']) && !in_array($this->validatedData['serveripv6'], $mysql_access_host_array)) {
			$mysql_access_host_array[] = $this->validatedData['serveripv6'];
		}
		$mysql_access_host_array = array_unique($mysql_access_host_array);

		foreach ($mysql_access_host_array as $mysql_access_host) {
			$this->grantDbPrivilegesTo($db_root, $this->validatedData['mysql_database'], $this->validatedData['mysql_unprivileged_user'], $this->validatedData['mysql_unprivileged_pass'], $mysql_access_host);
		}

		$db_root->query("FLUSH PRIVILEGES;");
		$this->validatedData['mysql_access_host'] = implode(',', $mysql_access_host_array);
	}

	/**
	 * Grant privileges to given user.
	 *
	 * @param $db_root
	 * @param $database
	 * @param $username
	 * @param $password
	 * @param $access_host
	 * @return void
	 * @throws Exception
	 */
	private function grantDbPrivilegesTo(&$db_root, $database, $username, $password, $access_host)
	{
		if ($this->validatedData['mysql_force_create']) {
			try {
				// try to drop the user, but ignore exceptions as the mysql-access-hosts might
				// have changed and we would try to drop a non-existing user
				$drop_stmt = $db_root->prepare("DROP USER :username@:host");
				$drop_stmt->execute([
					"username" => $username,
					"host" => $access_host
				]);
			} catch (PDOException $e) {
				/* continue */
			}
		}
		if (version_compare($db_root->getAttribute(PDO::ATTR_SERVER_VERSION), '8.0.11', '>=')) {
			// mariadb & mysql8
			// create user
			$stmt = $db_root->prepare("CREATE USER '" . $username . "'@'" . $access_host . "' IDENTIFIED BY :password");
			$stmt->execute([
				"password" => $password
			]);
			// grant privileges
			$stmt = $db_root->prepare("GRANT ALL ON `" . $database . "`.* TO :username@:host");
			$stmt->execute([
				"username" => $username,
				"host" => $access_host
			]);
		} else {
			// grant privileges
			$stmt = $db_root->prepare("GRANT ALL PRIVILEGES ON `" . $database . "`.* TO :username@:host IDENTIFIED BY :password");
			$stmt->execute([
				"username" => $username,
				"host" => $access_host,
				"password" => $password
			]);
		}
	}

	/**
	 * Import froxlor.sql into database
	 *
	 * @return void
	 * @throws Exception
	 */
	private function importDatabaseData()
	{
		try {
			$pdo = $this->getUnprivilegedPdo();
		} catch (PDOException $e) {
			throw new Exception(lng('install.errors.unprivileged_sql_connection_failed'));
		}

		// actually import data
		try {
			$froxlorSQL = include dirname(__FILE__, 5) . '/install/froxlor.sql.php';

			$pdo->query($froxlorSQL);
		} catch (PDOException $e) {
			throw new Exception(lng('install.errors.sql_import_failed', [$e->getMessage()]), 0, $e);
		}
	}

	/**
	 * change settings according to users input
	 *
	 * @param object $db_user
	 * @return void
	 * @throws Exception
	 */
	private function doSettings(object &$db_user)
	{
		$upd_stmt = $db_user->prepare("
			UPDATE `" . TABLE_PANEL_SETTINGS . "` SET `value` = :value
			WHERE `settinggroup` = :group AND `varname` = :varname
		");

		$mainip = !empty($this->validatedData['serveripv6']) ? $this->validatedData['serveripv6'] : $this->validatedData['serveripv4'];

		if ($this->validatedData['use_admin_email_as_sender'] == '1') {
			$adminmail_value = $this->validatedData['admin_email'];
		} elseif ($this->validatedData['use_admin_email_as_sender'] == '0' && !empty($this->validatedData['sender_email'])) {
			$adminmail_value = $this->validatedData['sender_email'];
		} else {
			$adminmail_value = 'admin@' . $this->validatedData['servername'];
		}
		$this->updateSetting($upd_stmt, $adminmail_value, 'panel', 'adminmail');
		$this->updateSetting($upd_stmt, $mainip, 'system', 'ipaddress');
		if ($this->validatedData['use_ssl']) {
			$this->updateSetting($upd_stmt, 1, 'system', 'use_ssl');
			$this->updateSetting($upd_stmt, 1, 'system', 'leenabled');
			$this->updateSetting($upd_stmt, 1, 'system', 'le_froxlor_enabled');
		}
		$this->updateSetting($upd_stmt, strtolower($this->validatedData['servername']), 'system', 'hostname');
		$this->updateSetting($upd_stmt, 'en', 'panel', 'standardlanguage'); // TODO: set language
		$this->updateSetting($upd_stmt, $this->validatedData['mysql_access_host'], 'system', 'mysql_access_host');
		$this->updateSetting($upd_stmt, $this->validatedData['webserver'], 'system', 'webserver');
		$this->updateSetting($upd_stmt, $this->validatedData['httpuser'], 'system', 'httpuser');
		$this->updateSetting($upd_stmt, $this->validatedData['httpgroup'], 'system', 'httpgroup');
		$this->updateSetting($upd_stmt, $this->validatedData['distribution'], 'system', 'distribution');

		// necessary changes for webservers != apache2
		if ($this->validatedData['webserver'] == "apache24") {
			$this->updateSetting($upd_stmt, 'apache2', 'system', 'webserver');
			$this->updateSetting($upd_stmt, '1', 'system', 'apache24');
		} elseif ($this->validatedData['webserver'] == "nginx") {
			$this->updateSetting($upd_stmt, '/var/run/', 'phpfpm', 'fastcgi_ipcdir');
			$this->updateSetting($upd_stmt, 'error', 'system', 'errorlog_level');
		}

		$distros = glob(FileDir::makeCorrectDir(Froxlor::getInstallDir() . '/lib/configfiles/') . '*.xml');
		foreach ($distros as $_distribution) {
			if ($this->validatedData['distribution'] == str_replace(".xml", "", strtolower(basename($_distribution)))) {
				$dist = new ConfigParser($_distribution);
				$defaults = $dist->getDefaults();
				if (!empty($defaults)) {
					foreach ($defaults as $property) {
						if (!isset($property->attributes()->for) || (isset($property->attributes()->for) && $property->attributes()->for == $this->validatedData['webserver'])) {
							$this->updateSetting($upd_stmt, $property->attributes()->value, $property->attributes()->settinggroup, $property->attributes()->varname);
						}
					}
				}
			}
		}

		$this->updateSetting($upd_stmt, $this->validatedData['activate_newsfeed'], 'admin', 'show_news_feed');
		$this->updateSetting($upd_stmt, dirname(__FILE__, 5), 'system', 'letsencryptchallengepath');
		$this->updateSetting($upd_stmt, dirname(__FILE__, 5) . '/templates/misc/deactivated/', 'system', 'deactivateddocroot');

		// insert the lastcronrun to be the installation date
		$this->updateSetting($upd_stmt, time(), 'system', 'lastcronrun');

		// set settings according to selected php-backend
		if ($this->validatedData['webserver_backend'] == 'php-fpm') {
			$this->updateSetting($upd_stmt, '1', 'phpfpm', 'enabled');
			$this->updateSetting($upd_stmt, '1', 'phpfpm', 'enabled_ownvhost');
		} elseif ($this->validatedData['webserver_backend'] == 'fcgid') {
			$this->updateSetting($upd_stmt, '1', 'system', 'mod_fcgid');
			$this->updateSetting($upd_stmt, '1', 'system', 'mod_fcgid_ownvhost');
		}

		// check currently used php version and set values of fpm/fcgid accordingly
		if (defined('PHP_MAJOR_VERSION') && defined('PHP_MINOR_VERSION')) {
			// php-fpm
			$reload = "service php" . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION . "-fpm restart";
			$config_dir = "/etc/php/" . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION . "/fpm/pool.d/";
			// fcgid
			if ($this->validatedData['distribution'] == 'bookworm' || $this->validatedData['distribution'] == 'trixie') {
				$binary = "/usr/bin/php-cgi" . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;
			} else {
				$binary = "/usr/bin/php" . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION . "-cgi";
			}
			$db_user->query("UPDATE `" . TABLE_PANEL_FPMDAEMONS . "` SET `reload_cmd` = '" . $reload . "', `config_dir` = '" . $config_dir . "' WHERE `id` ='1';");
			$db_user->query("UPDATE `" . TABLE_PANEL_PHPCONFIGS . "` SET `binary` = '" . $binary . "';");
		}

		if ($this->validatedData['use_ssl']) {
			// enable let's encrypt cron
			$db_user->query("UPDATE `" . TABLE_PANEL_CRONRUNS . "` SET `isactive` = '1' WHERE `module` = 'froxlor/letsencrypt';");
		}

		// set specific times for some crons (traffic only at night, etc.)
		$timestamp = mktime(0, 0, 0, date('m', time()), date('d', time()), date('Y', time()));
		$db_user->query("UPDATE `" . TABLE_PANEL_CRONRUNS . "` SET `lastrun` = '" . $timestamp . "' WHERE `cronfile` ='cron_traffic';");

		// insert task 99 to generate a correct cron.d-file automatically
		$db_user->query("INSERT INTO `" . TABLE_PANEL_TASKS . "` SET `type` = '99';");
	}

	/**
	 * execute prepared statement to update settings
	 *
	 * @param PDOStatement|null $stmt
	 * @param string|null $group
	 * @param string|null $varname
	 * @param string|null $value
	 */
	private function updateSetting(?PDOStatement &$stmt = null, ?string $value = null, ?string $group = null, ?string $varname = null)
	{
		$stmt->execute([
			'group' => $group,
			'varname' => $varname,
			'value' => $value
		]);
	}

	/**
	 * create corresponding entries in froxlor database
	 *
	 * @param $db_user
	 * @return void
	 */
	private function doDataEntries(&$db_user)
	{
		// lets insert the default ip and port
		$stmt = $db_user->prepare("
			INSERT INTO `" . TABLE_PANEL_IPSANDPORTS . "` SET
			`ip`= :serverip,
			`port` = :serverport,
			`namevirtualhost_statement` = :nvh,
			`vhostcontainer` = '1',
			`vhostcontainer_servername_statement` = '1',
			`ssl` = :ssl
		");
		$nvh = $this->validatedData['webserver'] == 'apache2' ? '1' : '0';
		$defaultip = false;
		if (!empty($this->validatedData['serveripv6'])) {
			$stmt->execute([
				'nvh' => $nvh,
				'serverip' => $this->validatedData['serveripv6'],
				'serverport' => 80,
				'ssl' => 0
			]);
			$defaultip = $db_user->lastInsertId();
		}
		if (!empty($this->validatedData['serveripv4'])) {
			$stmt->execute([
				'nvh' => $nvh,
				'serverip' => $this->validatedData['serveripv4'],
				'serverport' => 80,
				'ssl' => 0
			]);
			$lastinsert = $db_user->lastInsertId();
			$defaultip = $defaultip != false ? $defaultip . ',' . $lastinsert : $lastinsert;
		}

		$defaultsslip = false;
		if ($this->validatedData['use_ssl']) {
			if (!empty($this->validatedData['serveripv6'])) {
				$stmt->execute([
					'nvh' => $this->validatedData['webserver'] == 'apache2' ? '1' : '0',
					'serverip' => $this->validatedData['serveripv6'],
					'serverport' => 443,
					'ssl' => 1
				]);
				$defaultsslip = $db_user->lastInsertId();
			}
			if (!empty($this->validatedData['serveripv4'])) {
				$stmt->execute([
					'nvh' => $this->validatedData['webserver'] == 'apache2' ? '1' : '0',
					'serverip' => $this->validatedData['serveripv4'],
					'serverport' => 443,
					'ssl' => 1
				]);
				$lastinsert = $db_user->lastInsertId();
				$defaultsslip = $defaultsslip != false ? $defaultsslip . ',' . $lastinsert : $lastinsert;
			}
		}

		// insert the defaultip
		$upd_stmt = $db_user->prepare("
			UPDATE `" . TABLE_PANEL_SETTINGS . "` SET
			`value` = :defaultip
			WHERE `settinggroup` = 'system' AND `varname` = :defipfld
		");
		$upd_stmt->execute([
			'defaultip' => $defaultip,
			'defipfld' => 'defaultip'
		]);

		if ($defaultsslip) {
			$upd_stmt->execute([
				'defaultip' => $defaultsslip,
				'defipfld' => 'defaultsslip'
			]);
		}

		// last but not least create the main admin
		$ins_data = [
			'loginname' => $this->validatedData['admin_user'],
			'password' => password_hash($this->validatedData['admin_pass'], PASSWORD_DEFAULT),
			'adminname' => $this->validatedData['admin_name'],
			'email' => $this->validatedData['admin_email'],
			'deflang' => 'en' // TODO: set language
		];
		$ins_stmt = $db_user->prepare("
			INSERT INTO `" . TABLE_PANEL_ADMINS . "` SET
			`loginname` = :loginname,
			`password` = :password,
			`name` = :adminname,
			`email` = :email,
			`def_language` = :deflang,
			`api_allowed` = 1,
			`customers` = -1,
			`customers_see_all` = 1,
			`caneditphpsettings` = 1,
			`domains` = -1,
			`change_serversettings` = 1,
			`diskspace` = -1024,
			`mysqls` = -1,
			`emails` = -1,
			`email_accounts` = -1,
			`email_forwarders` = -1,
			`email_quota` = -1,
			`ftps` = -1,
			`subdomains` = -1,
			`traffic` = -1048576
		");

		$ins_stmt->execute($ins_data);
	}

	/**
	 * Create userdata.inc.php file
	 *
	 * @return void
	 * @throws Exception
	 */
	public function createUserdataConf()
	{
		$userdata = [
			'sql' => [
				'debug' => false,
				'host' => $this->validatedData['mysql_host'],
				'user' => $this->validatedData['mysql_unprivileged_user'],
				'password' => $this->validatedData['mysql_unprivileged_pass'],
				'db' => $this->validatedData['mysql_database'],
			],
			'sql_root' => [
				'0' => [
					'caption' => 'Default',
					'host' => $this->validatedData['mysql_host'],
					'user' => $this->validatedData['mysql_root_user'],
					'password' => $this->validatedData['mysql_root_pass'],
				]
			]
		];

		// enable sql ssl in userdata for unprivileged and root db user
		if (!empty($this->validatedData['mysql_ssl_ca_file']) && isset($this->validatedData['mysql_ssl_verify_server_certificate'])) {
			$userdata['sql']['ssl'] = [
				'caFile' => $this->validatedData['mysql_ssl_ca_file'],
				'verifyServerCertificate' => (bool)$this->validatedData['mysql_ssl_verify_server_certificate'],
			];
			$userdata['sql_root']['0']['ssl'] = [
				'caFile' => $this->validatedData['mysql_ssl_ca_file'],
				'verifyServerCertificate' => (bool)$this->validatedData['mysql_ssl_verify_server_certificate'],
			];
		}

		// test if we can store the userdata.inc.php in ../lib
		$umask = @umask(077);
		$userdata = PhpHelper::parseArrayToPhpFile($userdata);
		$userdata_file = dirname(__FILE__, 5) . '/lib/userdata.inc.php';
		if (@touch($userdata_file) && @is_writable($userdata_file)) {
			$fp = @fopen($userdata_file, 'w');
			@fputs($fp, $userdata, strlen($userdata));
			@fclose($fp);
		} else {
			@unlink($userdata_file);
			// try creating it in a temporary file
			$temp_file = @tempnam(sys_get_temp_dir(), 'fx');
			if ($temp_file) {
				$fp = @fopen($temp_file, 'w');
				@fputs($fp, $userdata, strlen($userdata));
				@fclose($fp);
			} else {
				throw new Exception(lng('install.errors.creating_configfile_failed'));
			}
		}
		@umask($umask);
	}

	private function createJsonArray(&$db_user)
	{
		// use traffic analyzer and ftpserver from settings as we could define defaults in the lib/configfiles/*.xml templates
		// which can be useful for third-party package-maintainer (e.g. other distros) to have more control
		// over the installation defaults (less hardcoded values)
		$custom_dependency = $db_user->query("
			SELECT `varname`, `value` FROM `" . TABLE_PANEL_SETTINGS . "`
			WHERE `settinggroup` = 'system' AND (`varname` = 'traffictool' OR `varname` = 'ftpserver')
		");
		$cd_result = $custom_dependency->fetchAll(\PDO::FETCH_KEY_PAIR);
		$system_params = ["cron", "libnssextrausers", "logrotate"];
		if (isset($cd_result['traffictool'])) {
			$system_params[] = $cd_result['traffictool'];
		}
		if ($this->validatedData['webserver_backend'] == 'php-fpm') {
			$system_params[] = 'php-fpm';
		} elseif ($this->validatedData['webserver_backend'] == 'fcgid') {
			$system_params[] = 'fcgid';
		}
		$json_params = [
			'distro' => $this->validatedData['distribution'],
			'dns' => 'x',
			'http' => $this->validatedData['webserver'],
			'smtp' => 'postfix_dovecot',
			'mail' => 'dovecot_postfix2',
			'antispam' => 'rspamd',
			'ftp' => $cd_result['ftpserver'] ?? 'x',
			'system' => $system_params
		];
		$_SESSION['installation']['json_params'] = json_encode($json_params);
	}

	private function createUserdataParamStr()
	{
		$req_fields = [
			'mysql_host',
			'mysql_unprivileged_user',
			'mysql_unprivileged_pass',
			'mysql_database',
			'mysql_root_user',
			'mysql_root_pass',
			'mysql_ssl_ca_file',
			'mysql_ssl_verify_server_certificate'
		];
		$json_params = [];
		foreach ($req_fields as $field) {
			$json_params[$field] = $this->validatedData[$field] ?? "";
		}
		$_SESSION['installation']['ud_str'] = base64_encode(json_encode($json_params));
	}
}
