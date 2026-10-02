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

namespace Froxlor\Database;

use Exception;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\Panel\UI;
use PDO;
use PDOException;
use PDOStatement;

/**
 * Class Database
 *
 * Wrapper-class for PHP-PDO
 *
 * @method static PDOStatement prepare($statement, array $driver_options = null) Prepares a statement for execution
 *         and returns a statement object
 * @method static PDOStatement query ($statement) Executes an SQL statement, returning a result set as a PDOStatement
 *         object
 * @method static string lastInsertId ($name = null) Returns the ID of the last inserted row or sequence value
 * @method static string quote ($string, $parameter_type = null) Quotes a string for use in a query.
 * @method static mixed getAttribute(int $attribute) Retrieve a database connection attribute
 */
class Database
{

	/**
	 * current database link
	 *
	 * @var object
	 */
	private static $link = null;

	/**
	 * indicator whether to use root-connection or not
	 */
	private static bool $needroot = false;

	/**
	 * indicator which database-server we're on (not really used)
	 */
	private static int $dbserver = 0;

	/**
	 * used database-name
	 */
	private static ?string $dbname = null;

	/**
	 * sql-access data
	 */
	private static bool $needsqldata = false;

	private static $sqldata = null;

	private static bool $need_dbname = true;

	/**
	 * Wrapper for PDOStatement::execute, so we can catch the PDOException
	 * and display the error nicely on the panel - also fetches the
	 * result from the statement and returns the resulting array
	 *
	 * @param PDOStatement $stmt
	 * @param array|null $params
	 *            (optional)
	 * @param bool $showerror
	 *            suppress error display (default true)
	 * @param bool $json_response
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public static function pexecute_first(PDOStatement &$stmt, $params = null, bool $showerror = true, bool $json_response = false)
	{
		self::pexecute($stmt, $params, $showerror, $json_response);
		return $stmt->fetch(PDO::FETCH_ASSOC);
	}

	/**
	 * Wrapper for PDOStatement::execute so we can catch the PDOException
	 * and display the error nicely on the panel
	 *
	 * @param PDOStatement $stmt
	 * @param array|null $params
	 *            (optional)
	 * @param bool $showerror
	 *            suppress error display (default true)
	 * @param bool $json_response
	 *
	 * @throws Exception
	 */
	public static function pexecute(PDOStatement &$stmt, $params = null, bool $showerror = true, bool $json_response = false)
	{
		try {
			$stmt->execute($params);
		} catch (PDOException $e) {
			self::showerror($e, $showerror, $json_response, $stmt);
		}
	}

	/**
	 * display a nice error if it occurs and log everything
	 *
	 * @param PDOException $error
	 * @param bool $showerror
	 *            if set to false, the error will be logged, but we go on
	 * @throws Exception
	 */
	private static function showerror(Exception $error, bool $showerror = true, bool $json_response = false, ?PDOStatement $stmt = null)
	{
		global $userinfo, $theme, $linker;

		$sql = [];
		$sql_root = [];

		// include userdata.inc.php
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		// le format
		if (isset($sql['root_user']) && isset($sql['root_password']) && empty($sql_root)) {
			$sql_root = [
				0 => [
					'caption' => 'Default',
					'host' => $sql['host'],
					'socket' => ($sql['socket'] ?? null),
					'user' => $sql['root_user'],
					'password' => $sql['root_password']
				]
			];
			unset($sql['root_user']);
			unset($sql['root_password']);
			// write new layout so this won't happen again
			self::generateNewUserData($sql, $sql_root);
			// re-read file
			require Froxlor::getInstallDir() . "/lib/userdata.inc.php";
		}

		$substitutions = [
			$sql['password'] => 'DB_UNPRIV_PWD',
		];
		foreach ($sql_root as $sql_root_data) {
			$substitutions[$sql_root_data['password']] = 'DB_ROOT_PWD';
		}

		// hide username/password in messages
		$error_message = $error->getMessage();
		$error_trace = $error->getTraceAsString();
		// error-message
		$error_message = self::substitute($error_message, $substitutions);
		// error-trace
		$error_trace = self::substitute($error_trace, $substitutions);

		if ($error->getCode() == 2003) {
			$error_message = "Unable to connect to database. Either the mysql-server is not running or your user/password is wrong.";
			$error_trace = "";
		}

		/**
		 * log to a file, so we can actually ask people for the error
		 * (no one seems to find the stuff in the syslog)
		 */
		$sl_dir = FileDir::makeCorrectDir(Froxlor::getInstallDir() . "/logs/");
		if (!file_exists($sl_dir)) {
			@mkdir($sl_dir, 0755);
		}
		if (!defined('TRAVIS_CI') || TRAVIS_CI == 0) {
			openlog("froxlor", LOG_PID | LOG_PERROR, LOG_LOCAL0);
			syslog(LOG_WARNING, str_replace("\n", " ", $error_message));
			syslog(LOG_WARNING, str_replace("\n", " ", "--- DEBUG: " . $error_trace));
			closelog();
		}

		/**
		 * log error for reporting
		 */
		$errid = self::genUniqueToken();
		$err_file = FileDir::makeCorrectFile($sl_dir . "/" . $errid . "_sql-error.log");
		$errlog = @fopen($err_file, 'w');
		@fwrite($errlog, "|CODE " . $error->getCode() . "\n");
		@fwrite($errlog, "|MSG " . $error_message . "\n");
		@fwrite($errlog, "|FILE " . $error->getFile() . "\n");
		@fwrite($errlog, "|LINE " . $error->getLine() . "\n");
		@fwrite($errlog, "|TRACE\n" . $error_trace . "\n");
		@fclose($errlog);

		if (empty($sql['debug'])) {
			$error_trace = '';
		} elseif (!is_null($stmt)) {
			$error_trace .= "\n\n" . $stmt->queryString;
		}

		if ($showerror && $json_response) {
			$exception_message = $error_message;
			if (isset($sql['debug']) && $sql['debug'] == true) {
				$exception_message .= "\n\n" . $error_trace;
			}
			throw new Exception($exception_message, 500);
		}

		if ($showerror) {
			// clean up sensitive data
			unset($sql);
			unset($sql_root);

			if ((isset($theme) && $theme != '') && !isset($_SERVER['SHELL']) || (isset($_SERVER['SHELL']) && $_SERVER['SHELL'] == '')) {
				// if we're not on the shell, output a nice error
				$err_report_link = '';
				if (is_array($userinfo) && (($userinfo['adminsession'] == '1' && Settings::Get('system.allow_error_report_admin') == '1') || ($userinfo['adminsession'] == '0' && Settings::Get('system.allow_error_report_customer') == '1'))) {
					$err_report_link = $linker->getLink([
						'section' => 'index',
						'page' => 'send_error_report',
						'errorid' => $errid
					]);
				}
				// show
				UI::initTwig(true);
				UI::twig()->addGlobal('install_mode', '1');
				UI::view('misc/dberrornice.html.twig', [
					'page_title' => 'Database error',
					'message' => $error_message,
					'debug' => $error_trace,
					'report' => $err_report_link
				]);
				die();
			}
			die("We are sorry, but a MySQL - error occurred. The administrator may find more information in the syslog");
		}
	}

	/**
	 * Substitutes patterns in content.
	 *
	 * @param string $content
	 * @param array $substitutions
	 * @param int $minLength
	 * @return string
	 */
	private static function substitute(string $content, array $substitutions, int $minLength = 6): string
	{
		$replacements = [];

		foreach ($substitutions as $search => $replace) {
			$replacements += self::createShiftedSubstitutions($search, $replace, $minLength);
		}

		return str_replace(array_keys($replacements), array_values($replacements), $content);
	}

	/**
	 * Creates substitutions, shifted by length, e.g.
	 *
	 * _createShiftedSubstitutions('abcdefgh', 'value', 4):
	 * array(
	 * 'abcdefgh' => 'value',
	 * 'abcdefg' => 'value',
	 * 'abcdef' => 'value',
	 * 'abcde' => 'value',
	 * 'abcd' => 'value',
	 * )
	 *
	 * @param string $search
	 * @param string $replace
	 * @param int $minLength
	 * @return array
	 */
	private static function createShiftedSubstitutions(string $search, string $replace, int $minLength): array
	{
		$substitutions = [];
		$length = strlen($search);

		if ($length > $minLength) {
			for ($shiftedLength = $length; $shiftedLength >= $minLength; $shiftedLength--) {
				$substitutions[substr($search, 0, $shiftedLength)] = $replace;
			}
		}

		return $substitutions;
	}

	/**
	 * generate safe unique token
	 *
	 * @param int $length
	 * @return string
	 * @throws Exception
	 */
	private static function genUniqueToken(int $length = 16): string
	{
		if (intval($length) <= 8) {
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
		return substr(md5(uniqid(microtime(), 1)), 0, $length);
	}

	/**
	 * returns the number of found rows of the last select query
	 *
	 * @return int
	 */
	public static function num_rows(): int
	{
		return Database::query("SELECT FOUND_ROWS()")->fetchColumn();
	}

	/**
	 * returns the database-name which is used
	 *
	 * @return string
	 */
	public static function getDbName(): ?string
	{
		return self::$dbname;
	}

	/**
	 * enabled the usage of a root-connection to the database
	 * Note: must be called *before* any prepare/query/etc.
	 * and should be called again with 'false'-parameter to resume
	 * the 'normal' database-connection
	 *
	 * @param bool $needroot
	 * @param int $dbserver optional
	 * @param bool $need_db
	 */
	public static function needRoot(bool $needroot = false, int $dbserver = 0, bool $need_db = true)
	{
		// force re-connecting to the db with corresponding user
		// and set the $dbserver (mostly to 0 = default)
		self::setServer($dbserver);
		self::$needroot = $needroot;
		self::$need_dbname = $need_db;
	}

	/**
	 * set the database-server (relevant for root-connection)
	 *
	 * @param int $dbserver
	 */
	private static function setServer(int $dbserver = 0)
	{
		self::$dbserver = $dbserver;
		self::$link = null;
	}

	/**
	 * get the currently used database-server (relevant for root-connection)
	 */
	public static function getServer()
	{
		return self::$dbserver;
	}

	/**
	 * enable the temporary access to sql-access data
	 * note: if you want root-sqldata you need to
	 * call needRoot(true) first.
	 * Also, this will
	 * only give you the data ONCE as it disable itself
	 * after the first access to the data
	 */
	public static function needSqlData()
	{
		self::$needsqldata = true;
		self::$sqldata = [];
		self::$link = null;
		// we need a connection here because
		// if getSqlData() is called RIGHT after
		// this function and no "real" PDO
		// function was called, getDB() wasn't
		// involved and no data collected
		self::getDB();
	}

	/**
	 * function that will be called on every static call
	 * which connects to the database if necessary
	 *
	 * @return object
	 * @throws Exception
	 */
	private static function getDB()
	{
		if (!extension_loaded('pdo') || !in_array("mysql", PDO::getAvailableDrivers())) {
			self::showerror(new Exception("The php PDO extension or PDO-MySQL driver is not available"));
		}

		// do we have a connection already?
		if (self::$link) {
			// return it
			return self::$link;
		}

		// include userdata.inc.php
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		// le format
		if (isset($sql['root_user']) && isset($sql['root_password']) && (!isset($sql_root) || !is_array($sql_root))) {
			$sql_root = [
				0 => [
					'caption' => 'Default',
					'host' => $sql['host'],
					'socket' => ($sql['socket'] ?? null),
					'user' => $sql['root_user'],
					'password' => $sql['root_password']
				]
			];
			unset($sql['root_user']);
			unset($sql['root_password']);
			// write new layout so this won't happen again
			self::generateNewUserData($sql, $sql_root);
			// re-read file
			require Froxlor::getInstallDir() . "/lib/userdata.inc.php";
		}

		// either root or unprivileged user
		if (self::$needroot) {
			$caption = $sql_root[self::$dbserver]['caption'];
			$user = $sql_root[self::$dbserver]['user'];
			$password = $sql_root[self::$dbserver]['password'];
			$host = $sql_root[self::$dbserver]['host'];
			$socket = $sql_root[self::$dbserver]['socket'] ?? null;
			$port = $sql_root[self::$dbserver]['port'] ?? '3306';
			$sslCAFile = $sql_root[self::$dbserver]['ssl']['caFile'] ?? "";
			$sslVerifyServerCertificate = $sql_root[self::$dbserver]['ssl']['verifyServerCertificate'] ?? false;
		} else {
			$caption = 'localhost';
			$user = $sql["user"];
			$password = $sql["password"];
			$host = $sql["host"];
			$socket = $sql['socket'] ?? null;
			$port = $sql['port'] ?? '3306';
			$sslCAFile = $sql['ssl']['caFile'] ?? "";
			$sslVerifyServerCertificate = $sql['ssl']['verifyServerCertificate'] ?? false;
		}

		// save sql-access-data if needed
		if (self::$needsqldata) {
			self::$sqldata = [
				'user' => $user,
				'passwd' => $password,
				'host' => $host,
				'port' => $port,
				'socket' => $socket,
				'db' => $sql["db"],
				'caption' => $caption,
				'ssl_ca_file' => $sslCAFile,
				'ssl_verify_server_certificate' => $sslVerifyServerCertificate
			];
		}

		// build up connection string
		$driver = 'mysql';
		$dsn = $driver . ":";
		$options = [
			'PDO::MYSQL_ATTR_INIT_COMMAND' => 'SET names utf8'
		];
		$attributes = [
			'ATTR_ERRMODE' => 'ERRMODE_EXCEPTION'
		];

		$dbconf["dsn"] = ['charset' => 'utf8'];

		if (self::$need_dbname) {
			$dbconf["dsn"]['dbname'] = $sql["db"];
		}

		if ($socket != null) {
			$dbconf["dsn"]['unix_socket'] = FileDir::makeCorrectFile($socket);
		} else {
			$dbconf["dsn"]['host'] = $host;
			$dbconf["dsn"]['port'] = $port;

			if (!empty(self::$sqldata['ssl_ca_file'])) {
				$options[PDO::MYSQL_ATTR_SSL_CA] = self::$sqldata['ssl_ca_file'];
				$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)self::$sqldata['ssl_verify_server_certificate'];
			}
		}

		self::$dbname = $sql["db"];

		// add options to dsn-string
		foreach ($dbconf["dsn"] as $k => $v) {
			$dsn .= $k . "=" . $v . ";";
		}

		// clean up
		unset($dbconf);

		// try to connect
		try {
			self::$link = new PDO($dsn, $user, $password, $options);
		} catch (PDOException $e) {
			self::showerror($e);
		}

		// set attributes
		foreach ($attributes as $k => $v) {
			self::$link->setAttribute(constant("PDO::" . $k), constant("PDO::" . $v));
		}

		$version_server = self::$link->getAttribute(PDO::ATTR_SERVER_VERSION);
		$sql_mode = 'NO_ENGINE_SUBSTITUTION';
		if (version_compare($version_server, '8.0.11', '<')) {
			$sql_mode .= ',NO_AUTO_CREATE_USER';
		}
		self::$link->exec('SET sql_mode = "' . $sql_mode . '"');

		// return PDO instance
		return self::$link;
	}

	/**
	 * returns the sql-access data as array using indices
	 * 'user', 'passwd' and 'host'.
	 * Returns false if not enabled
	 *
	 * @return array|bool
	 */
	public static function getSqlData()
	{
		$return = false;
		if (self::$sqldata !== null && is_array(self::$sqldata) && isset(self::$sqldata['user'])) {
			$return = self::$sqldata;
			// automatically disable sql-data
			self::$sqldata = null;
			self::$needsqldata = false;
		}
		return $return;
	}

	/**
	 * return number of characters that are allowed to use as username
	 *
	 * @return int
	 */
	public static function getSqlUsernameLength(): int
	{
		// MariaDB supports up to 80 characters but only 64 for databases and as we use the login-name also for
		// database names, we set the limit to 64 here
		if (strpos(strtolower(Database::getAttribute(\PDO::ATTR_SERVER_VERSION)), "mariadb") !== false) {
			$mysql_max = 64;
		} else {
			// MySQL user-names can be up to 32 characters long (16 characters before MySQL 5.7.8).
			$mysql_max = 32;
			if (version_compare(Database::getAttribute(\PDO::ATTR_SERVER_VERSION), '5.7.8', '<')) {
				$mysql_max = 16;
			}
		}
		return $mysql_max;
	}

	/**
	 * Lets us interact with the PDO-Object by using static
	 * call like "Database::function()"
	 *
	 * @param string $name
	 * @param mixed $args
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public static function __callStatic(string $name, $args)
	{
		$callback = [
			self::getDB(),
			$name
		];
		$result = null;
		try {
			$result = call_user_func_array($callback, $args);
		} catch (PDOException $e) {
			self::showerror($e);
		}
		return $result;
	}

	/**
	 * write new userdata.inc.php file
	 */
	private static function generateNewUserData(array $sql, array $sql_root)
	{
		$content = PhpHelper::parseArrayToPhpFile(
			['sql' => $sql, 'sql_root' => $sql_root],
			'automatically generated userdata.inc.php for froxlor'
		);
		chmod(Froxlor::getInstallDir() . "/lib/userdata.inc.php", 0700);
		file_put_contents(Froxlor::getInstallDir() . "/lib/userdata.inc.php", $content);
		chmod(Froxlor::getInstallDir() . "/lib/userdata.inc.php", 0400);
		clearstatcache();
		if (function_exists('opcache_invalidate')) {
			@opcache_invalidate(Froxlor::getInstallDir() . "/lib/userdata.inc.php", true);
		}
	}
}
