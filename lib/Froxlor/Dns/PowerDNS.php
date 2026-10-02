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

namespace Froxlor\Dns;

use Froxlor\FileDir;
use Froxlor\Settings;
use PDO;
use PDOException;

class PowerDNS
{
	private static $pdns_db = null;

	/**
	 * remove all records and entries of a given domain
	 *
	 * @param string|null $domain
	 */
	public static function cleanDomainZone(?string $domain = null)
	{
		if (!empty($domain)) {
			$pdns_domains_stmt = self::getDB()->prepare("SELECT `id`, `name` FROM `domains` WHERE `name` = :domain");
			$del_rec_stmt = self::getDB()->prepare("DELETE FROM `records` WHERE `domain_id` = :did");
			$del_meta_stmt = self::getDB()->prepare("DELETE FROM `domainmetadata` WHERE `domain_id` = :did");
			$del_dom_stmt = self::getDB()->prepare("DELETE FROM `domains` WHERE `id` = :did");

			$pdns_domains_stmt->execute([
				'domain' => $domain
			]);
			$pdns_domain = $pdns_domains_stmt->fetch(PDO::FETCH_ASSOC);

			$del_rec_stmt->execute([
				'did' => $pdns_domain['id']
			]);
			$del_meta_stmt->execute([
				'did' => $pdns_domain['id']
			]);
			$del_dom_stmt->execute([
				'did' => $pdns_domain['id']
			]);
		}
	}

	/**
	 * get pdo database connection to powerdns database
	 *
	 * @return \PDO
	 */
	public static function getDB(): \PDO
	{
		if (!isset(self::$pdns_db) || !(self::$pdns_db instanceof PDO)) {
			self::connectToPdnsDb();
		}
		return self::$pdns_db;
	}

	/**
	 * @return void
	 */
	private static function connectToPdnsDb()
	{
		// get froxlor pdns config
		$cf = Settings::Get('system.bindconf_directory') . '/froxlor/pdns_froxlor.conf';
		$config = FileDir::makeCorrectFile($cf);

		if (!file_exists($config)) {
			die('PowerDNS configuration file (' . $config . ') not found. Did you go through the configuration templates?' . PHP_EOL);
		}
		$lines = file($config);
		$mysql_data = [];
		foreach ($lines as $line) {
			$line = trim($line);
			if (strtolower(substr($line, 0, 6)) == 'gmysql') {
				$namevalue = explode("=", $line);
				$mysql_data[$namevalue[0]] = $namevalue[1];
			}
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
		$dbconf = [];

		$dbconf["dsn"] = [
			'dbname' => $mysql_data["gmysql-dbname"],
			'charset' => 'utf8'
		];

		if (isset($mysql_data['gmysql-socket']) && !empty($mysql_data['gmysql-socket'])) {
			$dbconf["dsn"]['unix_socket'] = FileDir::makeCorrectFile($mysql_data['gmysql-socket']);
		} else {
			$dbconf["dsn"]['host'] = $mysql_data['gmysql-host'];
			$dbconf["dsn"]['port'] = $mysql_data['gmysql-port'];

			if (!empty($mysql_data['gmysql-ssl-ca-file'])) {
				$options[PDO::MYSQL_ATTR_SSL_CA] = $mysql_data['gmysql-ssl-ca-file'];
				$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)$mysql_data['gmysql-ssl-verify-server-certificate'];
			}
		}

		// add options to dsn-string
		foreach ($dbconf["dsn"] as $k => $v) {
			$dsn .= $k . "=" . $v . ";";
		}

		// clean up
		unset($dbconf);

		// try to connect
		try {
			self::$pdns_db = new PDO($dsn, $mysql_data['gmysql-user'], $mysql_data['gmysql-password'], $options);
		} catch (PDOException $e) {
			die($e->getMessage());
		}

		// set attributes
		foreach ($attributes as $k => $v) {
			self::$pdns_db->setAttribute(constant("PDO::" . $k), constant("PDO::" . $v));
		}

		$version_server = self::$pdns_db->getAttribute(PDO::ATTR_SERVER_VERSION);
		$sql_mode = 'NO_ENGINE_SUBSTITUTION';
		if (version_compare($version_server, '8.0.11', '<')) {
			$sql_mode .= ',NO_AUTO_CREATE_USER';
		}
		self::$pdns_db->exec('SET sql_mode = "' . $sql_mode . '"');
	}
}
