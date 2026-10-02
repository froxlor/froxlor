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

namespace Froxlor\Config;

use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\Panel\UI;

class ConfigDisplay
{
	/**
	 * @var array
	 */
	private static $replace_arr;

	/**
	 * @var string
	 */
	private static $editor;

	/**
	 * @var string
	 */
	private static $theme;

	/**
	 * @param array $confarr
	 * @param string $editor
	 * @param string $theme
	 */
	public static function fromConfigArr(array $confarr, string $editor, string $theme)
	{
		self::$editor = $editor;
		self::$theme = $theme;

		$customer_tmpdir = '/tmp/';
		if (Settings::Get('system.mod_fcgid') == '1' && Settings::Get('system.mod_fcgid_tmpdir') != '') {
			$customer_tmpdir = Settings::Get('system.mod_fcgid_tmpdir');
		} elseif (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.tmpdir') != '') {
			$customer_tmpdir = Settings::Get('phpfpm.tmpdir');
		}

		// try to convert namserver hosts to ip's
		$ns_ips = "";
		$known_ns_ips = [];
		if (Settings::Get('system.nameservers') != '') {
			$nameservers = explode(',', Settings::Get('system.nameservers'));
			foreach ($nameservers as $nameserver) {
				$nameserver = trim($nameserver);
				// DNS servers might be multi homed; allow transfer from all ip
				// addresses of the DNS server
				$nameserver_ips = PhpHelper::gethostbynamel6($nameserver);
				// append dot to hostname
				if (substr($nameserver, -1, 1) != '.') {
					$nameserver .= '.';
				}
				// ignore invalid responses
				if (!is_array($nameserver_ips)) {
					// act like \Froxlor\PhpHelper::gethostbynamel6() and return unmodified hostname on error
					$nameserver_ips = [
						$nameserver
					];
				} else {
					$known_ns_ips = array_merge($known_ns_ips, $nameserver_ips);
				}
				if (!empty($ns_ips)) {
					$ns_ips .= ',';
				}
				$ns_ips .= implode(",", $nameserver_ips);
			}
		}

		// AXFR server
		if (Settings::Get('system.axfrservers') != '') {
			$axfrservers = explode(',', Settings::Get('system.axfrservers'));
			foreach ($axfrservers as $axfrserver) {
				if (!in_array(trim($axfrserver), $known_ns_ips)) {
					if (!empty($ns_ips)) {
						$ns_ips .= ',';
					}
					$ns_ips .= trim($axfrserver);
				}
			}
		}

		Database::needSqlData();
		$sql = Database::getSqlData();

		self::$replace_arr = [
			'<SQL_UNPRIVILEGED_USER>' => $sql['user'],
			'<SQL_UNPRIVILEGED_PASSWORD>' => 'FROXLOR_MYSQL_PASSWORD',
			'<SQL_DB>' => $sql['db'],
			'<SQL_HOST>' => $sql['host'],
			'<SQL_SOCKET>' => $sql['socket'] ?? null,
			'<SERVERNAME>' => Settings::Get('system.hostname'),
			'<SERVERIP>' => Settings::Get('system.ipaddress'),
			'<NAMESERVERS>' => Settings::Get('system.nameservers'),
			'<NAMESERVERS_IP>' => $ns_ips,
			'<VIRTUAL_MAILBOX_BASE>' => Settings::Get('system.vmail_homedir'),
			'<VIRTUAL_UID_MAPS>' => Settings::Get('system.vmail_uid'),
			'<VIRTUAL_GID_MAPS>' => Settings::Get('system.vmail_gid'),
			'<SSLPROTOCOLS>' => (Settings::Get('system.use_ssl') == '1') ? 'imaps pop3s' : '',
			'<CUSTOMER_TMP>' => FileDir::makeCorrectDir($customer_tmpdir),
			'<BASE_PATH>' => Froxlor::getInstallDir(),
			'<BIND_CONFIG_PATH>' => FileDir::makeCorrectDir(Settings::Get('system.bindconf_directory')),
			'<WEBSERVER_RELOAD_CMD>' => Settings::Get('system.apachereload_command'),
			'<CUSTOMER_LOGS>' => FileDir::makeCorrectDir(Settings::Get('system.logfiles_directory')),
			'<FPM_IPCDIR>' => FileDir::makeCorrectDir(Settings::Get('phpfpm.fastcgi_ipcdir')),
			'<WEBSERVER_GROUP>' => Settings::Get('system.httpgroup'),
			'<SSL_CERT_FILE>' => Settings::Get('system.ssl_cert_file'),
			'<SSL_KEY_FILE>' => Settings::Get('system.ssl_key_file'),
			'<ADMIN_MAIL>' => Settings::Get('panel.adminmail'),
		];

		$commands_pre = "";
		$commands_file = "";
		$commands_post = "";

		$lasttype = '';
		$commands = '';

		$configpage = "";

		foreach ($confarr as $_action) {
			if ($lasttype != '' && $lasttype != $_action['type']) {
				$commands = trim($commands);
				$numbrows = count(explode("\n", $commands));
				$configpage .= UI::twig()->render(UI::validateThemeTemplate('/settings/conf/command.html.twig', self::$theme), [
					'commands' => $commands,
					'numbrows' => $numbrows
				]);
				$lasttype = '';
				$commands = '';
			}
			switch ($_action['type']) {
				case "install":
					$commands .= strtr($_action['content'], self::$replace_arr) . "\n";
					$lasttype = "install";
					break;
				case "command":
					$commands .= strtr($_action['content'], self::$replace_arr) . "\n";
					$lasttype = "command";
					break;
				case "file":
					if (array_key_exists('content', $_action)) {
						$commands_file = self::getFileContentContainer($_action['content'], $_action['name']);
					} elseif (array_key_exists('subcommands', $_action)) {
						foreach ($_action['subcommands'] as $fileaction) {
							if (array_key_exists('execute', $fileaction) && $fileaction['execute'] == "pre") {
								$commands_pre .= $fileaction['content'] . "\n";
							} elseif (array_key_exists('execute', $fileaction) && $fileaction['execute'] == "post") {
								$commands_post .= $fileaction['content'] . "\n";
							} elseif ($fileaction['type'] == 'file') {
								$commands_file = self::getFileContentContainer($fileaction['content'], $_action['name']);
							}
						}
					}
					$realname = $_action['name'];
					$commands = trim($commands_pre);
					if ($commands != "") {
						$numbrows = count(explode("\n", $commands));
						$commands_pre = UI::twig()->render(UI::validateThemeTemplate('/settings/conf/command.html.twig', self::$theme), [
							'commands' => $commands,
							'numbrows' => $numbrows
						]);
					}
					$commands = trim($commands_post);
					if ($commands != "") {
						$numbrows = count(explode("\n", $commands));
						$commands_post = UI::twig()->render(UI::validateThemeTemplate('/settings/conf/command.html.twig', self::$theme), [
							'commands' => $commands,
							'numbrows' => $numbrows
						]);
					}
					$configpage .= UI::twig()->render(UI::validateThemeTemplate('/settings/conf/fileblock.html.twig', self::$theme), [
						'realname' => $realname,
						'commands_pre' => $commands_pre,
						'commands_file' => $commands_file,
						'commands_post' => $commands_post
					]);
					$commands = '';
					$commands_pre = '';
					$commands_post = '';
					break;
			}
		}
		$commands = trim($commands);
		if ($commands != '') {
			$numbrows = count(explode("\n", $commands));
			$configpage .= UI::twig()->render(UI::validateThemeTemplate('/settings/conf/command.html.twig', self::$theme), [
				'commands' => $commands,
				'numbrows' => $numbrows
			]);
		}
		return $configpage;
	}

	/**
	 * @param string $file_content
	 * @param string $realname
	 *
	 * @return string
	 */
	private static function getFileContentContainer(string $file_content, string $realname): string
	{
		$files = "";
		$file_content = trim($file_content);
		if ($file_content != '') {
			$file_content = strtr($file_content, self::$replace_arr);
			$file_content = htmlspecialchars($file_content);
			$numbrows = count(explode("\n", $file_content));
			//eval("\$files=\"" . \Froxlor\UI\Template::getTemplate("configfiles/configfiles_file") . "\";");
			$files = UI::twig()->render(UI::validateThemeTemplate('/settings/conf/file.html.twig', self::$theme), [
				'distro_editor' => self::$editor,
				'realname' => $realname,
				'numbrows' => $numbrows,
				'file_content' => $file_content
			]);
		}
		return $files;
	}
}
