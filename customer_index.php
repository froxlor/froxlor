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

const AREA = 'customer';
require __DIR__ . '/lib/init.php';

use Froxlor\Api\Commands\Customers as Customers;
use Froxlor\Cron\TaskId;
use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\Database\DbManager;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Language;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\System\Crypt;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;

if ($action == 'logout') {
	$log->logAction(FroxlorLogger::USR_ACTION, LOG_INFO, 'logged out');

	unset($_SESSION['userinfo']);
	CurrentUser::setData();
	session_destroy();

	Response::redirectTo('index.php');
} elseif ($action == 'suback') {
	if (is_array(CurrentUser::getField('switched_user'))) {
		$result = CurrentUser::getData();
		$result = $result['switched_user'];
		session_regenerate_id(true);
		CurrentUser::setData($result);
		$target = Request::get('target', 'index');
		$redirect = "admin_" . $target . ".php";
		if (!file_exists(Froxlor::getInstallDir() . "/" . $redirect)) {
			$redirect = "admin_index.php";
		}
		Response::redirectTo($redirect, null, true);
	} else {
		Response::dynamicError("Cannot change back - You've never switched to another user :-)");
	}
}

if ($page == 'overview') {
	$log->logAction(FroxlorLogger::USR_ACTION, LOG_INFO, "viewed customer_index");

	$domain_stmt = Database::prepare("SELECT `domain` FROM `" . TABLE_PANEL_DOMAINS . "`
		WHERE `customerid` = :customerid
		AND `parentdomainid` = '0'
		AND `id` <> :standardsubdomain
	");
	Database::pexecute($domain_stmt, [
		"customerid" => $userinfo['customerid'],
		"standardsubdomain" => $userinfo['standardsubdomain']
	]);

	$domainArray = [];
	while ($row = $domain_stmt->fetch(PDO::FETCH_ASSOC)) {
		$domainArray[] = $idna_convert->decode($row['domain']);
	}
	natsort($domainArray);

	// standard-subdomain
	$stdsubdomain = '';
	if ($userinfo['standardsubdomain'] != '0') {
		$std_domain_stmt = Database::prepare("
			SELECT `domain` FROM `" . TABLE_PANEL_DOMAINS . "`
			WHERE `customerid` = :customerid
			AND `id` = :standardsubdomain
		");
		$std_domain = Database::pexecute_first($std_domain_stmt, [
			"customerid" => $userinfo['customerid'],
			"standardsubdomain" => $userinfo['standardsubdomain']
		]);
		$stdsubdomain = $std_domain['domain'];
	}

	$userinfo['email'] = $idna_convert->decode($userinfo['email']);
	$yesterday = time() - (60 * 60 * 24);
	$month = date('M Y', $yesterday);

	// get disk-space usages for web, mysql and mail
	$usages_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_DISKSPACE . "` WHERE `customerid` = :cid ORDER BY `stamp` DESC LIMIT 1");
	$usages = Database::pexecute_first($usages_stmt, [
		'cid' => $userinfo['customerid']
	]);

	// get everything in bytes for the percentage calculation on the dashboard
	$userinfo['diskspace_bytes'] = ($userinfo['diskspace'] > -1) ? $userinfo['diskspace'] * 1024 : -1;
	$userinfo['traffic_bytes'] = ($userinfo['traffic'] > -1) ? $userinfo['traffic'] * 1024 : -1;
	$userinfo['traffic_bytes_used'] = $userinfo['traffic_used'] * 1024;

	if (Settings::Get('system.mail_quota_enabled')) {
		$userinfo['email_quota_bytes'] = ($userinfo['email_quota'] > -1) ? $userinfo['email_quota'] * 1024 * 1024 : -1;
		$userinfo['email_quota_bytes_used'] = $userinfo['email_quota_used'] * 1024 * 1024;
	}

	if ($usages) {
		$userinfo['diskspace_bytes_used'] = $usages['webspace'] * 1024;
		$userinfo['mailspace_used'] = $usages['mail'] * 1024;
		$userinfo['dbspace_used'] = $usages['mysql'] * 1024;
		$userinfo['total_bytes_used'] = ($usages['webspace'] + $usages['mail'] + $usages['mysql']) * 1024;
	} else {
		$userinfo['diskspace_bytes_used'] = 0;
		$userinfo['total_bytes_used'] = 0;
		$userinfo['mailspace_used'] = 0;
		$userinfo['dbspace_used'] = 0;
	}

	UI::twig()->addGlobal('userinfo', $userinfo);
	UI::view('user/index.html.twig', [
		'domains' => $domainArray,
		'stdsubdomain' => $stdsubdomain
	]);
} elseif ($page == 'profile') {
	$languages = Language::getLanguages();

	if (!empty($_POST)) {
		if (Request::post('send') == 'changepassword') {
			$old_password = Validate::validate(Request::post('old_password'), 'old password');

			if (!Crypt::validatePasswordLogin($userinfo, $old_password, TABLE_PANEL_CUSTOMERS, 'customerid')) {
				Response::standardError('oldpasswordnotcorrect');
			}

			try {
				$new_password = Crypt::validatePassword(Request::post('new_password'), 'new password');
				$new_password_confirm = Crypt::validatePassword(Request::post('new_password_confirm'), 'new password confirm');
			} catch (Exception $e) {
				Response::dynamicError($e->getMessage());
			}

			if ($old_password == '') {
				Response::standardError([
					'stringisempty',
					'changepassword.old_password'
				]);
			} elseif ($new_password == '') {
				Response::standardError([
					'stringisempty',
					'changepassword.new_password'
				]);
			} elseif ($new_password_confirm == '') {
				Response::standardError([
					'stringisempty',
					'changepassword.new_password_confirm'
				]);
			} elseif ($new_password != $new_password_confirm) {
				Response::standardError('newpasswordconfirmerror');
			} else {
				// Update user password
				try {
					Customers::getLocal($userinfo, [
						'id' => $userinfo['customerid'],
						'new_customer_password' => $new_password
					])->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, 'changed password');

				// Update ftp password
				if (Request::post('change_main_ftp') == 'true') {
					$cryptPassword = Crypt::makeCryptPassword($new_password);
					$stmt = Database::prepare("UPDATE `" . TABLE_FTP_USERS . "`
					SET `password` = :password
					WHERE `customerid` = :customerid
					AND `username` = :username");
					$params = [
						"password" => $cryptPassword,
						"customerid" => $userinfo['customerid'],
						"username" => $userinfo['loginname']
					];
					Database::pexecute($stmt, $params);
					$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, 'changed main ftp password');
				}

				// Update statistics password
				if (Request::post('change_stats') == 'true') {
					$new_stats_password = Crypt::makeCryptPassword($new_password, true);

					$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_HTPASSWDS . "`
					SET `password` = :password
					WHERE `customerid` = :customerid
					AND `username` = :username");
					$params = [
						"password" => $new_stats_password,
						"customerid" => $userinfo['customerid'],
						"username" => $userinfo['loginname']
					];
					Database::pexecute($stmt, $params);
					Cronjob::inserttask(TaskId::REBUILD_VHOST);
				}

				// Update global myqsl user password
				if ($userinfo['mysqls'] != 0 && Request::post('change_global_mysql') == 'true') {
					$allowed_mysqlservers = json_decode($userinfo['allowed_mysqlserver'] ?? '[]', true);
					foreach ($allowed_mysqlservers as $dbserver) {
						// require privileged access for target db-server
						Database::needRoot(true, $dbserver, false);
						// get DbManager
						$dbm = new DbManager($log);
						// give permission to the user on every access-host we have
						foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
							if ($dbm->getManager()->userExistsOnHost($userinfo['loginname'], $mysql_access_host)) {
								$dbm->getManager()->grantPrivilegesTo($userinfo['loginname'], $new_password, $mysql_access_host, false, true);
							} else {
								// create global mysql user if not exists
								$dbm->getManager()->grantPrivilegesTo($userinfo['loginname'], $new_password, $mysql_access_host, false, false, true);
							}
						}
						$dbm->getManager()->flushPrivileges();
					}
				}

				// hint at rotating active api-keys instead of silently invalidating them
				if (Settings::Get('api.enabled') == 1 && $userinfo['api_allowed'] == 1) {
					$apikey_count_stmt = Database::prepare("
						SELECT COUNT(*) AS `cnt` FROM `" . TABLE_API_KEYS . "`
						WHERE `customerid` = :id AND (`valid_until` = -1 OR `valid_until` >= UNIX_TIMESTAMP())
					");
					$apikey_count = Database::pexecute_first($apikey_count_stmt, [
						'id' => $userinfo['customerid']
					])['cnt'];
					if ($apikey_count > 0) {
						Response::standardSuccess('changepassword.apikeys_hint', $apikey_count, [
							'filename' => $filename,
							'page' => 'apikeys'
						]);
					}
				}

				Response::redirectTo($filename);
			}
		} elseif (Request::post('send') == 'changetheme') {
			if (Settings::Get('panel.allow_theme_change_customer') == 1) {
				$theme = Validate::validate(Request::post('theme'), 'theme');
				try {
					Customers::getLocal($userinfo, [
						'id' => $userinfo['customerid'],
						'theme' => $theme
					])->update();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}

				$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "changed default theme to '" . $theme . "'");
			}
			Response::redirectTo($filename);
		} elseif (Request::post('send') == 'changelanguage') {
			$def_language = Validate::validate(Request::post('def_language'), 'default language');
			if (isset($languages[$def_language])) {
				try {
					Customers::getLocal($userinfo, [
						'id' => $userinfo['customerid'],
						'def_language' => $def_language
					])->update();
					CurrentUser::setField('language', $def_language);
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
			}
			$log->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "changed default language to '" . $def_language . "'");
			Response::redirectTo($filename);
		}
	} else {
		// change theme
		$default_theme = Settings::Get('panel.default_theme');
		if ($userinfo['theme'] != '') {
			$default_theme = $userinfo['theme'];
		}
		$themes_avail = UI::getThemes();

		// change language
		$default_lang = Settings::Get('panel.standardlanguage');
		if ($userinfo['def_language'] != '') {
			$default_lang = $userinfo['def_language'];
		}

		UI::view('user/profile.html.twig', [
			'themes' => $themes_avail,
			'default_theme' => $default_theme,
			'languages' => $languages,
			'default_lang' => $default_lang,
		]);
	}
} elseif ($page == 'send_error_report' && Settings::Get('system.allow_error_report_customer') == '1') {
	require_once __DIR__ . '/error_report.php';
} elseif ($page == 'apikeys' && Settings::Get('api.enabled') == 1) {
	require_once __DIR__ . '/api_keys.php';
} elseif ($page == '2fa' && Settings::Get('2fa.enabled') == 1) {
	require_once __DIR__ . '/2fa.php';
}
