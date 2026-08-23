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

const AREA = 'login';
require __DIR__ . '/lib/init.php';

use Froxlor\Api\FroxlorRPC;
use Froxlor\CurrentUser;
use Froxlor\Customer\Customer;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\FroxlorTwoFactorAuth;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Crypt;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\User;
use Froxlor\Validate\Validate;

if ($action == '') {
	$action = 'login';
}

if ($action == '2fa_entercode') {
	// page for entering the 2FA code after successful login
	if (!isset($_SESSION) || !isset($_SESSION['secret_2fa'])) {
		// no session - redirect to index
		Response::redirectTo('index.php');
		exit();
	}
	$smessage = (int)Request::get('showmessage', 0);
	$message = "";
	if ($smessage > 0) {
		$message = lng('error.2fa_wrongcode');
	}
	// show template to enter code
	UI::view('login/enter2fa.html.twig', [
		'pagetitle' => lng('login.2fa'),
		'remember_me' => (Settings::Get('panel.db_version') >= 202608210) ? true : false,
		'message' => $message
	]);
} elseif ($action == '2fa_verify') {
	// verify code from 2fa code-enter form
	if (!isset($_SESSION) || !isset($_SESSION['secret_2fa'])) {
		// no session - redirect to index
		Response::redirectTo('index.php');
		exit();
	}
	$code = Request::post('2fa_code');
	$remember = Request::post('2fa_remember');
	// verify entered code
	$tfa = new FroxlorTwoFactorAuth('Froxlor ' . Settings::Get('system.hostname'));
	// get user-data
	$table = $_SESSION['uidtable_2fa'];
	$field = $_SESSION['uidfield_2fa'];
	$uid = $_SESSION['uid_2fa'];
	$isadmin = $_SESSION['unfo_2fa'];
	if ($_SESSION['secret_2fa'] == 'email') {
		// verify code set to user's data_2fa field
		$sel_stmt = Database::prepare("SELECT `data_2fa` FROM " . $table . " WHERE `" . $field . "` = :uid");
		$userinfo_code = Database::pexecute_first($sel_stmt, ['uid' => $uid]);
		// 60sec discrepancy (possible slow email delivery)
		$result = $tfa->verifyCode($userinfo_code['data_2fa'], $code, 60);
	} else {
		$result = $tfa->verifyCode($_SESSION['secret_2fa'], $code, 3);
	}
	// either the code is valid when using authenticator-app, or we will select userdata by id and entered code
	// which is temporarily stored for the customer when using email-2fa
	if ($result) {
		$sel_param = [
			'uid' => $uid
		];
		$sel_stmt = Database::prepare("SELECT * FROM " . $table . " WHERE `" . $field . "` = :uid");
		$userinfo = Database::pexecute_first($sel_stmt, $sel_param);
		// whoops, no (valid) user? Start again
		if (empty($userinfo)) {
			Response::redirectTo('index.php', [
				'showmessage' => '2'
			]);
		}
		// set fields in $userinfo required for finishLogin()
		$userinfo['adminsession'] = $isadmin;
		$userinfo['userid'] = $uid;

		// when using email-2fa, remove the one-time-code
		if ($userinfo['type_2fa'] == '1') {
			$del_stmt = Database::prepare("UPDATE " . $table . " SET `data_2fa` = '' WHERE `" . $field . "` = :uid");
			Database::pexecute_first($del_stmt, [
				'uid' => $uid
			]);
		}

		// when remember is activated, set the cookie - guarded by db_version since the
		// `admin` column (needed to scope tokens to the admin/customer namespace) might
		// not exist yet if this code has been deployed but the db update hasn't run yet
		if ($remember && Settings::Get('panel.db_version') >= 202608210) {
			$selector = base64_encode(Froxlor::genSessionId(9));
			$authenticator = Froxlor::genSessionId(33);
			$valid_until = time()+60*60*24*30;
			$ins_stmt = Database::prepare("
				INSERT INTO `".TABLE_PANEL_2FA_TOKENS."` SET
				`selector` = :selector,
				`token` = :authenticator,
				`userid` = :userid,
				`admin` = :isadmin,
				`valid_until` = :valid_until
			");
			Database::pexecute($ins_stmt, [
				'selector' => $selector,
				'authenticator' => hash('sha256', $authenticator),
				'userid' => $uid,
				'isadmin' => $isadmin ? 1 : 0,
				'valid_until' => $valid_until
			]);
			$cookie_params = [
				'expires' => $valid_until, // 30 days
				'path' => '/',
				'domain' => UI::getCookieHost(),
				'secure' => UI::requestIsHttps(),
				'httponly' => true,
				'samesite' => 'Strict'
			];
			setcookie('frx_2fa_remember', $selector.':'.base64_encode($authenticator), $cookie_params);
		}

		// if not successful somehow - start again
		if (!finishLogin($userinfo)) {
			Response::redirectTo('index.php', [
				'showmessage' => '2'
			]);
		}
		exit();
	}
	// wrong 2fa code - treat like "wrong password"
	$stmt = Database::prepare("
		UPDATE " . $table . "
		SET `lastlogin_fail`= :lastlogin_fail, `loginfail_count`=`loginfail_count`+1
		WHERE `" . $field . "`= :uid
	");
	Database::pexecute($stmt, [
		"lastlogin_fail" => time(),
		"uid" => $uid
	]);

	// get data for processing further
	$stmt = Database::prepare("
		SELECT `loginname`, `loginfail_count`, `lastlogin_fail` FROM " . $table . "
		WHERE `" . $field . "`= :uid
	");
	$fail_user = Database::pexecute_first($stmt, [
		"uid" => $uid
	]);

	if ($fail_user['loginfail_count'] >= Settings::Get('login.maxloginattempts') && $fail_user['lastlogin_fail'] > (time() - Settings::Get('login.deactivatetime'))) {
		// Log failed login
		$rstlog = FroxlorLogger::getInstanceOf([
			'loginname' => $_SERVER['REMOTE_ADDR']
		]);
		$rstlog->logAction(FroxlorLogger::LOGIN_ACTION, LOG_WARNING, "User '" . $fail_user['loginname'] . "' entered wrong 2fa code too often.");
		unset($fail_user);
		Response::redirectTo('index.php', [
			'showmessage' => '3'
		]);
		exit();
	}
	unset($fail_user);
	// back to form
	Response::redirectTo('index.php', [
		'action' => '2fa_entercode',
		'showmessage' => '1'
	]);
	exit();
} elseif ($action == 'login') {
	if (!empty($_POST)) {
		$loginname = Validate::validate(Request::post('loginname'), 'loginname');
		$password = Validate::validate(Request::post('password'), 'password');

		$select_additional = '';
		if (Settings::Get('panel.db_version') >= 202312230) {
			$select_additional = ' AND `gui_access` = 1';
		}
		$stmt = Database::prepare("
			SELECT `loginname` AS `customer`
			FROM `" . TABLE_PANEL_CUSTOMERS . "`
			WHERE `loginname`= :loginname" .
			$select_additional
		);
		Database::pexecute($stmt, [
			"loginname" => $loginname
		]);
		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		$is_admin = false;
		$table = "";
		if ($row && $row['customer'] == $loginname) {
			$table = "`" . TABLE_PANEL_CUSTOMERS . "`";
			$uid = 'customerid';
			$adminsession = '0';
		} else {
			if ((int)Settings::Get('login.domain_login') == 1) {
				$domainname = $idna_convert->encode(preg_replace([
					'/\:(\d)+$/',
					'/^https?\:\/\//'
				], '', $loginname));
				$stmt = Database::prepare("
					SELECT `customerid`
					FROM `" . TABLE_PANEL_DOMAINS . "`
					WHERE `domain` = :domain
				");
				Database::pexecute($stmt, [
					"domain" => $domainname
				]);
				$row2 = $stmt->fetch(PDO::FETCH_ASSOC);

				if (isset($row2['customerid']) && $row2['customerid'] > 0) {
					$loginname = Customer::getCustomerDetail($row2['customerid'], 'loginname');
					if ($loginname !== false) {
						$stmt = Database::prepare("
							SELECT `loginname` AS `customer`
							FROM `" . TABLE_PANEL_CUSTOMERS . "`
							WHERE `loginname`= :loginname
						");
						Database::pexecute($stmt, [
							"loginname" => $loginname
						]);
						$row3 = $stmt->fetch(PDO::FETCH_ASSOC);
						if ($row3 && $row3['customer'] == $loginname) {
							$table = "`" . TABLE_PANEL_CUSTOMERS . "`";
							$uid = 'customerid';
							$adminsession = '0';
						}
					}
				}
			}
		}

		if (empty($table)) {
			// try login as admin of no customer-login method worked
			$is_admin = true;
		}

		if ((Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) && $is_admin == false) {
			Response::redirectTo('index.php');
			exit();
		}

		if ($is_admin) {
			if (Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) {
				$stmt = Database::prepare("
					SELECT `loginname` AS `admin` FROM `" . TABLE_PANEL_ADMINS . "`
					WHERE `loginname`= :loginname
					AND `change_serversettings` = '1'
				");
				Database::pexecute($stmt, [
					"loginname" => $loginname
				]);
				$row = $stmt->fetch(PDO::FETCH_ASSOC);
				if (!isset($row['admin'])) {
					// not an admin who can see updates
					Response::redirectTo('index.php');
					exit();
				}
			} else {
				$select_additional = '';
				if (Settings::Get('panel.db_version') >= 202312230) {
					$select_additional = ' AND `gui_access` = 1';
				}
				$stmt = Database::prepare("
					SELECT `loginname` AS `admin`
					FROM `" . TABLE_PANEL_ADMINS . "`
					WHERE `loginname`= :loginname" .
					$select_additional
				);
				Database::pexecute($stmt, [
					"loginname" => $loginname
				]);
				$row = $stmt->fetch(PDO::FETCH_ASSOC);
			}

			if ($row && $row['admin'] == $loginname) {
				$table = "`" . TABLE_PANEL_ADMINS . "`";
				$uid = 'adminid';
				$adminsession = '1';
			} else {
				// Log failed login
				$rstlog = FroxlorLogger::getInstanceOf([
					'loginname' => $_SERVER['REMOTE_ADDR']
				]);
				$rstlog->logAction(FroxlorLogger::LOGIN_ACTION, LOG_WARNING, "Unknown user tried to login.");

				Response::redirectTo('index.php', [
					'showmessage' => '2'
				]);
				exit();
			}
		}

		$userinfo_stmt = Database::prepare("
			SELECT * FROM $table WHERE `loginname`= :loginname
		");
		Database::pexecute($userinfo_stmt, [
			"loginname" => $loginname
		]);
		$userinfo = $userinfo_stmt->fetch(PDO::FETCH_ASSOC);

		if ($userinfo['loginfail_count'] >= Settings::Get('login.maxloginattempts') && $userinfo['lastlogin_fail'] > (time() - Settings::Get('login.deactivatetime'))) {
			Response::redirectTo('index.php', [
				'showmessage' => '3'
			]);
			exit();
		} elseif (Crypt::validatePasswordLogin($userinfo, $password, $table, $uid)) {
			// only show "you're banned" if the login was successful
			// because we don't want to publish that the user does exist
			if ($userinfo['deactivated']) {
				unset($userinfo);
				Response::redirectTo('index.php', [
					'showmessage' => '5'
				]);
				exit();
			} else {
				// login correct
				// reset loginfail_counter, set lastlogin_succ
				$stmt = Database::prepare("
					UPDATE $table
					SET `lastlogin_succ`= :lastlogin_succ, `loginfail_count`='0'
					WHERE `$uid`= :uid
				");
				Database::pexecute($stmt, [
					"lastlogin_succ" => time(),
					"uid" => $userinfo[$uid]
				]);
				$userinfo['userid'] = $userinfo[$uid];
				$userinfo['adminsession'] = $adminsession;
			}
		} else {
			// login incorrect
			$stmt = Database::prepare("
				UPDATE $table
				SET `lastlogin_fail`= :lastlogin_fail, `loginfail_count`=`loginfail_count`+1
				WHERE `$uid`= :uid
			");
			Database::pexecute($stmt, [
				"lastlogin_fail" => time(),
				"uid" => $userinfo[$uid]
			]);

			// Log failed login
			$rstlog = FroxlorLogger::getInstanceOf([
				'loginname' => $_SERVER['REMOTE_ADDR']
			]);
			$rstlog->logAction(FroxlorLogger::LOGIN_ACTION, LOG_WARNING, "User tried to login with wrong password.");

			unset($userinfo);
			Response::redirectTo('index.php', [
				'showmessage' => '2'
			]);
			exit();
		}

		// 2FA activated
		if (Settings::Get('2fa.enabled') == '1' && $userinfo['type_2fa'] > 0) {

			// check for remember cookie - guarded by db_version since the `admin` column
			// might not exist yet if this code has been deployed but the db update hasn't
			// run yet; skipping just falls through to the normal 2fa code-entry prompt
			if (!empty($_COOKIE['frx_2fa_remember']) && Settings::Get('panel.db_version') >= 202608210) {
				list($selector, $authenticator) = explode(':', $_COOKIE['frx_2fa_remember']);
				// admin- and customer-ids are separate namespaces that can collide (e.g. both id 1),
				// so the lookup must also match the account type the token was issued for, not just
				// the numeric id, or a remembered customer token could satisfy an admin's 2fa step
				$sel_stmt = Database::prepare("SELECT `token` FROM `".TABLE_PANEL_2FA_TOKENS."` WHERE `selector` = :selector AND `userid` = :uid AND `admin` = :isadmin AND `valid_until` >= UNIX_TIMESTAMP()");
				$token_check = Database::pexecute_first($sel_stmt, ['selector' => $selector, 'uid' => $userinfo[$uid], 'isadmin' => $adminsession]);
				if ($token_check && hash_equals($token_check['token'], hash('sha256', base64_decode($authenticator)))) {
					if (!finishLogin($userinfo)) {
						Response::redirectTo('index.php', [
							'showmessage' => '2'
						]);
					}
					exit();
				}
				// not found or invalid, this cookie is useless, get rid of it
				unset($_COOKIE['frx_2fa_remember']);
				setcookie('frx_2fa_remember', "", time()-3600);
			}

			// redirect to code-enter-page
			$_SESSION['secret_2fa'] = ($userinfo['type_2fa'] == 2 ? $userinfo['data_2fa'] : 'email');
			$_SESSION['uid_2fa'] = $userinfo[$uid];
			$_SESSION['uidfield_2fa'] = $uid;
			$_SESSION['uidtable_2fa'] = $table;
			$_SESSION['unfo_2fa'] = $is_admin;
			// send mail if type_2fa = 1 (email)
			if ($userinfo['type_2fa'] == 1) {
				// generate code
				$tfa = new FroxlorTwoFactorAuth('Froxlor ' . Settings::Get('system.hostname'));
				$secret = $tfa->createSecret();
				$code = $tfa->getCode($secret);
				// set code for user
				$stmt = Database::prepare("UPDATE $table SET `data_2fa` = :d2fa WHERE `$uid` = :uid");
				Database::pexecute($stmt, [
					"d2fa" => $secret,
					"uid" => $userinfo[$uid]
				]);
				// build up & send email
				$_mailerror = false;
				$mailerr_msg = "";
				$replace_arr = [
					'CODE' => $code
				];
				$mail_body = html_entity_decode(PhpHelper::replaceVariables(lng('mails.2fa.mailbody'), $replace_arr));

				try {
					$mail->Subject = lng('mails.2fa.subject');
					$mail->AltBody = $mail_body;
					$mail->MsgHTML(str_replace("\n", "<br />", $mail_body));
					$mail->AddAddress($userinfo['email'], User::getCorrectUserSalutation($userinfo));
					$mail->Send();
				} catch (\PHPMailer\PHPMailer\Exception $e) {
					$mailerr_msg = $e->errorMessage();
					$_mailerror = true;
				} catch (Exception $e) {
					$mailerr_msg = $e->getMessage();
					$_mailerror = true;
				}

				if ($_mailerror) {
					$rstlog = FroxlorLogger::getInstanceOf([
						'loginname' => '2fa code-sending'
					]);
					$rstlog->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, "Error sending mail: " . $mailerr_msg);
					Response::redirectTo('index.php', [
						'showmessage' => '4',
						'customermail' => $userinfo['email']
					]);
					exit();
				}

				$mail->ClearAddresses();
			}
			Response::redirectTo('index.php', [
				'action' => '2fa_entercode'
			]);
			exit();
		}

		if (!finishLogin($userinfo)) {
			Response::redirectTo('index.php', [
				'showmessage' => '2'
			]);
		}
		exit();
	} else {
		$smessage = (int)Request::get('showmessage', 0);
		$message = '';
		$successmessage = '';

		switch ($smessage) {
			case 1:
				$successmessage = lng('pwdreminder.success');
				break;
			case 2:
				$message = lng('error.login');
				break;
			case 3:
				$message = lng('error.login_blocked', [Settings::Get('login.deactivatetime')]);
				break;
			case 4:
				$message = lng('error.errorsendingmailpub');
				break;
			case 5:
				$message = lng('error.user_banned');
				break;
			case 6:
				$successmessage = lng('pwdreminder.changed');
				break;
			case 7:
				$message = lng('pwdreminder.wrongcode');
				break;
			case 8:
				$message = lng('pwdreminder.notallowed');
				break;
		}

		$update_in_progress = false;
		if (Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) {
			$update_in_progress = true;
		}

		// Pass the last used page if needed
		$lastscript = Request::any('script', '');
		if (!empty($lastscript)) {
			$lastscript = str_replace("..", "", $lastscript);
			$lastscript = htmlspecialchars($lastscript, ENT_QUOTES);

			if (file_exists(__DIR__ . "/" . $lastscript)) {
				$_SESSION['lastscript'] = $lastscript;
			} else {
				$lastscript = "";
			}
		}
		$lastqrystr = Request::any('qrystr', '');
		if (!empty($lastqrystr)) {
			$lastqrystr = urlencode($lastqrystr);
			$_SESSION['lastqrystr'] = $lastqrystr;
		}

		UI::view('login/login.html.twig', [
			'pagetitle' => 'Login',
			'upd_in_progress' => $update_in_progress,
			'message' => $message,
			'successmsg' => $successmessage
		]);
	}
}

if ($action == 'forgotpwd') {
	$adminchecked = false;
	$message = '';

	if (!empty($_POST)) {
		$loginname = Validate::validate(Request::post('loginname'), 'loginname');
		$email = Validate::validateEmail(Request::post('loginemail'));
		$result_stmt = Database::prepare("SELECT `adminid`, `customerid`, `customernumber`, `firstname`, `name`, `company`, `email`, `loginname`, `def_language`, `deactivated` FROM `" . TABLE_PANEL_CUSTOMERS . "`
			WHERE `loginname`= :loginname
			AND `email`= :email");
		Database::pexecute($result_stmt, [
			"loginname" => $loginname,
			"email" => $email
		]);

		if (Database::num_rows() == 0) {
			$result_stmt = Database::prepare("SELECT `adminid`, `name`, `email`, `loginname`, `def_language`, `deactivated` FROM `" . TABLE_PANEL_ADMINS . "`
				WHERE `loginname`= :loginname
				AND `email`= :email");
			Database::pexecute($result_stmt, [
				"loginname" => $loginname,
				"email" => $email
			]);

			if (Database::num_rows() > 0) {
				$adminchecked = true;
			} else {
				$result_stmt = null;
			}
		}

		if ($adminchecked) {
			if (Settings::Get('panel.allow_preset_admin') != '1') {
				$message = lng('pwdreminder.notallowed');
				unset($adminchecked);
			}
		} else {
			if (Settings::Get('panel.allow_preset') != '1') {
				$message = lng('pwdreminder.notallowed');
			}
		}

		if (empty($message)) {
			if ($result_stmt !== null) {
				$user = $result_stmt->fetch(PDO::FETCH_ASSOC);

				/* Check whether user is banned */
				if ($user['deactivated']) {
					$message = lng('pwdreminder.notallowed');
				} else {
					if (($adminchecked && Settings::Get('panel.allow_preset_admin') == '1') || $adminchecked == false) {
						if ($user !== false) {
							// build a activation code
							$timestamp = time();
							$first = substr(md5($user['loginname'] . $timestamp . PhpHelper::randomStr(16)), 0, 15);
							$third = substr(md5($user['email'] . $timestamp . PhpHelper::randomStr(16)), -15);
							$activationcode = $first . $timestamp . $third . substr(md5($third . $timestamp), 0, 10);

							// Drop all existing activation codes for this user
							$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_ACTIVATION . "`
								WHERE `userid` = :userid
								AND `admin` = :admin");
							$params = [
								"userid" => $adminchecked ? $user['adminid'] : $user['customerid'],
								"admin" => $adminchecked ? 1 : 0
							];
							Database::pexecute($stmt, $params);

							// Add new activation code to database
							$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_ACTIVATION . "`
								(userid, admin, creation, activationcode)
								VALUES (:userid, :admin, :creation, :activationcode)");
							$params = [
								"userid" => $adminchecked ? $user['adminid'] : $user['customerid'],
								"admin" => $adminchecked ? 1 : 0,
								"creation" => $timestamp,
								"activationcode" => $activationcode
							];
							Database::pexecute($stmt, $params);

							$rstlog = FroxlorLogger::getInstanceOf([
								'loginname' => 'password_reset'
							]);
							$rstlog->logAction(FroxlorLogger::USR_ACTION, LOG_WARNING, "User '" . $user['loginname'] . "' requested a link for setting a new password.");

							// Set together our activation link
							$protocol = empty($_SERVER['HTTPS']) ? 'http' : 'https';
							// this can be a fixed value to avoid potential exploiting by modifying headers
							$host = Settings::Get('system.hostname'); // $_SERVER['HTTP_HOST'];
							$port = $_SERVER['SERVER_PORT'] != 80 ? ':' . $_SERVER['SERVER_PORT'] : '';
							// don't add :443 when https is used, as it is default (and just looks weird!)
							if ($protocol == 'https' && $_SERVER['SERVER_PORT'] == '443') {
								$port = '';
							}
							// there can be only one script to handle this so we can use a fixed value here
							$script = "/index.php"; // $_SERVER['SCRIPT_NAME'];
							if (Settings::Get('system.froxlordirectlyviahostname') == 0) {
								$script = FileDir::makeCorrectFile("/" . basename(__DIR__) . "/" . $script);
							}
							$activationlink = $protocol . '://' . $host . $port . $script . '?action=resetpwd&resetcode=' . $activationcode;

							$replace_arr = [
								'SALUTATION' => User::getCorrectUserSalutation($user),
								'NAME' => $user['name'],
								'FIRSTNAME' => $user['firstname'] ?? "",
								'COMPANY' => $user['company'] ?? "",
								'CUSTOMER_NO' => $user['customernumber'] ?? 0,
								'USERNAME' => $loginname,
								'LINK' => $activationlink
							];

							$def_language = ($user['def_language'] != '') ? $user['def_language'] : Settings::Get('panel.standardlanguage');
							$result_stmt = Database::prepare('SELECT `value` FROM `' . TABLE_PANEL_TEMPLATES . '`
								WHERE `adminid`= :adminid
								AND `language`= :lang
								AND `templategroup`=\'mails\'
								AND `varname`=\'password_reset_subject\'');
							Database::pexecute($result_stmt, [
								"adminid" => $user['adminid'],
								"lang" => $def_language
							]);
							$result = $result_stmt->fetch(PDO::FETCH_ASSOC);
							$mail_subject = html_entity_decode(PhpHelper::replaceVariables((($result['value'] != '') ? $result['value'] : lng('mails.password_reset.subject')), $replace_arr));

							$result_stmt = Database::prepare('SELECT `value` FROM `' . TABLE_PANEL_TEMPLATES . '`
								WHERE `adminid`= :adminid
								AND `language`= :lang
								AND `templategroup`=\'mails\'
								AND `varname`=\'password_reset_mailbody\'');
							Database::pexecute($result_stmt, [
								"adminid" => $user['adminid'],
								"lang" => $def_language
							]);
							$result = $result_stmt->fetch(PDO::FETCH_ASSOC);
							$mail_body = html_entity_decode(PhpHelper::replaceVariables((($result['value'] != '') ? $result['value'] : lng('mails.password_reset.mailbody')), $replace_arr));

							$_mailerror = false;
							$mailerr_msg = "";
							try {
								$mail->Subject = $mail_subject;
								$mail->AltBody = $mail_body;
								$mail->MsgHTML(str_replace("\n", "<br />", $mail_body));
								$mail->AddAddress($user['email'], User::getCorrectUserSalutation($user));
								$mail->Send();
							} catch (\PHPMailer\PHPMailer\Exception $e) {
								$mailerr_msg = $e->errorMessage();
								$_mailerror = true;
							} catch (Exception $e) {
								$mailerr_msg = $e->getMessage();
								$_mailerror = true;
							}

							if ($_mailerror) {
								$rstlog = FroxlorLogger::getInstanceOf([
									'loginname' => 'password_reset'
								]);
								$rstlog->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, "Error sending mail: " . $mailerr_msg);
								Response::redirectTo('index.php', [
									'showmessage' => '4',
									'customermail' => $user['email']
								]);
								exit();
							}

							$mail->ClearAddresses();
							Response::redirectTo('index.php', [
								'showmessage' => '1'
							]);
							exit();
						} else {
							$rstlog = FroxlorLogger::getInstanceOf([
								'loginname' => 'password_reset'
							]);
							$rstlog->logAction(FroxlorLogger::USR_ACTION, LOG_WARNING, "Unknown user requested to set a new password, but was not found in database!");
							$message = lng('login.usernotfound');
						}

						unset($user);
					}
				}
			} else {
				$message = lng('pwdreminder.notallowed');
			}
		}
	}

	UI::view('login/fpwd.html.twig', [
		'pagetitle' => lng('login.presend'),
		'formaction' => 'index.php?action=' . $action,
		'message' => $message,
	]);
}

if ($action == 'resetpwd') {
	$message = '';

	// Remove old activation codes
	$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_ACTIVATION . "`
		WHERE creation < :oldest");
	Database::pexecute($stmt, [
		"oldest" => time() - 86400
	]);

	$activationcode = Request::get('resetcode');
	if (!empty($activationcode) && strlen($activationcode) == 50) {
		// Check if activation code is valid
		$timestamp = substr($activationcode, 15, 10);
		$third = substr($activationcode, 25, 15);
		$check = substr($activationcode, 40, 10);

		if (substr(md5($third . $timestamp), 0, 10) == $check && $timestamp >= time() - 86400) {
			if (!empty($_POST)) {
				$stmt = Database::prepare("SELECT `userid`, `admin` FROM `" . TABLE_PANEL_ACTIVATION . "`
					WHERE `activationcode` = :activationcode");
				$result = Database::pexecute_first($stmt, [
					"activationcode" => $activationcode
				]);

				if ($result !== false) {
					try {
						$new_password = Crypt::validatePassword(Request::post('new_password'), true);
						$new_password_confirm = Crypt::validatePassword(Request::post('new_password_confirm'), true);
					} catch (Exception $e) {
						$message = $e->getMessage();
					}

					if (empty($message) && (empty($new_password) || $new_password != $new_password_confirm)) {
						$message = lng('error.newpasswordconfirmerror');
					}

					if (empty($message)) {
						// Update user password
						if ($result['admin'] == 1) {
							$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_ADMINS . "`
								SET `password` = :newpassword
								WHERE `adminid` = :userid");
						} else {
							$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "`
								SET `password` = :newpassword
								WHERE `customerid` = :userid");
						}
						Database::pexecute($stmt, [
							"newpassword" => Crypt::makeCryptPassword($new_password),
							"userid" => $result['userid']
						]);

						$rstlog = FroxlorLogger::getInstanceOf([
							'loginname' => 'password_reset'
						]);
						$rstlog->logAction(FroxlorLogger::USR_ACTION, LOG_NOTICE, "changed password using password reset.");

						// Remove activation code from DB
						$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_ACTIVATION . "`
							WHERE `activationcode` = :activationcode
							AND `userid` = :userid");
						Database::pexecute($stmt, [
							"activationcode" => $activationcode,
							"userid" => $result['userid']
						]);
						Response::redirectTo('index.php', [
							"showmessage" => '6'
						]);
					}
				} else {
					Response::redirectTo('index.php', [
						"showmessage" => '7'
					]);
				}
			}

			UI::view('login/rpwd.html.twig', [
				'pagetitle' => lng('pwdreminder.choosenew'),
				'formaction' => 'index.php?action=resetpwd&resetcode=' . $activationcode,
				'message' => $message,
			]);
		} else {
			Response::redirectTo('index.php', [
				"showmessage" => '7'
			]);
		}
	} else {
		Response::redirectTo('index.php');
	}
}

// one-time link login
if ($action == 'll') {
	if (!Froxlor::hasUpdates() && !Froxlor::hasDbUpdates()) {
		$loginname = Request::get('ln');
		$hash = Request::get('h');
		if ($loginname && $hash) {
			$sel_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_LOGINLINKS . "`
				WHERE `loginname` = :loginname AND `hash` = :hash
			");
			try {
				$entry = Database::pexecute_first($sel_stmt, ['loginname' => $loginname, 'hash' => $hash]);
			} catch (Exception $e) {
				$entry = false;
			}
			if ($entry) {
				// delete entry
				$del_stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_LOGINLINKS . "` WHERE `loginname` = :loginname AND `hash` = :hash");
				Database::pexecute($del_stmt, ['loginname' => $loginname, 'hash' => $hash]);
				if (time() <= $entry['valid_until']) {
					$valid = true;
					// validate source ip if specified
					if (!empty($entry['allowed_from'])) {
						$valid = false;
						$ip_list = explode(",", $entry['allowed_from']);
						if (FroxlorRPC::validateAllowedFrom($ip_list, $_SERVER['REMOTE_ADDR'])) {
							$valid = true;
						}
					}
					if ($valid) {
						// login user / select only non-deactivated (in case the user got deactivated after generating the link)
						$userinfo_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname`= :loginname AND `deactivated` = 0");
						try {
							$userinfo = Database::pexecute_first($userinfo_stmt, [
								"loginname" => $loginname
							]);
						} catch (Exception $e) {
							$userinfo = false;
						}
						if ($userinfo) {
							$userinfo['userid'] = $userinfo['customerid'];
							$userinfo['adminsession'] = 0;
							finishLogin($userinfo);
						}
					}
				}
			}
		}
	}
	Response::redirectTo('index.php');
}

function finishLogin($userinfo)
{
	if (isset($userinfo['userid']) && $userinfo['userid'] != '') {
		session_regenerate_id(true);
		CurrentUser::setData($userinfo);

		$language = $userinfo['def_language'] ?? Settings::Get('panel.standardlanguage');
		CurrentUser::setField('language', $language);

		if (isset($userinfo['theme']) && $userinfo['theme'] != '') {
			$theme = $userinfo['theme'];
		} else {
			$theme = Settings::Get('panel.default_theme');
		}
		CurrentUser::setField('theme', $theme);

		$qryparams = [];
		if (!empty($_SESSION['lastqrystr'])) {
			parse_str(urldecode($_SESSION['lastqrystr']), $qryparams);
			unset($_SESSION['lastqrystr']);
		}

		if ($userinfo['adminsession'] == '1') {
			if (Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) {
				Response::redirectTo('admin_updates.php?page=overview');
			} else {
				if (!empty($_SESSION['lastscript'])) {
					$lastscript = $_SESSION['lastscript'];
					unset($_SESSION['lastscript']);
					if (preg_match("/customer\_/", $lastscript) === 1) {
						Response::redirectTo('admin_customers.php', [
							"page" => "customers"
						]);
					} else {
						Response::redirectTo($lastscript, $qryparams);
					}
				} else {
					Response::redirectTo('admin_index.php', $qryparams);
				}
			}
		} else {
			if (!empty($_SESSION['lastscript'])) {
				$lastscript = $_SESSION['lastscript'];
				unset($_SESSION['lastscript']);
				Response::redirectTo($lastscript, $qryparams);
			} else {
				Response::redirectTo('customer_index.php', $qryparams);
			}
		}
	}
	return false;
}
