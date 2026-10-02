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

namespace Froxlor\Api\Commands;

use Exception;
use Froxlor\Api\ApiCommand;
use Froxlor\Api\ResourceEntity;
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\System\Crypt;
use Froxlor\UI\Response;
use Froxlor\User;
use Froxlor\Validate\Check;
use Froxlor\Validate\Validate;

/**
 * @since 0.10.0
 */
class EmailAccounts extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new email account for a given email-address either by id or emailaddr
	 *
	 * @param int $id
	 *            optional email-address-id of email-address to add the account for
	 * @param string $emailaddr
	 *            optional email-address to add the account for
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param string $email_password
	 *            password for the account
	 * @param string $alternative_email
	 *            optional email address to send account information to, default is the account that is being created
	 * @param int $email_quota
	 *            optional quota if enabled in MB, default setting: system.mail_quota
	 * @param bool $sendinfomail
	 *            optional, sends the welcome message to the new account (needed for creation, without the user won't
	 *            be able to login before any mail is received), default 1 (true)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		if ($this->getUserDetail('email_accounts_used') < $this->getUserDetail('email_accounts') || $this->getUserDetail('email_accounts') == '-1') {
			// parameter
			$id = $this->getParam('id', true, 0);
			$ea_optional = $id > 0;
			$emailaddr = $this->getParam('emailaddr', $ea_optional, '');
			$email_password = $this->getParam('email_password');
			$alternative_email = $this->getParam('alternative_email', true, '');
			$quota = $this->getParam('email_quota', true, Settings::Get('system.mail_quota') ?? 0);
			$sendinfomail = $this->getBoolParam('sendinfomail', true, 1);

			// validation
			$quota = Validate::validate($quota, 'email_quota', '/^\d+$/', 'vmailquotawrong', [], true);

			// get needed customer info to reduce the email-account-counter by one
			$customer = $this->getCustomerData('email_accounts');

			// check for imap||pop3 == 1, see #1298
			// d00p, 6.5.2023 @revert this - if a customer has resources which allow email accounts
			// it implicitly allowed SMTP, e.g. sending of emails which also requires an account to exist
			/*
			if ($customer['imap'] != '1' && $customer['pop3'] != '1') {
				Response::standardError('notallowedtouseaccounts', '', true);
			}
			*/

			if (!empty($emailaddr)) {
				$idna_convert = new IdnaWrapper();
				$emailaddr = $idna_convert->encode($emailaddr);
			}

			// get email address
			$result = $this->apiCall('Emails.get', [
				'id' => $id,
				'emailaddr' => $emailaddr
			]);
			$id = $result['id'];

			$idna_convert = new IdnaWrapper();
			$email_full = $result['email_full'];
			$username = $email_full;
			$password = Validate::validate($email_password, 'password', '', '', [], true);
			$password = Crypt::validatePassword($password, true);

			if ($result['popaccountid'] != 0) {
				throw new Exception("Email address '" . $email_full . "' has already an account assigned.", 406);
			}

			if (Check::checkMailAccDeletionState($email_full)) {
				Response::standardError([
					'mailaccistobedeleted'
				], $email_full, true);
			}

			// alternative email address to send info to
			if (Settings::Get('panel.sendalternativemail') == 1) {
				$alternative_email = $idna_convert->encode(Validate::validate($alternative_email, 'alternative_email', '', '', [], true));
				if (!empty($alternative_email) && !Validate::validateEmail($alternative_email)) {
					Response::standardError('alternativeemailiswrong', $alternative_email, true);
				}
			} else {
				$alternative_email = '';
			}

			// validate quota if enabled
			if (Settings::Get('system.mail_quota_enabled') == 1) {
				if ($customer['email_quota'] != '-1' && ($quota == 0 || ($quota + $customer['email_quota_used']) > $customer['email_quota'])) {
					Response::standardError('allocatetoomuchquota', $quota, true);
				}
			} else {
				// disable
				$quota = 0;
			}

			if ($password == $email_full) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			}

			// prefix hash-algo
			switch (Settings::Get('system.passwordcryptfunc')) {
				case 'argon2i':
					$cpPrefix = '{ARGON2I}';
					break;
				case 'argon2id':
					$cpPrefix = '{ARGON2ID}';
					break;
				default:
					$cpPrefix = '{BLF-CRYPT}';
					break;
			}
			// encrypt the password
			$cryptPassword = $cpPrefix . Crypt::makeCryptPassword($password);

			$email_user = substr($email_full, 0, strrpos($email_full, "@"));
			$email_domain = substr($email_full, strrpos($email_full, "@") + 1);
			$maildirname = trim(Settings::Get('system.vmail_maildirname'));
			// Add trailing slash to Maildir if needed
			$maildirpath = $maildirname;
			if (!empty($maildirname) && substr($maildirname, -1) != "/") {
				$maildirpath .= "/";
			}

			// insert data
			$stmt = Database::prepare("INSERT INTO `" . TABLE_MAIL_USERS . "` SET
				`customerid` = :cid,
				`email` = :email,
				`username` = :username," . (Settings::Get('system.mailpwcleartext') == '1' ? '`password` = :password, ' : '') . "
				`password_enc` = :password_enc,
				`homedir` = :homedir,
				`maildir` = :maildir,
				`uid` = :uid,
				`gid` = :gid,
				`domainid` = :domainid,
				`postfix` = 'y',
				`quota` = :quota,
				`imap` = :imap,
				`pop3` = :pop3
			");
			$params = [
				"cid" => $customer['customerid'],
				"email" => $email_full,
				"username" => $username,
				"password_enc" => $cryptPassword,
				"homedir" => Settings::Get('system.vmail_homedir'),
				"maildir" => $customer['loginname'] . '/' . $email_domain . "/" . $email_user . "/" . $maildirpath,
				"uid" => Settings::Get('system.vmail_uid'),
				"gid" => Settings::Get('system.vmail_gid'),
				"domainid" => $result['domainid'],
				"quota" => $quota,
				"imap" => $customer['imap'],
				"pop3" => $customer['pop3']
			];
			if (Settings::Get('system.mailpwcleartext') == '1') {
				$params["password"] = $password;
			}
			Database::pexecute($stmt, $params, true, true);
			$popaccountid = Database::lastInsertId();

			// add email address to its destination field
			$result['destination'] .= ' ' . $email_full;
			$stmt = Database::prepare("
				UPDATE `" . TABLE_MAIL_VIRTUAL . "`	SET `destination` = :destination, `popaccountid` = :popaccountid
				WHERE `customerid`= :cid AND `id`= :id
			");
			$params = [
				"destination" => FileDir::makeCorrectDestination($result['destination']),
				"popaccountid" => $popaccountid,
				"cid" => $customer['customerid'],
				"id" => $id
			];
			Database::pexecute($stmt, $params, true, true);

			// update customer usage
			Customers::increaseUsage($customer['customerid'], 'email_accounts_used');
			Customers::increaseUsage($customer['customerid'], 'email_quota_used', '', $quota);

			if ($sendinfomail) {
				// replacer array for mail to create account on server
				$replace_arr = [
					'EMAIL' => $email_full,
					'PASSWORD' => htmlentities(htmlentities($password)),
					'SALUTATION' => User::getCorrectUserSalutation($customer),
					'NAME' => $customer['name'],
					'FIRSTNAME' => $customer['firstname'],
					'COMPANY' => $customer['company'],
					'USERNAME' => $customer['loginname'],
					'CUSTOMER_NO' => $customer['customernumber']
				];

				// get the customers admin
				$stmt = Database::prepare("SELECT `name`, `email` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `adminid`= :adminid");
				$admin = Database::pexecute_first($stmt, [
					"adminid" => $customer['adminid']
				]);

				// get template for mail subject
				$mail_subject = $this->getMailTemplate($customer, 'mails', 'pop_success_subject', $replace_arr, lng('mails.pop_success.subject'));
				// get template for mail body
				$mail_body = $this->getMailTemplate($customer, 'mails', 'pop_success_mailbody', $replace_arr, lng('mails.pop_success.mailbody'));

				$_mailerror = false;
				$mailerr_msg = "";
				try {
					$this->mailer()->setFrom(Settings::Get('panel.adminmail'), User::getCorrectUserSalutation($admin));
					$this->mailer()->clearReplyTos();
					$this->mailer()->addReplyTo($admin['email'], User::getCorrectUserSalutation($admin));
					$this->mailer()->Subject = $mail_subject;
					$this->mailer()->AltBody = $mail_body;
					$this->mailer()->Body = str_replace("\n", "<br />", $mail_body);
					$this->mailer()->addAddress($email_full);
					$this->mailer()->send();
				} catch (\PHPMailer\PHPMailer\Exception $e) {
					$mailerr_msg = $e->errorMessage();
					$_mailerror = true;
				} catch (Exception $e) {
					$mailerr_msg = $e->getMessage();
					$_mailerror = true;
				}

				if ($_mailerror) {
					$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_ERR, "[API] Error sending mail: " . $mailerr_msg);
					Response::standardError('errorsendingmail', $email_full, true);
				}

				$this->mailer()->clearAddresses();

				// customer wants to send the e-mail to an alternative email address too
				if (Settings::Get('panel.sendalternativemail') == 1 && !empty($alternative_email)) {
					// get template for mail subject
					$mail_subject = $this->getMailTemplate($customer, 'mails', 'pop_success_alternative_subject', $replace_arr, lng('mails.pop_success_alternative.subject'));
					// get template for mail body
					$mail_body = $this->getMailTemplate($customer, 'mails', 'pop_success_alternative_mailbody', $replace_arr, lng('mails.pop_success_alternative.mailbody'));

					$_mailerror = false;
					try {
						$this->mailer()->setFrom(Settings::Get('panel.adminmail'), User::getCorrectUserSalutation($admin));
						$this->mailer()->clearReplyTos();
						$this->mailer()->addReplyTo($admin['email'], User::getCorrectUserSalutation($admin));
						$this->mailer()->Subject = $mail_subject;
						$this->mailer()->AltBody = $mail_body;
						$this->mailer()->msgHTML(str_replace("\n", "<br />", $mail_body));
						$this->mailer()->addAddress($idna_convert->encode($alternative_email), User::getCorrectUserSalutation($customer));
						$this->mailer()->send();
					} catch (\PHPMailer\PHPMailer\Exception $e) {
						$mailerr_msg = $e->errorMessage();
						$_mailerror = true;
					} catch (Exception $e) {
						$mailerr_msg = $e->getMessage();
						$_mailerror = true;
					}

					if ($_mailerror) {
						$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_ERR, "[API] Error sending mail: " . $mailerr_msg);
						Response::standardError([
							'errorsendingmail'
						], $alternative_email, true);
					}

					$this->mailer()->clearAddresses();
				}
			}

			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added email account for '" . $result['email_full'] . "'");
			$result = $this->apiCall('Emails.get', [
				'emailaddr' => $result['email_full']
			]);
			return $this->response($result);
		}
		throw new Exception("No more resources available", 406);
	}

	/**
	 * You cannot directly get an email account.
	 * You need to call Emails.get()
	 */
	public function get()
	{
		throw new Exception('You cannot directly get an email account. You need to call Emails.get()', 303);
	}

	/**
	 * update email-account entry for given email-address by either id or email-address
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to update
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param int $email_quota
	 *            optional, update quota
	 * @param string $email_password
	 *            optional, update password
	 * @param bool $deactivated
	 *            optional, admin-only
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');

		if (!empty($emailaddr)) {
			$idna_convert = new IdnaWrapper();
			$emailaddr = $idna_convert->encode($emailaddr);
		}

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		if (empty($result['popaccountid']) || $result['popaccountid'] == 0) {
			throw new Exception("Email address '" . $result['email_full'] . "' has no account assigned.", 406);
		}

		$password = $this->getParam('email_password', true, '');
		$quota = $this->getParam('email_quota', true, $result['quota']);
		$deactivated = $this->getBoolParam('deactivated', true, strtolower($result['postfix']) == 'n');

		// get needed customer info to reduce the email-account-counter by one
		$customer = $this->getCustomerData();

		// validation
		$quota = Validate::validate($quota, 'email_quota', '/^\d+$/', 'vmailquotawrong', [], true);

		$upd_query = "";
		$upd_params = [
			"id" => $result['popaccountid'],
			"cid" => $customer['customerid']
		];
		if (!empty($password)) {
			if ($password == $result['email_full']) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			}
			$password = Crypt::validatePassword($password, true);
			// prefix hash-algo
			switch (Settings::Get('system.passwordcryptfunc')) {
				case 'argon2i':
					$cpPrefix = '{ARGON2I}';
					break;
				case 'argon2id':
					$cpPrefix = '{ARGON2ID}';
					break;
				default:
					$cpPrefix = '{BLF-CRYPT}';
					break;
			}
			// encrypt the password
			$cryptPassword = $cpPrefix . Crypt::makeCryptPassword($password);
			$upd_query .= (Settings::Get('system.mailpwcleartext') == '1' ? "`password` = :password, " : '') . "`password_enc`= :password_enc";
			$upd_params['password_enc'] = $cryptPassword;
			if (Settings::Get('system.mailpwcleartext') == '1') {
				$upd_params['password'] = $password;
			}
		}

		if (Settings::Get('system.mail_quota_enabled') == 1) {
			if ($quota != $result['quota']) {
				if ($customer['email_quota'] != '-1' && ($quota == 0 || ($quota + $customer['email_quota_used'] - $result['quota']) > $customer['email_quota'])) {
					Response::standardError('allocatetoomuchquota', $quota, true);
				}
				if (!empty($upd_query)) {
					$upd_query .= ", ";
				}
				$upd_query .= "`quota` = :quota";
				$upd_params['quota'] = $quota;
			}
		} else {
			// disable
			$quota = 0;
		}

		if ($this->isAdmin()) {
			if (($deactivated == true && strtolower($result['postfix']) == 'y') || ($deactivated == false && strtolower($result['postfix']) == 'n')) {
				if (!empty($upd_query)) {
					$upd_query .= ", ";
				}
				$upd_query .= "`postfix` = :postfix, `imap` = :imap, `pop3` = :pop3";
				$upd_params['postfix'] = $deactivated ? 'N' : 'Y';
				$upd_params['imap'] = $deactivated ? '0' : '1';
				$upd_params['pop3'] = $deactivated ? '0' : '1';
			}
		}

		// build update query
		if (!empty($upd_query)) {
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_MAIL_USERS . "` SET " . $upd_query . " WHERE `id` = :id AND `customerid`= :cid
			");
			Database::pexecute($upd_stmt, $upd_params, true, true);
		}

		if ($customer['email_quota'] != '-1') {
			Customers::increaseUsage($customer['customerid'], 'email_quota_used', '', ($quota - $result['quota']));
			Admins::increaseUsage($customer['adminid'], 'email_quota_used', '', ($quota - $result['quota']));
		}

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated email account '" . $result['email_full'] . "'");
		$result = $this->apiCall('Emails.get', [
			'emailaddr' => $result['email_full']
		]);
		return $this->response($result);
	}

	/**
	 * You cannot directly list email accounts.
	 * You need to call Emails.listing()
	 */
	public function listing()
	{
		throw new Exception('You cannot directly list email accounts. You need to call Emails.listing()', 303);
	}

	/**
	 * You cannot directly count email accounts.
	 * You need to call Emails.listingCount()
	 */
	public function listingCount()
	{
		throw new Exception('You cannot directly count email accounts. You need to call Emails.listingCount()', 303);
	}

	/**
	 * delete email-account entry for given email-address by either id or email-address
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to delete the account for
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param bool $delete_userfiles
	 *            optional, default false
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');
		$delete_userfiles = $this->getBoolParam('delete_userfiles', true, 0);

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		], true);
		$id = $result['id'];

		if (empty($result['popaccountid']) || $result['popaccountid'] == 0) {
			throw new Exception("Email address '" . $result['email_full'] . "' has no account assigned.", 406);
		}

		// get needed customer info to reduce the email-account-counter by one
		$customer = $this->getCustomerData();

		// delete entry
		$stmt = Database::prepare("
			DELETE FROM `" . TABLE_MAIL_USERS . "` WHERE `customerid`= :cid AND `id`= :id
		");
		Database::pexecute($stmt, [
			"cid" => $customer['customerid'],
			"id" => $result['popaccountid']
		], true, true);

		// update mail-virtual entry
		$result['destination'] = str_replace($result['email_full'], '', $result['destination']);

		$stmt = Database::prepare("
			UPDATE `" . TABLE_MAIL_VIRTUAL . "` SET `destination` = :dest, `popaccountid` = '0' WHERE `customerid`= :cid AND `id`= :id
		");
		$params = [
			"dest" => FileDir::makeCorrectDestination($result['destination']),
			"cid" => $customer['customerid'],
			"id" => $id
		];
		Database::pexecute($stmt, $params, true, true);
		$result['popaccountid'] = 0;

		if (Settings::Get('system.mail_quota_enabled') == '1' && $customer['email_quota'] != '-1') {
			$quota = (int)$result['quota'];
		} else {
			$quota = 0;
		}

		if ($delete_userfiles) {
			Cronjob::inserttask(TaskId::DELETE_EMAIL_DATA, $customer['loginname'], FileDir::makeCorrectDir($result['homedir'] . '/' . $result['maildir']));
		}

		// decrease usage for customer
		Customers::decreaseUsage($customer['customerid'], 'email_accounts_used');
		Customers::decreaseUsage($customer['customerid'], 'email_quota_used', '', $quota);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_WARNING, "[API] deleted email account for '" . $result['email_full'] . "'");
		return $this->response($result);
	}
}
