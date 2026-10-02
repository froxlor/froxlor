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
use Froxlor\CurrentUser;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;

/**
 * @since 2.3.0
 */
class EmailSender extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new sender email address for a given email-address either by id or emailaddr
	 *
	 * @param int $id
	 *            optional id of email-address to add the allowed sender for (must have an account)
	 * @param string $emailaddr
	 *            optional address of email-address to add the allowed sender for (must have an account)
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param string $allowed_sender
	 *            required email-address or @domain.tld notation (wildcard) of allowed sender entry for the given account
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{

		if (Settings::Get('mail.enable_allow_sender') != '1') {
			throw new Exception("Allowed-sender not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');
		$allowed_sender = strtolower($this->getParam('allowed_sender'));

		// validation
		$idna_convert = new IdnaWrapper();
		if (!empty($emailaddr)) {
			$emailaddr = $idna_convert->encode($emailaddr);
		}

		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		if (empty($result['popaccountid'])) {
			Response::standardError('emailhasnoaccount', $result['email_full'], true);
		}

		if (substr($allowed_sender, 0, 1) != '@') {
			if (!Validate::validateEmail($idna_convert->encode($allowed_sender))) {
				Response::standardError('emailiswrong', $allowed_sender, true);
			}
			self::validateLocalDomainOwnership(explode("@", $allowed_sender)[1] ?? "");
		} else {
			if (!Validate::validateDomain($idna_convert->encode(substr($allowed_sender, 1)))) {
				Response::standardError('wildcardemailiswrong', substr($allowed_sender, 1), true);
			}
			self::validateLocalDomainOwnership(substr($allowed_sender, 1));
		}

		// get needed customer info
		$customer = $this->getCustomerData();

		// check whether account exists and if it belongs to the customer
		$sel_stmt = Database::prepare("
			SELECT `username`
			FROM `" . TABLE_MAIL_USERS . "`
			WHERE `id` = :id
			AND `customerid` = :cid
		");
		$emailaccount = Database::pexecute_first($sel_stmt, [
			'id' => (int)$result['popaccountid'],
			'cid' => (int)$customer['customerid']
		]);
		if ($emailaccount && !empty($emailaccount['username'])) {
			// insert email sender
			$ins_stmt = Database::prepare("
				INSERT IGNORE INTO `" . TABLE_MAIL_SENDER_ALIAS . "` SET
				`email` = :email,
				`allowed_sender` = :allowed_sender
			");
			$result = [
				'email' => $emailaccount['username'],
				'allowed_sender' => $allowed_sender
			];
			Database::pexecute($ins_stmt, $result);
			$result['id'] = Database::lastInsertId();

			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] added email-sender alias '" . $result['email'] . "' for account '" . $result['allowed_sender'] . "'");
			return $this->response($result);
		}
		throw new Exception("Email account for email-address " . $result['email_full'] . " could not be found", 404);
	}

	/**
	 * You cannot update an email sender alias.
	 * You need to delete the entry and create a new one.
	 */
	public function update()
	{
		throw new Exception('You cannot update an email sender alias. You need to delete the entry and create a new one.', 303);
	}

	/**
	 * You cannot directly get an email sender alias.
	 * Try EmailSender.listing()
	 */
	public function get()
	{
		throw new Exception('You cannot directly get an email sender alias. Try EmailSender.listing()', 303);
	}

	/**
	 * List email senders for a given email address
	 *
	 * @param int $id
	 *            optional, the id of the email-address to list allowed senders from
	 * @param string $emailaddr
	 *            optional, the email-address to list allowed senders from
	 * @param int $customerid
	 *            optional, admin-only, the customer-id
	 * @param string $loginname
	 *            optional, admin-only, the loginname
	 *
	 * @access admin,customer
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		if (Settings::Get('mail.enable_allow_sender') != '1') {
			throw new Exception("Allowed-sender not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		if (empty($result['popaccountid'])) {
			return $this->response([
				'count' => 0,
				'list' => []
			]);
		} else {
			$sel_stmt = Database::prepare("
				SELECT s.*
				FROM `" . TABLE_MAIL_SENDER_ALIAS . "` s
				LEFT JOIN `" . TABLE_MAIL_USERS . "` u ON u.username = s.email
				WHERE u.id = :popaccountid AND u.customerid = :cid
			");
			Database::pexecute($sel_stmt, ['popaccountid' => (int)$result['popaccountid'], 'cid' => $result['customerid']]);
			$senders = [];
			while ($row = $sel_stmt->fetch(\PDO::FETCH_ASSOC)) {
				$senders[] = $row;
			}
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list email-senders for '" . $result['email_full'] . "'");
			return $this->response([
				'count' => count($senders),
				'list' => $senders
			]);
		}
	}

	/**
	 * returns the total number of allowed sender addresses for a given email address
	 *
	 * @param int $id
	 * 			optional, the id of the email-address to list allowed senders from
	 * @param string $emailaddr
	 * 			optional, the email-address to list allowed senders from
	 * @param int $customerid
	 * 			optional, admin-only, the customer-id
	 * @param string $loginname
	 * 			optional, admin-only, the loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if (Settings::Get('mail.enable_allow_sender') != '1') {
			throw new Exception("Allowed-sender not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		if (empty($result['popaccountid'])) {
			return $this->response(0);
		} else {
			$sel_stmt = Database::prepare("
				SELECT COUNT(*) as cnt
				FROM `" . TABLE_MAIL_SENDER_ALIAS . "` s
				LEFT JOIN `" . TABLE_MAIL_USERS . "` u ON u.username = s.email
				WHERE u.id = :popaccountid AND u.customerid = :cid
			");
			$sender_cnt = Database::pexecute_first($sel_stmt, ['popaccountid' => (int)$result['popaccountid'], 'cid' => $result['customerid']]);

			return $this->response($sender_cnt['cnt']);
		}
	}

	/**
	 * delete email-sender entry for given email-address by either id or email-address and sender-id
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to delete the forwarder from
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param int $senderid
	 *            id of the sender to delete
	 *
	 * @access admin,customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if (Settings::Get('mail.enable_allow_sender') != '1') {
			throw new Exception("Allowed-sender not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');
		$senderid = $this->getParam('senderid');

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		if (!empty($result['popaccountid'])) {
			// get needed customer info
			$customer = $this->getCustomerData();

			$sel_stmt = Database::prepare("
				SELECT s.id
				FROM `" . TABLE_MAIL_SENDER_ALIAS . "` s
				LEFT JOIN `" . TABLE_MAIL_USERS . "` u ON u.username = s.email
				WHERE u.id = :popaccountid AND u.customerid = :cid AND s.id = :senderid
			");
			$sender_result = Database::pexecute_first($sel_stmt, [
				'popaccountid' => (int)$result['popaccountid'],
				'cid' => $customer['customerid'],
				'senderid' => $senderid
			]);
			if ($sender_result && $sender_result['id'] == $senderid) {
				$del_stmt = Database::prepare("DELETE FROM `" . TABLE_MAIL_SENDER_ALIAS . "` WHERE `id` = :senderid");
				Database::pexecute($del_stmt, ['senderid' => $senderid]);

				$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] deleted email sender for '" . $result['email_full'] . "'");
				$result = $this->apiCall('Emails.get', [
					'emailaddr' => $result['email_full']
				]);
				return $this->response($result);
			}
		}
		throw new Exception("Unknown sender id", 404);
	}

	private static function validateLocalDomainOwnership(string $domain): void
	{
		// check whether the used domain belongs to the customer if it's a domain on this system
		$sel_stmt = Database::prepare("SELECT customerid FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `domain` = :domain");
		$domain_result = Database::pexecute_first($sel_stmt, ['domain' => $domain]);
		if ($domain_result && $domain_result['customerid'] != CurrentUser::getField('customerid')) {
			// domain exists in our system but not owned by current user
			Response::standardError('senderdomainnotowned', $domain, true);
		}
		elseif (!$domain_result && Settings::Get('mail.allow_external_domains') != '1') {
			// domain is not known to the system, assuming external, and external is not allowed
			Response::standardError('senderdomainexternal', $domain, true);
		}
	}
}
