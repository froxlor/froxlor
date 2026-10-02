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

namespace Froxlor;

use Froxlor\Database\Database;
use PDO;

class User
{
	/**
	 * Returns full style user details "Name, Firstname | Company"
	 *
	 * @param array An array with keys firstname, name and company
	 * @return string The full details
	 *
	 * @author Florian Lippert <flo@syscp.org> (2003-2009)
	 */
	public static function getCorrectFullUserDetails($userinfo, $html = false): string
	{
		$returnval = '';

		if (isset($userinfo['firstname']) && isset($userinfo['name']) && isset($userinfo['company'])) {
			if ($userinfo['company'] == '') {
				$returnval = $userinfo['name'] . ', ' . $userinfo['firstname'];
			} else {
				if ($userinfo['name'] != '' && $userinfo['firstname'] != '') {
					if ($html) {
						$returnval = $userinfo['name'] . ', ' . $userinfo['firstname'] . '<br><small>' . $userinfo['company'] . '</small>';
					} else {
						$returnval = $userinfo['name'] . ', ' . $userinfo['firstname'] . ', ' . $userinfo['company'];
					}
				} else {
					$returnval = $userinfo['company'];
				}
			}
		} elseif (isset($userinfo['name'])) {
			$returnval = $userinfo['name'];
		}

		return $returnval;
	}

	/**
	 * Returns correct user salutation, either "Firstname Name" or "Company"
	 *
	 * @param array An array with keys firstname, name and company
	 * @return string The correct salutation
	 *
	 * @author Florian Lippert <flo@syscp.org> (2003-2009)
	 */
	public static function getCorrectUserSalutation($userinfo)
	{
		$returnval = '';

		if (isset($userinfo['firstname']) && isset($userinfo['name']) && isset($userinfo['company'])) {
			// Always prefer firstname name

			if ($userinfo['company'] != '' && $userinfo['name'] == '' && $userinfo['firstname'] == '') {
				$returnval = $userinfo['company'];
			} else {
				$returnval = $userinfo['firstname'] . ' ' . $userinfo['name'];
			}
		}

		return $returnval;
	}

	/**
	 * Function which updates all counters of used resources in panel_admins and panel_customers
	 *
	 * @param bool $returndebuginfo Set to true to get an array with debug information
	 * @return array Contains debug information if parameter 'returndebuginfo' is set to true
	 *
	 * @author Florian Lippert <flo@syscp.org> (2003-2009)
	 * @author Froxlor team <team@froxlor.org> (2010-)
	 */
	public static function updateCounters($returndebuginfo = false)
	{
		$returnval = [];

		if ($returndebuginfo === true) {
			$returnval = [
				'admins' => [],
				'customers' => []
			];
		}

		// Customers
		$customers_stmt = Database::prepare('SELECT * FROM `' . TABLE_PANEL_CUSTOMERS . '` ORDER BY `customerid`');
		Database::pexecute($customers_stmt);
		// array to store currently used resources per admin
		$admin_resources = [];
		while ($customer = $customers_stmt->fetch(PDO::FETCH_ASSOC)) {
			// set current admin
			$cur_adm = $customer['adminid'];
			// initialize admin-resources array for admin $customer['adminid']
			if (!isset($admin_resources[$cur_adm])) {
				$admin_resources[$cur_adm] = [];
			}

			// fill admin resource usage array with customer data
			self::addResourceCountEx($admin_resources[$cur_adm], $customer, 'diskspace_used', 'diskspace');
			self::addResourceCountEx($admin_resources[$cur_adm], $customer, 'traffic_used', 'traffic_used'); // !!! yes, USED and USED

			foreach ([
				'mysqls',
				'ftps',
				'emails',
				'email_accounts',
				'email_forwarders',
				'email_quota',
				'subdomains'
			] as $field) {
				self::addResourceCount($admin_resources[$cur_adm], $customer, $field . '_used', $field);
			}

			// calculate real usage
			$customer_mysqls_stmt = Database::prepare('SELECT COUNT(*) AS `number_mysqls` FROM `' . TABLE_PANEL_DATABASES . '`
			WHERE `customerid` = :cid');
			$customer_mysqls = Database::pexecute_first($customer_mysqls_stmt, [
				"cid" => $customer['customerid']
			]);
			$customer['mysqls_used_new'] = (int)$customer_mysqls['number_mysqls'];

			$customer_emails_stmt = Database::prepare('SELECT COUNT(*) AS `number_emails` FROM `' . TABLE_MAIL_VIRTUAL . '`
			WHERE `customerid` = :cid');
			$customer_emails = Database::pexecute_first($customer_emails_stmt, [
				"cid" => $customer['customerid']
			]);
			$customer['emails_used_new'] = (int)$customer_emails['number_emails'];

			$customer_emails_result_stmt = Database::prepare('SELECT `email`, `email_full`, `destination`, `popaccountid` FROM `' . TABLE_MAIL_VIRTUAL . '`
			WHERE `customerid` = :cid');
			Database::pexecute($customer_emails_result_stmt, [
				"cid" => $customer['customerid']
			]);
			$customer_email_forwarders = 0;
			$customer_email_accounts = 0;

			while ($customer_emails_row = $customer_emails_result_stmt->fetch(PDO::FETCH_ASSOC)) {
				if ($customer_emails_row['destination'] != '') {
					$customer_emails_row['destination'] = explode(' ', FileDir::makeCorrectDestination($customer_emails_row['destination']));
					$customer_email_forwarders += count($customer_emails_row['destination']);

					if (in_array($customer_emails_row['email_full'], $customer_emails_row['destination'])) {
						$customer_email_forwarders -= 1;
						$customer_email_accounts++;
					}
				}
			}

			$customer['email_accounts_used_new'] = $customer_email_accounts;
			$customer['email_forwarders_used_new'] = $customer_email_forwarders;

			$customer_ftps_stmt = Database::prepare('SELECT COUNT(*) AS `number_ftps` FROM `' . TABLE_FTP_USERS . '` WHERE `customerid` = :cid');
			$customer_ftps = Database::pexecute_first($customer_ftps_stmt, [
				"cid" => $customer['customerid']
			]);
			$customer['ftps_used_new'] = ((int)$customer_ftps['number_ftps'] - 1);

			$customer_subdomains_stmt = Database::prepare('SELECT COUNT(*) AS `number_subdomains` FROM `' . TABLE_PANEL_DOMAINS . '` WHERE `customerid` = :cid AND `parentdomainid` <> "0"');
			$customer_subdomains = Database::pexecute_first($customer_subdomains_stmt, [
				"cid" => $customer['customerid']
			]);
			$customer['subdomains_used_new'] = (int)$customer_subdomains['number_subdomains'];

			$customer_email_quota_stmt = Database::prepare('SELECT SUM(`quota`) AS `email_quota` FROM `' . TABLE_MAIL_USERS . '` WHERE `customerid` = :cid');
			$customer_email_quota = Database::pexecute_first($customer_email_quota_stmt, [
				"cid" => $customer['customerid']
			]);
			$customer['email_quota_used_new'] = (int)$customer_email_quota['email_quota'];

			// update database accordingly
			$stmt = Database::prepare('UPDATE `' . TABLE_PANEL_CUSTOMERS . '`
			SET `mysqls_used` = :mysqls_used,
				`emails_used` = :emails_used,
				`email_accounts_used` = :email_accounts_used,
				`email_forwarders_used` = :email_forwarders_used,
				`email_quota_used` = :email_quota_used,
				`ftps_used` = :ftps_used,
				`subdomains_used` = :subdomains_used
			WHERE `customerid` = :cid');
			$params = [
				"mysqls_used" => $customer['mysqls_used_new'],
				"emails_used" => $customer['emails_used_new'],
				"email_accounts_used" => $customer['email_accounts_used_new'],
				"email_forwarders_used" => $customer['email_forwarders_used_new'],
				"email_quota_used" => $customer['email_quota_used_new'],
				"ftps_used" => $customer['ftps_used_new'],
				"subdomains_used" => $customer['subdomains_used_new'],
				"cid" => $customer['customerid']
			];
			Database::pexecute($stmt, $params);

			if ($returndebuginfo === true) {
				$returnval['customers'][$customer['customerid']] = $customer;
			}
		}

		// Admins
		$admins_stmt = Database::prepare('SELECT * FROM `' . TABLE_PANEL_ADMINS . '` ORDER BY `adminid`');
		Database::pexecute($admins_stmt, []);

		$resource_fields = [
			'diskspace_used',
			'traffic_used',
			'mysqls_used',
			'ftps_used',
			'emails_used',
			'email_accounts_used',
			'email_forwarders_used',
			'email_quota_used',
			'subdomains_used'
		];

		$admin_customers_stmt = Database::prepare('SELECT * FROM `' . TABLE_PANEL_CUSTOMERS . '` WHERE `adminid` = :aid');
		while ($admin = $admins_stmt->fetch(PDO::FETCH_ASSOC)) {
			Database::pexecute($admin_customers_stmt, [
				"aid" => $admin['adminid']
			]);
			$admin_customers = $admin_customers_stmt->fetchAll(PDO::FETCH_ASSOC);
			$admin['customers_used_new'] = count($admin_customers);

			$admin_domains_stmt = Database::prepare('SELECT COUNT(*) AS `number_domains` FROM `' . TABLE_PANEL_DOMAINS . '` WHERE `adminid` = :aid AND `parentdomainid` = "0"');
			$admin_domains = Database::pexecute_first($admin_domains_stmt, [
				"aid" => $admin['adminid']
			]);
			// subtract the amount of domains that are std-subdomains later when we iterated through all customers and know for sure
			$admin['domains_used_new'] = $admin_domains['number_domains'];
			// set current admin
			$cur_adm = $admin['adminid'];
			// if there's an admin without any customers it might be possible that the id is not yet known in $admin_resources
			if (!isset($admin_resources[$cur_adm])) {
				$admin_resources[$cur_adm] = [];
			}
			// be sure that all fields are set in the array
			foreach ($resource_fields as $field) {
				self::initArrField($field, $admin_resources[$cur_adm], 0);
				// initialize new values
				$admin[$field . '_new'] = 0;
			}
			// now get the customer resource usage which we have re-calculated previously
			foreach ($admin_customers as $acustomer) {
				foreach ($resource_fields as $field) {
					if ($field == 'diskspace_used') {
						// admin/reseller-usage == what has been assign to the customer
						if (($acustomer['diskspace'] / 1024) != -1) {
							$admin[$field . '_new'] += $acustomer['diskspace'];
						}
					} else if ($field != 'traffic_used') {
						if ($acustomer[str_replace("_used", "", $field)] != '-1') {
							$admin[$field . '_new'] += $acustomer[str_replace("_used", "", $field)];
						}
					} else {
						// traffic is always the current usage, not the assigned value
						$admin[$field . '_new'] += $acustomer[$field];
					}
				}
				// check for std-subdomain
				if ($acustomer['standardsubdomain'] > 0) {
					// std-subdomain does not count as assigned resource
					$admin['domains_used_new']--;
				}
			}
			// update database entry accordingly
			$stmt = Database::prepare('UPDATE `' . TABLE_PANEL_ADMINS . '`
			SET `customers_used` = :customers_used,
				`domains_used` = :domains_used,
				`diskspace_used` = :diskspace_used,
				`mysqls_used` = :mysqls_used,
				`emails_used` = :emails_used,
				`email_accounts_used` = :email_accounts_used,
				`email_forwarders_used` = :email_forwarders_used,
				`email_quota_used` = :email_quota_used,
				`ftps_used` = :ftps_used,
				`subdomains_used` = :subdomains_used,
				`traffic_used` = :traffic_used
			WHERE `adminid` = :aid');

			$params = [
				"customers_used" => $admin['customers_used_new'],
				"domains_used" => $admin['domains_used_new'],
				"diskspace_used" => $admin['diskspace_used_new'],
				"mysqls_used" => $admin['mysqls_used_new'],
				"emails_used" => $admin['emails_used_new'],
				"email_accounts_used" => $admin['email_accounts_used_new'],
				"email_forwarders_used" => $admin['email_forwarders_used_new'],
				"email_quota_used" => $admin['email_quota_used_new'],
				"ftps_used" => $admin['ftps_used_new'],
				"subdomains_used" => $admin['subdomains_used_new'],
				"traffic_used" => $admin['traffic_used_new'],
				"aid" => $admin['adminid']
			];
			Database::pexecute($stmt, $params);

			if ($returndebuginfo === true) {
				$returnval['admins'][$admin['adminid']] = $admin;
			}
		}

		return $returnval;
	}

	/**
	 * if the customer does not have unlimited resources, add the used resources
	 * to the admin-resource-counter
	 * Special function wrapper for diskspace and traffic as they need to
	 * be calculated otherwise to get the -1 for unlimited
	 *
	 * @param array $arr reference
	 * @param array $customer_arr
	 * @param string $used_field
	 * @param string $field
	 *
	 * @return void
	 */
	private static function addResourceCountEx(&$arr, $customer_arr, $used_field = null, $field = null)
	{
		self::initArrField($used_field, $arr, 0);
		if ($field == 'diskspace' && ($customer_arr[$field] / 1024) != '-1') {
			$arr[$used_field] += intval($customer_arr[$field]);
		} elseif ($field == 'traffic_used') {
			// no check for -1 here because we don't want the assigned traffic for admins/resellers but
			// the actually used (for stats reasons)
			$arr[$used_field] += intval($customer_arr[$field]);
		}
	}

	/**
	 * initialize a field-value of an array if not yet initialized
	 *
	 * @param string $field
	 * @param array $arr reference
	 * @param int $init_value
	 *
	 * @return void
	 */
	private static function initArrField($field = null, &$arr = [], $init_value = 0)
	{
		if (!isset($arr[$field])) {
			$arr[$field] = $init_value;
		}
	}

	/**
	 * if the customer does not have unlimited resources, add the used resources
	 * to the admin-resource-counter
	 *
	 * @param array $arr reference
	 * @param array $customer_arr
	 * @param string $used_field
	 * @param string $field
	 *
	 * @return void
	 */
	private static function addResourceCount(&$arr, $customer_arr, $used_field = null, $field = null)
	{
		self::initArrField($used_field, $arr, 0);
		if ($customer_arr[$field] != '-1') {
			$arr[$used_field] += intval($customer_arr[$used_field]);
		}
	}
}
