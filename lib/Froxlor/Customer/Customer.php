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

namespace Froxlor\Customer;

use Froxlor\Database\Database;
use PDO;

class Customer
{

	/**
	 * Get value of a specific field from a given customer
	 *
	 * @param int $customerid
	 * @param string $varname
	 * @return false|mixed
	 * @throws \Exception
	 */
	public static function getCustomerDetail(int $customerid, string $varname)
	{
		$customer_stmt = Database::prepare("
			SELECT `" . $varname . "` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `customerid` = :customerid
		");
		$customer = Database::pexecute_first($customer_stmt, [
			'customerid' => $customerid
		]);

		if (isset($customer[$varname])) {
			return $customer[$varname];
		}
		return false;
	}

	/**
	 * returns the loginname of a customer by given uid
	 *
	 * @param int $uid uid of customer
	 *
	 * @return string customers loginname
	 * @throws \Exception
	 */
	public static function getLoginNameByUid(int $uid)
	{
		$result_stmt = Database::prepare("
			SELECT `loginname` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `guid` = :guid
		");
		$result = Database::pexecute_first($result_stmt, [
			'guid' => $uid
		]);

		if ($result && isset($result['loginname'])) {
			return $result['loginname'];
		}
		return false;
	}

	/**
	 * Function customerHasPerlEnabled
	 *
	 * returns true or false whether perl is
	 * enabled for the given customer
	 *
	 * @param int $cid customer-id
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public static function customerHasPerlEnabled(int $cid = 0)
	{
		if ($cid > 0) {
			$result_stmt = Database::prepare("
				SELECT `perlenabled` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `customerid` = :cid");
			$result = Database::pexecute_first($result_stmt, [
				'cid' => $cid
			]);

			if ($result && isset($result['perlenabled'])) {
				return (bool)$result['perlenabled'];
			}
		}
		return false;
	}
}
