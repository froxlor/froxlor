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
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use PDO;

/**
 * @since 0.10.0
 */
class Traffic extends ApiCommand implements ResourceEntity
{

	/**
	 * You cannot add traffic data
	 *
	 * @throws Exception
	 */
	public function add()
	{
		throw new Exception('You cannot add traffic data', 303);
	}

	/**
	 * to get specific traffic details use year, month and/or day parameter for Traffic.listing()
	 *
	 * @throws Exception
	 */
	public function get()
	{
		throw new Exception('To get specific traffic details use year, month and/or day parameter for Traffic.listing()', 303);
	}

	/**
	 * You cannot update traffic data
	 *
	 * @throws Exception
	 */
	public function update()
	{
		throw new Exception('You cannot update traffic data', 303);
	}

	/**
	 * list traffic information
	 *
	 * @param int $year
	 *            optional, default empty
	 * @param int $month
	 *            optional, default empty
	 * @param int $day
	 *            optional, default empty
	 * @param int $date_from
	 *            optional timestamp, default empty, if specified, $year, $month and $day will be ignored
	 * @param int $date_until
	 *            optional timestamp, default empty, if specified, $year, $month and $day will be ignored
	 * @param bool $customer_traffic
	 *            optional, admin-only, whether to output ones own traffic or all of ones customers, default is 0
	 *            (false)
	 * @param int $customerid
	 *            optional, admin-only, select traffic of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select traffic of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		$year = $this->getParam('year', true, "");
		$month = $this->getParam('month', true, "");
		$day = $this->getParam('day', true, "");
		$date_from = $this->getParam('date_from', true, -1);
		$date_until = $this->getParam('date_until', true, -1);
		$customer_traffic = $this->getBoolParam('customer_traffic', true, 0);
		$customer_ids = $this->getAllowedCustomerIds();
		$result = [];
		$params = [];

		// validate parameters
		if ($date_from >= 0 || $date_until >= 0) {
			$year = "";
			$month = "";
			$day = "";
			if ($date_from == $date_until) {
				$date_until = -1;
			}
			if ($date_from >= 0 && $date_until >= 0 && $date_until < $date_from) {
				// switch
				$temp_ts = $date_from;
				$date_from = $date_until;
				$date_until = $temp_ts;
			}
		}

		// check for year/month/day
		$where_str = "";
		if (!empty($year) && is_numeric($year)) {
			$where_str .= " AND `year` = :year";
			$params['year'] = $year;
		}
		if (!empty($month) && is_numeric($month)) {
			$where_str .= " AND `month` = :month";
			$params['month'] = $month;
		}
		if (!empty($day) && is_numeric($day)) {
			$where_str .= " AND `day` = :day";
			$params['day'] = $day;
		}
		if ($date_from >= 0 && $date_until >= 0) {
			$where_str .= " AND `stamp` BETWEEN :df AND :du";
			$params['df'] = $date_from;
			$params['du'] = $date_until;
		} elseif ($date_from >= 0 && $date_until < 0) {
			$where_str .= " AND `stamp` > :df";
			$params['df'] = $date_from;
		} elseif ($date_from < 0 && $date_until >= 0) {
			$where_str .= " AND `stamp` < :du";
			$params['du'] = $date_until;
		}

		if (!$this->isAdmin() || ($this->isAdmin() && $customer_traffic)) {
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_TRAFFIC . "`
				WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")" . $where_str);
		} else {
			$params['adminid'] = $this->getUserDetail('adminid');
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_TRAFFIC_ADMINS . "`
				WHERE `adminid` = :adminid" . $where_str);
		}
		Database::pexecute($result_stmt, $params, true, true);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			// make Bytes from KB
			$row['http'] *= 1024;
			$row['ftp_up'] *= 1024;
			$row['ftp_down'] *= 1024;
			$row['mail'] *= 1024;
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list traffic");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * You cannot count the traffic data list
	 *
	 * @throws Exception
	 */
	public function listingCount()
	{
		throw new Exception('You cannot count the traffic data list', 303);
	}

	/**
	 * You cannot delete traffic data
	 *
	 * @throws Exception
	 */
	public function delete()
	{
		throw new Exception('You cannot delete traffic data', 303);
	}
}
