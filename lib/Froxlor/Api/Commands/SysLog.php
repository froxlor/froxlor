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
 * @since 0.10.6
 */
class SysLog extends ApiCommand implements ResourceEntity
{

	/**
	 * list all log-entries
	 *
	 * @param array $sql_search
	 *            optional array with index = fieldname, and value = array with 'op' => operator (one of <, > or =),
	 *            LIKE is used if left empty and 'value' => searchvalue
	 * @param int $sql_limit
	 *            optional specify number of results to be returned
	 * @param int $sql_offset
	 *            optional specify offset for resultset
	 * @param array $sql_orderby
	 *            optional array with index = fieldname and value = ASC|DESC to order the resultset by one or more
	 *            fields
	 *
	 * @access admin, customer
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		$result = [];
		$query_fields = [];
		if ($this->isAdmin() && $this->getUserDetail('customers_see_all') == '1') {
			$result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_LOG . "` " . $this->getSearchWhere($query_fields) . $this->getOrderBy() . $this->getLimit());
		} elseif ($this->isAdmin()) {
			// get all admin customers
			$_custom_list_result = $this->apiCall('Customers.listing');
			$custom_list_result = $_custom_list_result['list'];
			$customer_names = [];
			foreach ($custom_list_result as $customer) {
				$customer_names[] = $customer['loginname'];
			}
			if (count($customer_names) > 0) {
				$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_LOG . "`
				WHERE `user` = :loginname OR `user` IN ('" . implode("', '", $customer_names) . "')" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
			} else {
				$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_LOG . "`
				WHERE `user` = :loginname" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
			}
			$query_fields['loginname'] = $this->getUserDetail('loginname');
		} else {
			// every one else just sees their logs
			$result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_LOG . "`
			WHERE `user` = :loginname AND `action` <> 99 " . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
			$query_fields['loginname'] = $this->getUserDetail('loginname');
		}
		Database::pexecute($result_stmt, $query_fields, true, true);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			// clean log-text
			$row['text'] = preg_replace("/[^\w @#\"':.,()\[\]+\-_\/\\\!]/i", "_", $row['text']);
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list log-entries");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of log-entries
	 *
	 * @access admin
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		$params = [];
		$query_fields = [];
		if ($this->isAdmin() && $this->getUserDetail('customers_see_all') == '1') {
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_logs FROM `" . TABLE_PANEL_LOG . "`
			" . $this->getSearchWhere($query_fields));
		} elseif ($this->isAdmin()) {
			// get all admin customers
			$_custom_list_result = $this->apiCall('Customers.listing');
			$custom_list_result = $_custom_list_result['list'];
			$customer_names = [];
			foreach ($custom_list_result as $customer) {
				$customer_names[] = $customer['loginname'];
			}
			if (count($customer_names) > 0) {
				$result_stmt = Database::prepare("
					SELECT COUNT(*) as num_logs FROM `" . TABLE_PANEL_LOG . "`
					WHERE `user` = :loginname OR `user` IN ('" . implode("', '", $customer_names) . "')
				" . $this->getSearchWhere($query_fields, true));
			} else {
				$result_stmt = Database::prepare("
					SELECT COUNT(*) as num_logs FROM `" . TABLE_PANEL_LOG . "`
					WHERE `user` = :loginname
				" . $this->getSearchWhere($query_fields, true));
			}
			$params = [
				'loginname' => $this->getUserDetail('loginname')
			];
		} else {
			// every one else just sees their logs
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_logs FROM `" . TABLE_PANEL_LOG . "`
				WHERE `user` = :loginname AND `action` <> 99
			" . $this->getSearchWhere($query_fields, true));
			$params = [
				'loginname' => $this->getUserDetail('loginname')
			];
		}
		$params = array_merge($params, $query_fields);
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			return $this->response($result['num_logs']);
		}
		return $this->response(0);
	}

	/**
	 * You cannot get log entries
	 */
	public function get()
	{
		throw new Exception('You cannot get log entries', 303);
	}

	/**
	 * You cannot add log entries
	 */
	public function add()
	{
		throw new Exception('You cannot add log entries', 303);
	}

	/**
	 * You cannot update log entries
	 */
	public function update()
	{
		throw new Exception('You cannot update log entries', 303);
	}

	/**
	 * delete log entries
	 *
	 * @param int $min_to_keep
	 *            optional minutes to keep, default is 10
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin()) {
			$min_to_keep = self::getParam('min_to_keep', true, 10);
			if ($min_to_keep < 0) {
				$min_to_keep = 0;
			}
			$truncatedate = time() - (60 * $min_to_keep);
			$params = [];
			if ($this->getUserDetail('customers_see_all') == '1') {
				$result_stmt = Database::prepare("
					DELETE FROM `" . TABLE_PANEL_LOG . "` WHERE `date` < :trunc
				");
			} else {
				// get all admin customers
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
				$customer_names = [];
				foreach ($custom_list_result as $customer) {
					$customer_names[] = $customer['loginname'];
				}
				if (count($customer_names) > 0) {
					$result_stmt = Database::prepare("
						DELETE FROM `" . TABLE_PANEL_LOG . "` WHERE `date` < :trunc AND `user` = :loginname OR `user` IN ('" . implode("', '", $customer_names) . "')
					");
				} else {
					$result_stmt = Database::prepare("
						DELETE FROM `" . TABLE_PANEL_LOG . "` WHERE `date` < :trunc AND `user` = :loginname
					");
				}
				$params = [
					'loginname' => $this->getUserDetail('loginname')
				];
			}
			$params['trunc'] = $truncatedate;
			Database::pexecute($result_stmt, $params, true, true);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] truncated the froxlor syslog");
			return $this->response(true);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}
}
