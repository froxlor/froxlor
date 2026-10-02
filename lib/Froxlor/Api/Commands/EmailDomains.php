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
use Froxlor\Settings;
use PDO;

/**
 * @since 2.0
 */
class EmailDomains extends ApiCommand implements ResourceEntity
{
	/**
	 * list all domains with email addresses connected to it.
	 * If called from an admin, list all domains with email addresses
	 * connected to it from all customers you are allowed to view, or
	 * specify id or loginname for one specific customer
	 *
	 * @param int $customerid
	 *            optional, admin-only, select email addresses of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select email addresses of a specific customer by loginname
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
		$customer_ids = $this->getAllowedCustomerIds('email');
		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
		SELECT DISTINCT d.domain, d.domain_ace, e.domainid,
		COUNT(e.email) as addresses,
		IFNULL(SUM(CASE WHEN e.popaccountid > 0 THEN 1 ELSE 0 END), 0) as accounts,
		IFNULL(SUM(
			CASE
			WHEN LENGTH(REPLACE(e.destination, CONCAT(e.email_full, ' '), '')) - LENGTH(REPLACE(REPLACE(e.destination, CONCAT(e.email_full, ' '), ''), ' ', '')) > 0
			THEN LENGTH(REPLACE(e.destination, CONCAT(e.email_full, ' '), '')) - LENGTH(REPLACE(REPLACE(e.destination, CONCAT(e.email_full, ' '), ''), ' ', ''))
			WHEN e.destination <> e.email_full THEN 1
			ELSE 0
			END
		), 0) as forwarder
		FROM `" . TABLE_MAIL_VIRTUAL . "` e
		LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` d ON d.id = e.domainid
		WHERE e.customerid IN (" . implode(", ", $customer_ids) . ") AND d.domain IS NOT NULL " .
			$this->getSearchWhere($query_fields,
				true) . " GROUP BY e.domainid  " . $this->getOrderBy() . $this->getLimit());
		Database::pexecute($result_stmt, $query_fields, true, true);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO,
			"[API] list email-domains");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of accessible domains with email addresses connected to
	 *
	 * @param int $customerid
	 *            optional, admin-only, select email addresses of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select email addresses of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		$customer_ids = $this->getAllowedCustomerIds('email');
		$query_fields = [];
		$result_stmt = Database::prepare("
		SELECT COUNT(DISTINCT d.domain) as num_emaildomains
		FROM `" . TABLE_MAIL_VIRTUAL . "` e
		LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` d ON d.id = e.domainid
		WHERE e.customerid IN (" . implode(", ", $customer_ids) . ") AND d.domain IS NOT NULL
		" . $this->getSearchWhere($query_fields, true));
		$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
		if ($result) {
			return $this->response($result['num_emaildomains']);
		}
		return $this->response(0);
	}

	/**
	 * You cannot directly access email-domains
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}
		throw new Exception('You cannot directly access this resource.', 303);
	}

	/**
	 * You cannot directly add email-domains
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
		throw new Exception('You cannot directly add this resource.', 303);
	}

	/**
	 * toggle catchall flag of given email address either by id or email-address
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
		throw new Exception('You cannot directly update this resource.', 303);
	}

	/**
	 * You cannot directly delete email-domains
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
		throw new Exception('You cannot directly delete this resource.', 303);
	}

}
