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
use Froxlor\FroxlorLogger;
use Froxlor\System\Cronjob;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class Cronjobs extends ApiCommand implements ResourceEntity
{

	private array $allowed_intervals = [
		'MINUTE',
		'HOUR',
		'DAY',
		'WEEK',
		'MONTH'
	];

	/**
	 * You cannot add new cronjobs yet.
	 */
	public function add()
	{
		throw new Exception('You cannot add new cronjobs yet.', 303);
	}

	/**
	 * return a cronjob entry by id
	 *
	 * @param int $id
	 *            cronjob-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$id = $this->getParam('id');

			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_CRONRUNS . "` WHERE `id` = :id
			");
			$result = Database::pexecute_first($result_stmt, [
				'id' => $id
			], true, true);
			if ($result) {
				return $this->response($result);
			}
			throw new Exception("cronjob with id #" . $id . " could not be found", 404);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * update a cronjob entry by given id
	 *
	 * @param int $id
	 * @param bool $isactive
	 *            optional whether the cronjob is active or not
	 * @param int $interval_value
	 *            optional number of seconds/minutes/hours/etc. for the interval
	 * @param string $interval_interval
	 *            optional interval for the cronjob (MINUTE, HOUR, DAY, WEEK or MONTH)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			// required parameter
			$id = $this->getParam('id');

			$result = $this->apiCall('Cronjobs.get', [
				'id' => $id
			]);

			// split interval
			$cur_int = explode(" ", $result['interval']);

			// parameter
			$isactive = $this->getBoolParam('isactive', true, $result['isactive']);
			$interval_value = $this->getParam('interval_value', true, $cur_int[0]);
			$interval_interval = $this->getParam('interval_interval', true, $cur_int[1]);

			// validation
			if ($isactive != 1) {
				$isactive = 0;
			}
			$interval_value = Validate::validate($interval_value, 'interval_value', '/^([0-9]+)$/Di', 'stringisempty', [], true);
			$interval_interval = Validate::validate($interval_interval, 'interval_interval', '', '', [], true);

			if (!in_array(strtoupper($interval_interval), $this->allowed_intervals)) {
				Response::standardError('invalidcronjobintervalvalue', implode(", ", $this->allowed_intervals), true);
			}

			// put together interval value
			$interval = $interval_value . ' ' . strtoupper($interval_interval);

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CRONRUNS . "`
				SET `isactive` = :isactive, `interval` = :int
				WHERE `id` = :id
			");
			Database::pexecute($upd_stmt, [
				'isactive' => $isactive,
				'int' => $interval,
				'id' => $id
			], true, true);

			// insert task to re-generate the cron.d-file
			Cronjob::inserttask(TaskId::REBUILD_CRON);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] cronjob with description '" . $result['module'] . '/' . $result['cronfile'] . "' has been updated by '" . $this->getUserDetail('loginname') . "'");
			$result = $this->apiCall('Cronjobs.get', [
				'id' => $id
			]);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * lists all cronjob entries
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
	 * @access admin
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] list cronjobs");
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT `c`.* FROM `" . TABLE_PANEL_CRONRUNS . "` `c` " . $this->getSearchWhere($query_fields) . $this->getOrderBy() . $this->getLimit());
			Database::pexecute($result_stmt, $query_fields, true, true);
			$result = [];
			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$result[] = $row;
			}
			return $this->response([
				'count' => count($result),
				'list' => $result
			]);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * returns the total number of cronjobs
	 *
	 * @access admin
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_crons FROM `" . TABLE_PANEL_CRONRUNS . "` `c`
			" . $this->getSearchWhere($query_fields));
			$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
			if ($result) {
				return $this->response($result['num_crons']);
			}
			return $this->response(0);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * You cannot delete system cronjobs.
	 */
	public function delete()
	{
		throw new Exception('You cannot delete system cronjobs.', 303);
	}
}
