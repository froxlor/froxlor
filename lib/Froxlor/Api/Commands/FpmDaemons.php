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
use Froxlor\System\Cronjob;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class FpmDaemons extends ApiCommand implements ResourceEntity
{

	/**
	 * lists all fpm-daemon entries
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
		if ($this->isAdmin()) {
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] list fpm-daemons");
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_FPMDAEMONS . "`" . $this->getSearchWhere($query_fields) . $this->getOrderBy() . $this->getLimit());
			Database::pexecute($result_stmt, $query_fields, true, true);
			$fpmdaemons = [];
			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$query_params = [
					'id' => $row['id']
				];

				$configresult_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_PHPCONFIGS . "` WHERE `fpmsettingid` = :id");
				Database::pexecute($configresult_stmt, $query_params, true, true);

				$configs = [];
				if (Database::num_rows() > 0) {
					while ($row2 = $configresult_stmt->fetch(PDO::FETCH_ASSOC)) {
						$configs[] = $row2['description'];
					}
				}

				if (empty($configs)) {
					$configs[] = lng('admin.phpsettings.notused');
				}

				$row['configs'] = $configs;
				$fpmdaemons[] = $row;
			}

			return $this->response([
				'count' => count($fpmdaemons),
				'list' => $fpmdaemons
			]);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * returns the total number of accessible fpm daemons
	 *
	 * @access admin
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin()) {
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_fpms FROM `" . TABLE_PANEL_FPMDAEMONS . "`
			"  . $this->getSearchWhere($query_fields));
			$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
			if ($result) {
				return $this->response($result['num_fpms']);
			}
			return $this->response(0);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * return a fpm-daemon entry by id
	 *
	 * @param int $id
	 *            fpm-daemon-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if ($this->isAdmin()) {
			$id = $this->getParam('id');

			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_FPMDAEMONS . "` WHERE `id` = :id
			");
			$result = Database::pexecute_first($result_stmt, [
				'id' => $id
			], true, true);
			if ($result) {
				return $this->response($result);
			}
			throw new Exception("fpm-daemon with id #" . $id . " could not be found", 404);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * create a new fpm-daemon entry
	 *
	 * @param string $description
	 * @param string $reload_cmd
	 * @param string $config_dir
	 * @param string $pm
	 *            optional, process-manager, one of 'static', 'dynamic' or 'ondemand', default 'dynamic'
	 * @param int $max_children
	 *            optional, default 5
	 * @param int $start_servers
	 *            optional, default 2
	 * @param int $min_spare_servers
	 *            optional, default 1
	 * @param int $max_spare_servers
	 *            optional, default 3
	 * @param int $max_requests
	 *            optional, default 0
	 * @param int $idle_timeout
	 *            optional, default 10
	 * @param string $limit_extensions
	 *            optional, limit execution to the following extensions, default '.php'
	 * @param string $custom_config
	 *            optional, custom settings appended to phpfpm pool configuration
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			// required parameter
			$description = $this->getParam('description');
			$reload_cmd = $this->getParam('reload_cmd');
			$config_dir = $this->getParam('config_dir');

			// parameters
			$pmanager = $this->getParam('pm', true, 'dynamic');
			$max_children = $this->getParam('max_children', true, 5);
			$start_servers = $this->getParam('start_servers', true, 2);
			$min_spare_servers = $this->getParam('min_spare_servers', true, 1);
			$max_spare_servers = $this->getParam('max_spare_servers', true, 3);
			$max_requests = $this->getParam('max_requests', true, 0);
			$idle_timeout = $this->getParam('idle_timeout', true, 10);
			$limit_extensions = $this->getParam('limit_extensions', true, '.php');
			$custom_config = $this->getParam('custom_config', true, '');

			// validation
			$description = Validate::validate($description, 'description', Validate::REGEX_DESC_TEXT, '', [], true);
			$reload_cmd = Validate::validate($reload_cmd, 'reload_cmd', '/^[a-z0-9\/\._\-@ ]+$/i', '', [], true);
			$sel_stmt = Database::prepare("SELECT `id` FROM `".TABLE_PANEL_FPMDAEMONS."` WHERE `reload_cmd` = :rc");
			$dupcheck = Database::pexecute_first($sel_stmt, ['rc' => $reload_cmd]);
			if ($dupcheck && $dupcheck['id']) {
				throw new Exception("PHP-FPM version with the given restart command already exists", 406);
			}
			$config_dir = Validate::validate($config_dir, 'config_dir', Validate::REGEX_DIR, '', [], true);
			if (!in_array($pmanager, [
				'static',
				'dynamic',
				'ondemand'
			])) {
				throw new Exception("Unknown process manager", 406);
			}
			if (empty($limit_extensions)) {
				$limit_extensions = '.php';
			}
			$limit_extensions = Validate::validate($limit_extensions, 'limit_extensions', '/^(\.[a-z]([a-z0-9]+)\ ?)+$/', '', [], true);

			if (strlen($description) == 0 || strlen($description) > 50) {
				Response::standardError('descriptioninvalid', '', true);
			}

			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_FPMDAEMONS . "` SET
				`description` = :desc,
				`reload_cmd` = :reload_cmd,
				`config_dir` = :config_dir,
				`pm` = :pm,
				`max_children` = :max_children,
				`start_servers` = :start_servers,
				`min_spare_servers` = :min_spare_servers,
				`max_spare_servers` = :max_spare_servers,
				`max_requests` = :max_requests,
				`idle_timeout` = :idle_timeout,
				`limit_extensions` = :limit_extensions,
				`custom_config` = :custom_config
			");
			$ins_data = [
				'desc' => $description,
				'reload_cmd' => $reload_cmd,
				'config_dir' => FileDir::makeCorrectDir($config_dir),
				'pm' => $pmanager,
				'max_children' => $max_children,
				'start_servers' => $start_servers,
				'min_spare_servers' => $min_spare_servers,
				'max_spare_servers' => $max_spare_servers,
				'max_requests' => $max_requests,
				'idle_timeout' => $idle_timeout,
				'limit_extensions' => $limit_extensions,
				'custom_config' => $custom_config
			];
			Database::pexecute($ins_stmt, $ins_data);
			$id = Database::lastInsertId();

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] fpm-daemon with description '" . $description . "' has been created by '" . $this->getUserDetail('loginname') . "'");
			$result = $this->apiCall('FpmDaemons.get', [
				'id' => $id
			]);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * update a fpm-daemon entry by given id
	 *
	 * @param int $id
	 *            fpm-daemon id
	 * @param string $description
	 *            optional
	 * @param string $reload_cmd
	 *            optional
	 * @param string $config_dir
	 *            optional
	 * @param string $pm
	 *            optional, process-manager, one of 'static', 'dynamic' or 'ondemand', default 'dynamic'
	 * @param int $max_children
	 *            optional, default 5
	 * @param int $start_servers
	 *            optional, default 2
	 * @param int $min_spare_servers
	 *            optional, default 1
	 * @param int $max_spare_servers
	 *            optional, default 3
	 * @param int $max_requests
	 *            optional, default 0
	 * @param int $idle_timeout
	 *            optional, default 10
	 * @param string $limit_extensions
	 *            optional, limit execution to the following extensions, default '.php'
	 * @param string $custom_config
	 *            optional, custom settings appended to phpfpm pool configuration
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

			$result = $this->apiCall('FpmDaemons.get', [
				'id' => $id
			]);

			// parameters
			$description = $this->getParam('description', true, $result['description']);
			$reload_cmd = $this->getParam('reload_cmd', true, $result['reload_cmd']);
			$config_dir = $this->getParam('config_dir', true, $result['config_dir']);
			$pmanager = $this->getParam('pm', true, $result['pm']);
			$max_children = $this->getParam('max_children', true, $result['max_children']);
			$start_servers = $this->getParam('start_servers', true, $result['start_servers']);
			$min_spare_servers = $this->getParam('min_spare_servers', true, $result['min_spare_servers']);
			$max_spare_servers = $this->getParam('max_spare_servers', true, $result['max_spare_servers']);
			$max_requests = $this->getParam('max_requests', true, $result['max_requests']);
			$idle_timeout = $this->getParam('idle_timeout', true, $result['idle_timeout']);
			$limit_extensions = $this->getParam('limit_extensions', true, $result['limit_extensions']);
			$custom_config = $this->getParam('custom_config', true, $result['custom_config']);

			// validation
			$description = Validate::validate($description, 'description', Validate::REGEX_DESC_TEXT, '', [], true);
			$reload_cmd = Validate::validate($reload_cmd, 'reload_cmd', '/^[a-z0-9\/\._\-@ ]+$/i', '', [], true);
			$sel_stmt = Database::prepare("SELECT `id` FROM `".TABLE_PANEL_FPMDAEMONS."` WHERE `reload_cmd` = :rc");
			$dupcheck = Database::pexecute_first($sel_stmt, ['rc' => $reload_cmd]);
			if ($dupcheck && $dupcheck['id'] != $id) {
				throw new Exception("PHP-FPM version with the given restart command already exists", 406);
			}
			$config_dir = Validate::validate($config_dir, 'config_dir', Validate::REGEX_DIR, '', [], true);
			if (!in_array($pmanager, [
				'static',
				'dynamic',
				'ondemand'
			])) {
				throw new Exception("Unknown process manager", 406);
			}
			if (empty($limit_extensions)) {
				$limit_extensions = '.php';
			}
			$limit_extensions = Validate::validate($limit_extensions, 'limit_extensions', '/^(\.[a-z]([a-z0-9]+)\ ?)+$/', '', [], true);

			if (strlen($description) == 0 || strlen($description) > 50) {
				Response::standardError('descriptioninvalid', '', true);
			}

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_FPMDAEMONS . "` SET
				`description` = :desc,
				`reload_cmd` = :reload_cmd,
				`config_dir` = :config_dir,
				`pm` = :pm,
				`max_children` = :max_children,
				`start_servers` = :start_servers,
				`min_spare_servers` = :min_spare_servers,
				`max_spare_servers` = :max_spare_servers,
				`max_requests` = :max_requests,
				`idle_timeout` = :idle_timeout,
				`limit_extensions` = :limit_extensions,
				`custom_config` = :custom_config
				WHERE `id` = :id
			");
			$upd_data = [
				'desc' => $description,
				'reload_cmd' => $reload_cmd,
				'config_dir' => FileDir::makeCorrectDir($config_dir),
				'pm' => $pmanager,
				'max_children' => $max_children,
				'start_servers' => $start_servers,
				'min_spare_servers' => $min_spare_servers,
				'max_spare_servers' => $max_spare_servers,
				'max_requests' => $max_requests,
				'idle_timeout' => $idle_timeout,
				'limit_extensions' => $limit_extensions,
				'custom_config' => $custom_config,
				'id' => $id
			];
			Database::pexecute($upd_stmt, $upd_data, true, true);

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] fpm-daemon with description '" . $description . "' has been updated by '" . $this->getUserDetail('loginname') . "'");
			$result = $this->apiCall('FpmDaemons.get', [
				'id' => $id
			]);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * delete a fpm-daemon entry by id
	 *
	 * @param int $id
	 *            fpm-daemon-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$id = $this->getParam('id');

			if ($id == 1) {
				Response::standardError('cannotdeletedefaultphpconfig', '', true);
			}

			$result = $this->apiCall('FpmDaemons.get', [
				'id' => $id
			]);

			// set default fpm daemon config for all php-config that use this config that is to be deleted
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_PHPCONFIGS . "` SET
				`fpmsettingid` = '1' WHERE `fpmsettingid` = :id
			");
			Database::pexecute($upd_stmt, [
				'id' => $id
			], true, true);

			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_FPMDAEMONS . "` WHERE `id` = :id
			");
			Database::pexecute($del_stmt, [
				'id' => $id
			], true, true);

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] fpm-daemon setting '" . $result['description'] . "' has been deleted by '" . $this->getUserDetail('loginname') . "'");
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}
}
