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
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class IpsAndPorts extends ApiCommand implements ResourceEntity
{

	/**
	 * lists all ip/port entries
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
		if ($this->isAdmin() && ($this->getUserDetail('change_serversettings') || !empty($this->getUserDetail('ip')))) {
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] list ips and ports");
			$ip_where = "";
			$append_where = false;
			if (!empty($this->getUserDetail('ip')) && $this->getUserDetail('ip') != -1) {
				$ip_ids = array_map('intval', json_decode($this->getUserDetail('ip'), true));
				$ip_where = "WHERE `id` IN (" . implode(", ", $ip_ids) . ")";
				$append_where = true;
			}
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` " . $ip_where . $this->getSearchWhere($query_fields, $append_where) . $this->getOrderBy() . $this->getLimit());
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
	 * returns the total number of accessible ip/port entries
	 *
	 * @access admin
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin() && ($this->getUserDetail('change_serversettings') || !empty($this->getUserDetail('ip')))) {
			$ip_where = "";
			$query_fields = [];
			if (!empty($this->getUserDetail('ip')) && $this->getUserDetail('ip') != -1) {
				$ip_ids = array_map('intval', json_decode($this->getUserDetail('ip'), true));
				$ip_where = "WHERE `id` IN (" . implode(", ", $ip_ids) . ") " . $this->getSearchWhere($query_fields, true);
			} else {
				$ip_where =  $this->getSearchWhere($query_fields);
			}
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_ips FROM `" . TABLE_PANEL_IPSANDPORTS . "` " . $ip_where);
			$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
			if ($result) {
				return $this->response($result['num_ips']);
			}
			return $this->response(0);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * create a new ip/port entry
	 *
	 * @param string $ip
	 * @param int $port
	 *            optional, default 80
	 * @param bool $listen_statement
	 *            optional, default 0 (false)
	 * @param bool $namevirtualhost_statement
	 *            optional, default 0 (false)
	 * @param bool $vhostcontainer
	 *            optional, default 0 (false)
	 * @param string $specialsettings
	 *            optional, default empty
	 * @param bool $vhostcontainer_servername_statement
	 *            optional, default 0 (false)
	 * @param string $default_vhostconf_domain
	 *            optional, defatul empty
	 * @param string $docroot
	 *            optional, default empty (point to froxlor)
	 * @param bool $ssl
	 *            optional, default 0 (false)
	 * @param string $ssl_cert_file
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_key_file
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_ca_file
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_cert_chainfile
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_specialsettings
	 *            optional, requires $ssl = 1, default empty
	 * @param bool $include_specialsettings
	 *            optional, requires $ssl = 1, whether or not to include non-ssl specialsettings, default false
	 * @param string $ssl_default_vhostconf_domain
	 *            optional, requires $ssl = 1, defatul empty
	 * @param bool $include_default_vhostconf_domain
	 *            optional, requires $ssl = 1, whether or not to include non-ssl default_vhostconf_domain, default false
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings')) {
			$ip = Validate::validate_ip2($this->getParam('ip'), false, 'invalidip', false, true, false, false, true);
			$port = Validate::validate($this->getParam('port', true, 80), 'port', Validate::REGEX_PORT, [
				'stringisempty',
				'myport'
			], [], true);
			$listen_statement = !empty($this->getBoolParam('listen_statement', true, 0)) ? 1 : 0;
			$namevirtualhost_statement = !empty($this->getBoolParam('namevirtualhost_statement', true, 0)) ? 1 : 0;
			$vhostcontainer = !empty($this->getBoolParam('vhostcontainer', true, 0)) ? 1 : 0;
			$ss = $this->getParam('specialsettings', true, '');
			$specialsettings = Validate::validate(str_replace("\r\n", "\n", $ss ?? ""), 'specialsettings', Validate::REGEX_CONF_TEXT, '', [], true);
			$vhostcontainer_servername_statement = !empty($this->getBoolParam('vhostcontainer_servername_statement', true, 1)) ? 1 : 0;
			$dvd = $this->getParam('default_vhostconf_domain', true, '');
			$default_vhostconf_domain = Validate::validate(str_replace("\r\n", "\n", $dvd), 'default_vhostconf_domain', Validate::REGEX_CONF_TEXT, '', [], true);
			$docroot = Validate::validate($this->getParam('docroot', true, ''), 'docroot', Validate::REGEX_DIR, '', [], true);

			if ((int)Settings::Get('system.use_ssl') == 1) {
				$ssl = (bool)$this->getBoolParam('ssl', true, 0);
				$cert_optional = !($ssl && empty(Settings::Get('system.ssl_cert_file')));
				$ssl_cert_file = Validate::validate($this->getParam('ssl_cert_file', $cert_optional, ''), 'ssl_cert_file', '', '', [], true);
				$ssl_key_file = Validate::validate($this->getParam('ssl_key_file', $cert_optional, ''), 'ssl_key_file', '', '', [], true);
				$ssl_ca_file = Validate::validate($this->getParam('ssl_ca_file', true, ''), 'ssl_ca_file', '', '', [], true);
				$ssl_cert_chainfile = Validate::validate($this->getParam('ssl_cert_chainfile', true, ''), 'ssl_cert_chainfile', '', '', [], true);
				$sslss = $this->getParam('ssl_specialsettings', true, '');
				$ssl_specialsettings = Validate::validate(str_replace("\r\n", "\n", $sslss ?? ""), 'ssl_specialsettings', Validate::REGEX_CONF_TEXT, '', [], true);
				$include_specialsettings = !empty($this->getBoolParam('include_specialsettings', true, 0)) ? 1 : 0;
				$ssldvd = $this->getParam('ssl_default_vhostconf_domain', true, '');
				$ssl_default_vhostconf_domain = Validate::validate(str_replace("\r\n", "\n", $ssldvd ?? ""), 'ssl_default_vhostconf_domain', Validate::REGEX_CONF_TEXT, '', [], true);
				$include_default_vhostconf_domain = !empty($this->getBoolParam('include_default_vhostconf_domain', true, 0)) ? 1 : 0;
			} else {
				$ssl = 0;
				$ssl_cert_file = '';
				$ssl_key_file = '';
				$ssl_ca_file = '';
				$ssl_cert_chainfile = '';
				$ssl_specialsettings = '';
				$include_specialsettings = 0;
				$ssl_default_vhostconf_domain = '';
				$include_default_vhostconf_domain = 0;
			}

			if ($listen_statement != '1') {
				$listen_statement = '0';
			}

			if ($namevirtualhost_statement != '1') {
				$namevirtualhost_statement = '0';
			}

			if ($vhostcontainer != '1') {
				$vhostcontainer = '0';
			}

			if ($vhostcontainer_servername_statement != '1') {
				$vhostcontainer_servername_statement = '0';
			}

			if ($ssl != '1') {
				$ssl = '0';
			}

			if ($ssl_cert_file != '') {
				$ssl_cert_file = FileDir::makeCorrectFile($ssl_cert_file);
			}

			if ($ssl_key_file != '') {
				$ssl_key_file = FileDir::makeCorrectFile($ssl_key_file);
			}

			if ($ssl_ca_file != '') {
				$ssl_ca_file = FileDir::makeCorrectFile($ssl_ca_file);
			}

			if ($ssl_cert_chainfile != '') {
				$ssl_cert_chainfile = FileDir::makeCorrectFile($ssl_cert_chainfile);
			}

			if (strlen(trim($docroot)) > 0) {
				$docroot = FileDir::makeCorrectDir($docroot);
			} else {
				$docroot = '';
			}

			// always use compressed ipv6 format
			$ip = inet_ntop(inet_pton($ip));

			$result_checkfordouble_stmt = Database::prepare("
			SELECT `id` FROM `" . TABLE_PANEL_IPSANDPORTS . "`
			WHERE `ip` = :ip AND `port` = :port");
			$result_checkfordouble = Database::pexecute_first($result_checkfordouble_stmt, [
				'ip' => $ip,
				'port' => $port
			]);

			if ($result_checkfordouble && $result_checkfordouble['id'] != '') {
				Response::standardError('myipnotdouble', '', true);
			}

			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_IPSANDPORTS . "`
				SET
				`ip` = :ip, `port` = :port, `listen_statement` = :ls,
				`namevirtualhost_statement` = :nvhs, `vhostcontainer` = :vhc,
				`vhostcontainer_servername_statement` = :vhcss,
				`specialsettings` = :ss, `ssl` = :ssl,
				`ssl_cert_file` = :ssl_cert, `ssl_key_file` = :ssl_key,
				`ssl_ca_file` = :ssl_ca, `ssl_cert_chainfile` = :ssl_chain,
				`default_vhostconf_domain` = :dvhd, `docroot` = :docroot,
				`ssl_specialsettings` = :ssl_ss, `include_specialsettings` = :incss,
				`ssl_default_vhostconf_domain` = :ssl_dvhd, `include_default_vhostconf_domain` = :incdvhd;
			");
			$ins_data = [
				'ip' => $ip,
				'port' => $port,
				'ls' => $listen_statement,
				'nvhs' => $namevirtualhost_statement,
				'vhc' => $vhostcontainer,
				'vhcss' => $vhostcontainer_servername_statement,
				'ss' => $specialsettings,
				'ssl' => $ssl,
				'ssl_cert' => $ssl_cert_file,
				'ssl_key' => $ssl_key_file,
				'ssl_ca' => $ssl_ca_file,
				'ssl_chain' => $ssl_cert_chainfile,
				'dvhd' => $default_vhostconf_domain,
				'docroot' => $docroot,
				'ssl_ss' => $ssl_specialsettings,
				'incss' => $include_specialsettings,
				'ssl_dvhd' => $ssl_default_vhostconf_domain,
				'incdvhd' => $include_default_vhostconf_domain
			];
			Database::pexecute($ins_stmt, $ins_data);
			$ins_data['id'] = Database::lastInsertId();

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			// Using nameserver, insert a task which rebuilds the server config
			Cronjob::inserttask(TaskId::REBUILD_DNS);

			if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$ip = '[' . $ip . ']';
			}
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] added IP/port '" . $ip . ":" . $port . "'");
			// get ip for return-array
			$result = $this->apiCall('IpsAndPorts.get', [
				'id' => $ins_data['id']
			]);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * return an ip/port entry by id
	 *
	 * @param int $id
	 *            ip-port-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if ($this->isAdmin() && ($this->getUserDetail('change_serversettings') || !empty($this->getUserDetail('ip')))) {
			$id = $this->getParam('id');
			if (!empty($this->getUserDetail('ip')) && $this->getUserDetail('ip') != -1) {
				$allowed_ips = json_decode($this->getUserDetail('ip'), true);
				if (!in_array($id, $allowed_ips)) {
					throw new Exception("You cannot access this resource", 405);
				}
			}
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `id` = :id
			");
			$result = Database::pexecute_first($result_stmt, [
				'id' => $id
			], true, true);
			if ($result) {
				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] get ip " . $result['ip'] . " " . $result['port']);
				return $this->response($result);
			}
			throw new Exception("IP/port with id #" . $id . " could not be found", 404);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * update ip/port entry by given id
	 *
	 * @param int $id
	 * @param string $ip
	 *            optional
	 * @param int $port
	 *            optional, default 80
	 * @param bool $listen_statement
	 *            optional, default 0 (false)
	 * @param bool $namevirtualhost_statement
	 *            optional, default 0 (false)
	 * @param bool $vhostcontainer
	 *            optional, default 0 (false)
	 * @param string $specialsettings
	 *            optional, default empty
	 * @param bool $vhostcontainer_servername_statement
	 *            optional, default 0 (false)
	 * @param string $default_vhostconf_domain
	 *            optional, defatul empty
	 * @param string $docroot
	 *            optional, default empty (point to froxlor)
	 * @param bool $ssl
	 *            optional, default 0 (false)
	 * @param string $ssl_cert_file
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_key_file
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_ca_file
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_cert_chainfile
	 *            optional, requires $ssl = 1, default empty
	 * @param string $ssl_specialsettings
	 *            optional, requires $ssl = 1, default empty
	 * @param bool $include_specialsettings
	 *            optional, requires $ssl = 1, whether or not to include non-ssl specialsettings, default false
	 * @param string $ssl_default_vhostconf_domain
	 *            optional, requires $ssl = 1, defatul empty
	 * @param bool $include_default_vhostconf_domain
	 *            optional, requires $ssl = 1, whether or not to include non-ssl default_vhostconf_domain, default false
	 *
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings')) {
			$id = $this->getParam('id');

			$result = $this->apiCall('IpsAndPorts.get', [
				'id' => $id
			]);

			$ip = Validate::validate_ip2($this->getParam('ip', true, $result['ip']), false, 'invalidip', false, true, false, false, true);
			$port = Validate::validate($this->getParam('port', true, $result['port']), 'port', Validate::REGEX_PORT, [
				'stringisempty',
				'myport'
			], [], true);
			$listen_statement = $this->getBoolParam('listen_statement', true, $result['listen_statement']);
			$namevirtualhost_statement = $this->getBoolParam('namevirtualhost_statement', true, $result['namevirtualhost_statement']);
			$vhostcontainer = $this->getBoolParam('vhostcontainer', true, $result['vhostcontainer']);
			$ss = $this->getParam('specialsettings', true, $result['specialsettings']);
			$specialsettings = Validate::validate(str_replace("\r\n", "\n", $ss ?? ""), 'specialsettings', Validate::REGEX_CONF_TEXT, '', [], true);
			$vhostcontainer_servername_statement = $this->getParam('vhostcontainer_servername_statement', true, $result['vhostcontainer_servername_statement']);
			$dvd = $this->getParam('default_vhostconf_domain', true, $result['default_vhostconf_domain']);
			$default_vhostconf_domain = Validate::validate(str_replace("\r\n", "\n", $dvd ?? ""), 'default_vhostconf_domain', Validate::REGEX_CONF_TEXT, '', [], true);
			$docroot = Validate::validate($this->getParam('docroot', true, $result['docroot']), 'docroot', Validate::REGEX_DIR, '', [], true);

			if ((int)Settings::Get('system.use_ssl') == 1) {
				$ssl = (bool)$this->getBoolParam('ssl', true, $result['ssl']);
				$cert_optional = !($ssl && empty(Settings::Get('system.ssl_cert_file')));
				$ssl_cert_file = Validate::validate($this->getParam('ssl_cert_file', $cert_optional, $result['ssl_cert_file']), 'ssl_cert_file', '', '', [], true);
				$ssl_key_file = Validate::validate($this->getParam('ssl_key_file', $cert_optional, $result['ssl_key_file']), 'ssl_key_file', '', '', [], true);
				$ssl_ca_file = Validate::validate($this->getParam('ssl_ca_file', true, $result['ssl_ca_file']), 'ssl_ca_file', '', '', [], true);
				$ssl_cert_chainfile = Validate::validate($this->getParam('ssl_cert_chainfile', true, $result['ssl_cert_chainfile']), 'ssl_cert_chainfile', '', '', [], true);
				$sslss = $this->getParam('ssl_specialsettings', true, $result['ssl_specialsettings']);
				$ssl_specialsettings = Validate::validate(str_replace("\r\n", "\n", $sslss ?? ""), 'ssl_specialsettings', Validate::REGEX_CONF_TEXT, '', [], true);
				$include_specialsettings = $this->getBoolParam('include_specialsettings', true, $result['include_specialsettings']);
				$ssldvd = $this->getParam('ssl_default_vhostconf_domain', true, $result['ssl_default_vhostconf_domain']);
				$ssl_default_vhostconf_domain = Validate::validate(str_replace("\r\n", "\n", $ssldvd ?? ""), 'ssl_default_vhostconf_domain', Validate::REGEX_CONF_TEXT, '', [], true);
				$include_default_vhostconf_domain = $this->getBoolParam('include_default_vhostconf_domain', true, $result['include_default_vhostconf_domain']);
			} else {
				$ssl = 0;
				$ssl_cert_file = '';
				$ssl_key_file = '';
				$ssl_ca_file = '';
				$ssl_cert_chainfile = '';
				$ssl_specialsettings = '';
				$include_specialsettings = 0;
				$ssl_default_vhostconf_domain = '';
				$include_default_vhostconf_domain = 0;
			}

			$result_checkfordouble_stmt = Database::prepare("
				SELECT `id` FROM `" . TABLE_PANEL_IPSANDPORTS . "`
				WHERE `ip` = :ip AND `port` = :port
			");
			$result_checkfordouble = Database::pexecute_first($result_checkfordouble_stmt, [
				'ip' => $ip,
				'port' => $port
			]);

			$result_sameipotherport_stmt = Database::prepare("
				SELECT `id` FROM `" . TABLE_PANEL_IPSANDPORTS . "`
				WHERE `ip` = :ip AND `id` <> :id
			");
			$result_sameipotherport = Database::pexecute_first($result_sameipotherport_stmt, [
				'ip' => $ip,
				'id' => $id
			], true, true);

			if ($listen_statement != '1') {
				$listen_statement = '0';
			}

			if ($namevirtualhost_statement != '1') {
				$namevirtualhost_statement = '0';
			}

			if ($vhostcontainer != '1') {
				$vhostcontainer = '0';
			}

			if ($vhostcontainer_servername_statement != '1') {
				$vhostcontainer_servername_statement = '0';
			}

			if ($ssl != '1') {
				$ssl = '0';
			}

			if ($ssl_cert_file != '') {
				$ssl_cert_file = FileDir::makeCorrectFile($ssl_cert_file);
			}

			if ($ssl_key_file != '') {
				$ssl_key_file = FileDir::makeCorrectFile($ssl_key_file);
			}

			if ($ssl_ca_file != '') {
				$ssl_ca_file = FileDir::makeCorrectFile($ssl_ca_file);
			}

			if ($ssl_cert_chainfile != '') {
				$ssl_cert_chainfile = FileDir::makeCorrectFile($ssl_cert_chainfile);
			}

			if (strlen(trim($docroot)) > 0) {
				$docroot = FileDir::makeCorrectDir($docroot);
			} else {
				$docroot = '';
			}

			// always use compressed ipv6 format
			$ip = inet_ntop(inet_pton($ip));

			if ($result['ip'] != $ip && $result['ip'] == Settings::Get('system.ipaddress') && $result_sameipotherport == false) {
				Response::standardError('cantchangesystemip', '', true);
			} elseif ($result_checkfordouble && $result_checkfordouble['id'] != '' && $result_checkfordouble['id'] != $id) {
				Response::standardError('myipnotdouble', '', true);
			} else {
				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_IPSANDPORTS . "`
					SET
					`ip` = :ip, `port` = :port, `listen_statement` = :ls,
					`namevirtualhost_statement` = :nvhs, `vhostcontainer` = :vhc,
					`vhostcontainer_servername_statement` = :vhcss,
					`specialsettings` = :ss, `ssl` = :ssl,
					`ssl_cert_file` = :ssl_cert, `ssl_key_file` = :ssl_key,
					`ssl_ca_file` = :ssl_ca, `ssl_cert_chainfile` = :ssl_chain,
					`default_vhostconf_domain` = :dvhd, `docroot` = :docroot,
					`ssl_specialsettings` = :ssl_ss, `include_specialsettings` = :incss,
					`ssl_default_vhostconf_domain` = :ssl_dvhd, `include_default_vhostconf_domain` = :incdvhd
					WHERE `id` = :id;
				");
				$upd_data = [
					'ip' => $ip,
					'port' => $port,
					'ls' => $listen_statement,
					'nvhs' => $namevirtualhost_statement,
					'vhc' => $vhostcontainer,
					'vhcss' => $vhostcontainer_servername_statement,
					'ss' => $specialsettings,
					'ssl' => $ssl,
					'ssl_cert' => $ssl_cert_file,
					'ssl_key' => $ssl_key_file,
					'ssl_ca' => $ssl_ca_file,
					'ssl_chain' => $ssl_cert_chainfile,
					'dvhd' => $default_vhostconf_domain,
					'docroot' => $docroot,
					'ssl_ss' => $ssl_specialsettings,
					'incss' => $include_specialsettings,
					'ssl_dvhd' => $ssl_default_vhostconf_domain,
					'incdvhd' => $include_default_vhostconf_domain,
					'id' => $id
				];
				Database::pexecute($upd_stmt, $upd_data);

				Cronjob::inserttask(TaskId::REBUILD_VHOST);
				// Using nameserver, insert a task which rebuilds the server config
				Cronjob::inserttask(TaskId::REBUILD_DNS);

				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] changed IP/port from '" . $result['ip'] . ":" . $result['port'] . "' to '" . $ip . ":" . $port . "'");

				$result = $this->apiCall('IpsAndPorts.get', [
					'id' => $result['id']
				]);
				return $this->response($result);
			}
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * delete an ip/port entry by id
	 *
	 * @param int $id
	 *            ip-port-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings')) {
			$id = $this->getParam('id');

			$result = $this->apiCall('IpsAndPorts.get', [
				'id' => $id
			]);

			$result_checkdomain_stmt = Database::prepare("
				SELECT `id_domain` FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_ipandports` = :id
			");
			$result_checkdomain = Database::pexecute_first($result_checkdomain_stmt, [
				'id' => $id
			], true, true);

			if (empty($result_checkdomain)) {
				if (!in_array($result['id'], explode(',', Settings::Get('system.defaultip'))) && !in_array($result['id'], explode(',', Settings::Get('system.defaultsslip')))) {
					// check whether there is the same IP with a different port
					// in case this ip-address is the system.ipaddress and therefore
					// when there is one - we have an alternative
					$result_sameipotherport_stmt = Database::prepare("
						SELECT `id` FROM `" . TABLE_PANEL_IPSANDPORTS . "`
						WHERE `ip` = :ip AND `id` <> :id");
					$result_sameipotherport = Database::pexecute_first($result_sameipotherport_stmt, [
						'id' => $id,
						'ip' => $result['ip']
					]);

					if (($result['ip'] != Settings::Get('system.ipaddress')) || ($result['ip'] == Settings::Get('system.ipaddress') && $result_sameipotherport != false)) {
						$del_stmt = Database::prepare("
							DELETE FROM `" . TABLE_PANEL_IPSANDPORTS . "`
							WHERE `id` = :id
						");
						Database::pexecute($del_stmt, [
							'id' => $id
						], true, true);

						// also, remove connections to domains (multi-stack)
						$del_stmt = Database::prepare("
							DELETE FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_ipandports` = :id
						");
						Database::pexecute($del_stmt, [
							'id' => $id
						], true, true);

						Cronjob::inserttask(TaskId::REBUILD_VHOST);
						// Using nameserver, insert a task which rebuilds the server config
						Cronjob::inserttask(TaskId::REBUILD_DNS);

						$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] deleted IP/port '" . $result['ip'] . ":" . $result['port'] . "'");
						return $this->response($result);
					} else {
						Response::standardError('cantdeletesystemip', '', true);
					}
				} else {
					Response::standardError('cantdeletedefaultip', '', true);
				}
			} else {
				Response::standardError('ipstillhasdomains', '', true);
			}
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}
}
