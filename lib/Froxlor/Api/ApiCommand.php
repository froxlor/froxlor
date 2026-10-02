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

namespace Froxlor\Api;

use Exception;
use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Language;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Mailer;

abstract class ApiCommand extends ApiParameter
{

	/**
	 * froxlor version
	 *
	 * @var string
	 */
	protected $version = null;
	/**
	 * froxlor dbversion
	 *
	 * @var int
	 */
	protected $dbversion = null;
	/**
	 * froxlor version-branding
	 *
	 * @var string
	 */
	protected $branding = null;
	/**
	 * debug flag
	 *
	 * @var boolean
	 */
	private $debug = false;
	/**
	 * is admin flag
	 *
	 * @var boolean
	 */
	private $is_admin = false;
	/**
	 * internal user data array
	 *
	 * @var array
	 */
	private $user_data = null;
	/**
	 * logger interface
	 *
	 * @var FroxlorLogger
	 */
	private $logger = null;
	/**
	 * mail interface
	 *
	 * @var Mailer
	 */
	private $mail = null;
	/**
	 * whether the call is an internal one or not
	 *
	 * @var boolean
	 */
	private $internal_call = false;

	/**
	 *
	 * @param array $header
	 *            optional, passed via API
	 * @param array $params
	 *            optional, array of parameters (var=>value) for the command
	 * @param array $userinfo
	 *            optional, passed via WebInterface (instead of $header)
	 * @param boolean $internal
	 *            optional whether called internally, default false
	 *
	 * @throws Exception
	 */
	final public function __construct($header = null, $params = null, $userinfo = null, $internal = false)
	{
		parent::__construct($params);

		$this->version = Froxlor::VERSION;
		$this->dbversion = Froxlor::DBVERSION;
		$this->branding = Froxlor::BRANDING;

		if (!empty($header)) {
			$this->readUserData($header);
		} elseif (!empty($userinfo)) {
			$this->user_data = $userinfo;
			$this->is_admin = (isset($userinfo['adminsession']) && $userinfo['adminsession'] == 1 && $userinfo['adminid'] > 0) ? true : false;
		} else {
			throw new Exception("Invalid user data", 500);
		}
		$this->logger = FroxlorLogger::getInstanceOf($this->user_data);

		// check whether the user is deactivated
		if ($this->getUserDetail('deactivated') == 1) {
			$this->logger()->logAction(FroxlorLogger::LOG_ERROR, LOG_INFO, "[API] User '" . $this->getUserDetail('loginnname') . "' tried to use API but is deactivated");
			throw new Exception("Account suspended", 406);
		}

		$this->initLang();

		/**
		 * Initialize the mailingsystem
		 */
		$this->mail = new Mailer(true);

		if ($this->debug) {
			$this->logger()->logAction(FroxlorLogger::LOG_ERROR, LOG_DEBUG, "[API] " . get_called_class() . ": " . json_encode($params, JSON_UNESCAPED_SLASHES));
		}

		// set internal call flag
		$this->internal_call = $internal;
	}

	/**
	 * read user data from database by api-request-header fields
	 *
	 * @param array $header
	 *            api-request header
	 *
	 * @return boolean
	 * @throws Exception
	 */
	private function readUserData($header = null)
	{
		$sel_stmt = Database::prepare("SELECT * FROM `api_keys` WHERE `apikey` = :ak AND `secret` = :as");
		$result = Database::pexecute_first($sel_stmt, [
			'ak' => $header['apikey'],
			'as' => $header['secret']
		], true, true);
		if ($result) {
			// admin or customer?
			if ($result['customerid'] == 0 && $result['adminid'] > 0) {
				$this->is_admin = true;
				$table = 'panel_admins';
				$key = "adminid";
			} elseif ($result['customerid'] > 0 && $result['adminid'] > 0) {
				$this->is_admin = false;
				$table = 'panel_customers';
				$key = "customerid";
			} else {
				// neither adminid is > 0 nor customerid is > 0 - sorry man, no way
				throw new Exception("Invalid API credentials", 400);
			}
			$sel_stmt = Database::prepare("SELECT * FROM `" . $table . "` WHERE `" . $key . "` = :id");
			$this->user_data = Database::pexecute_first($sel_stmt, [
				'id' => ($this->is_admin ? $result['adminid'] : $result['customerid'])
			], true, true);
			if ($this->is_admin) {
				$this->user_data['adminsession'] = 1;
			}
			return true;
		}
		throw new Exception("Invalid API credentials", 400);
	}

	/**
	 * return field from user-table
	 *
	 * @param string $detail
	 *
	 * @return string|null
	 */
	protected function getUserDetail($detail = null)
	{
		return ($this->user_data[$detail] ?? null);
	}

	/**
	 * return logger instance
	 *
	 * @return FroxlorLogger
	 */
	protected function logger()
	{
		return $this->logger;
	}

	/**
	 * initialize language to have localized strings available for the ApiCommands
	 */
	private function initLang()
	{
		Language::setLanguage(Settings::Get('panel.standardlanguage'));

		if ($this->getUserDetail('language') !== null && isset(Language::getLanguages()[$this->getUserDetail('language')])) {
			Language::setLanguage($this->getUserDetail('language'));
		} elseif ($this->getUserDetail('def_language') !== null) {
			Language::setLanguage($this->getUserDetail('def_language'));
		}
	}

	/**
	 * increase/decrease a resource field for customers/admins
	 *
	 * @param string $table
	 * @param string $keyfield
	 * @param int $key
	 * @param string $operator
	 * @param string $resource
	 * @param string $extra
	 * @param int $step
	 */
	protected static function updateResourceUsage($table = null, $keyfield = null, $key = null, $operator = '+', $resource = null, $extra = null, $step = 1)
	{
		$stmt = Database::prepare("
			UPDATE `" . $table . "`
			SET `" . $resource . "` = `" . $resource . "` " . $operator . " " . (int)$step . " " . $extra . "
			WHERE `" . $keyfield . "` = :key
		");
		Database::pexecute($stmt, [
			'key' => $key
		], true, true);
	}

	/**
	 * return SQL when parameter $sql_search is given via API
	 *
	 * @param array $sql_search
	 *            optional array with index = fieldname, and value = array with 'op' => operator (one of <, > or =),
	 *            LIKE is used if left empty and 'value' => searchvalue
	 * @param array $query_fields
	 *            optional array of placeholders mapped to the actual value which is used in the API commands when
	 *            executing the statement [internal]
	 * @param boolean $append
	 *            optional append to WHERE clause rather then create new one, default false [internal]
	 *
	 * @return string
	 */
	protected function getSearchWhere(&$query_fields = [], $append = false)
	{
		$search = $this->getParam('sql_search', true, []);
		$condition = '';
		if (!empty($search)) {
			if ($append == true) {
				$condition = ' AND ';
			} else {
				$condition = ' WHERE ';
			}
			$ops = [
				'<',
				'>',
				'=',
				'<>'
			];
			$first = true;
			foreach ($search as $field => $valoper) {
				if ($field == '_plainsql' && $this->internal_call) {
					if (isset($valoper['sql']) && isset($valoper['values']) && is_array($valoper['values'])) {
						if (preg_match('/^([a-z0-9\-\.,=\+_`\(\)\:\'\"\!\<\>\ ]+)$/i', $valoper['sql']) == false) {
							// skip
							continue;
						}
						$condition .= $valoper['sql'];
						foreach ($valoper['values'] as $var => $value) {
							$query_fields[':' . $var] = $value;
						}
					}
				} else {
					$cleanfield = str_replace(".", "", $field);
					$sortfield = explode('.', $field);
					foreach ($sortfield as $id => $sfield) {
						if (substr($sfield, -1, 1) != '`') {
							$sfield .= '`';
						}
						if ($sfield[0] != '`') {
							$sfield = '`' . $sfield;
						}
						$sortfield[$id] = $sfield;
					}
					$field = implode('.', $sortfield);
					if (preg_match('/^([a-z0-9\-\._`]+)$/i', $field) == false) {
						// skip
						continue;
					}
					if (!$first) {
						$condition .= ' AND ';
					}
					if (!is_array($valoper) || !isset($valoper['op']) || empty($valoper['op'])) {
						$condition .= $field . ' LIKE :' . $cleanfield;
						if (!is_array($valoper)) {
							$query_fields[':' . $cleanfield] = '%' . $valoper . '%';
						} else {
							$query_fields[':' . $cleanfield] = '%' . $valoper['value'] . '%';
						}
					} elseif (in_array($valoper['op'], $ops)) {
						$condition .= $field . ' ' . $valoper['op'] . ':' . $cleanfield;
						$query_fields[':' . $cleanfield] = $valoper['value'] ?? '';
					} elseif (strtolower($valoper['op']) == 'in' && is_array($valoper['value']) && count($valoper['value']) > 0) {
						$condition .= $field . ' ' . $valoper['op'] . ' (';
						foreach ($valoper['value'] as $incnt => $invalue) {
							if (!is_numeric($incnt)) {
								// skip
								continue;
							}
							if (!empty($invalue) && preg_match('/^([a-z0-9\-\._`]+)$/i', $invalue) == false) {
								// skip
								continue;
							}
							$condition .= ":" . $cleanfield . $incnt . ", ";
							$query_fields[':' . $cleanfield . $incnt] = $invalue ?? '';
						}
						$condition = substr($condition, 0, -2) . ')';
					} else {
						continue;
					}
					if ($first) {
						$first = false;
					}
				}
			}
		}
		return $condition;
	}

	/**
	 * return LIMIT clause when at least $sql_limit parameter is given via API
	 *
	 * @param int $sql_limit
	 *            optional, limit resultset, default 0
	 * @param int $sql_offset
	 *            optional, offset for limitation, default 0
	 *
	 * @return string
	 */
	protected function getLimit()
	{
		$limit = $this->getParam('sql_limit', true, 0);
		$offset = $this->getParam('sql_offset', true, 0);

		if (!is_numeric($limit)) {
			$limit = 0;
		}
		if (!is_numeric($offset)) {
			$offset = 0;
		}

		if ($limit > 0) {
			return ' LIMIT ' . $offset . ',' . $limit;
		}

		return '';
	}

	/**
	 * return ORDER BY clause if parameter $sql_orderby parameter is given via API
	 *
	 * @param array $sql_orderby
	 *            optional array with index = fieldname and value = ASC|DESC
	 * @param boolean $append
	 *            optional append to ORDER BY clause rather then create new one, default false [internal]
	 *
	 * @return string
	 */
	protected function getOrderBy($append = false)
	{
		$orderby = $this->getParam('sql_orderby', true, []);
		$order = "";
		if (!empty($orderby)) {
			if ($append) {
				$order .= ", ";
			} else {
				$order .= " ORDER BY ";
			}

			$nat_fields = [
				'`c`.`loginname`',
				'`c`.`name`',
				'`a`.`loginname`',
				'`adminname`',
				'`databasename`',
				'`username`'
			];

			foreach ($orderby as $field => $by) {
				$sortfield = explode('.', $field);
				foreach ($sortfield as $id => $sfield) {
					if (substr($sfield, -1, 1) != '`') {
						$sfield .= '`';
					}
					if ($sfield[0] != '`') {
						$sfield = '`' . $sfield;
					}
					$sortfield[$id] = $sfield;
				}
				$field = implode('.', $sortfield);
				if (preg_match('/^([a-z0-9\-\._`]+)$/i', $field) == false) {
					// skip
					continue;
				}
				$by = strtoupper($by);
				if (!in_array($by, [
					'ASC',
					'DESC'
				])) {
					$by = 'ASC';
				}
				if (Settings::Get('panel.natsorting') == 1 && in_array($field, $nat_fields)) {
					// Acts similar to php's natsort(), found in one comment at http://my.opera.com/cpr/blog/show.dml/160556
					$order .= "CONCAT( IF( ASCII( LEFT( " . $field . ", 5 ) ) > 57,
					LEFT( " . $field . ", 1 ), 0 ),
					IF( ASCII( RIGHT( " . $field . ", 1 ) ) > 57,
						LPAD( " . $field . ", 255, '0' ),
						LPAD( CONCAT( " . $field . ", '-' ), 255, '0' )
					)) " . $by . ", ";
				} else {
					$order .= $field . " " . $by . ", ";
				}
			}
			$order = substr($order, 0, -2);
		}

		return $order;
	}

	/**
	 * return mailer instance
	 *
	 * @return Mailer
	 */
	protected function mailer()
	{
		return $this->mail;
	}

	/**
	 * return api-compatible response in JSON format and send corresponding http-header
	 *
	 * @param mixed $data
	 * @param int $response_code
	 * @return string json-encoded response message
	 */
	protected function response($data = null, int $response_code = 200)
	{
		return Response::jsonDataResponse($data, $response_code);
	}

	/**
	 * returns an array of customers the current user can access
	 *
	 * @param string $customer_hide_option
	 *            optional, when called as customer, some options might be hidden due to the
	 *            panel.customer_hide_options settings
	 *
	 * @return array
	 * @throws Exception
	 */
	protected function getAllowedCustomerIds($customer_hide_option = '')
	{
		$customer_ids = [];
		if ($this->isAdmin()) {
			// if we're an admin, list all of the admins customers
			// or optionally for one specific customer identified by id or loginname
			$customerid = $this->getParam('customerid', true, 0);
			$loginname = $this->getParam('loginname', true, '');

			if (!empty($customerid) || !empty($loginname)) {
				$_result = $this->apiCall('Customers.get', [
					'id' => $customerid,
					'loginname' => $loginname
				]);
				$custom_list_result = [
					$_result
				];
			} else {
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
			}
			foreach ($custom_list_result as $customer) {
				$customer_ids[] = $customer['customerid'];
			}
		} else {
			if (!$this->isInternal() && !empty($customer_hide_option) && Settings::IsInList('panel.customer_hide_options', $customer_hide_option)) {
				throw new Exception("You cannot access this resource", 405);
			}
			$customer_ids = [
				$this->getUserDetail('customerid')
			];
		}
		if (empty($customer_ids)) {
			throw new Exception("Required resource unsatisfied.", 405);
		}
		return $customer_ids;
	}

	/**
	 * admin flag
	 *
	 * @return boolean
	 */
	protected function isAdmin()
	{
		return $this->is_admin;
	}

	/**
	 * call an api-command internally
	 *
	 * @param string $command
	 * @param array|null $params
	 * @param boolean $internal
	 *            optional whether called internally, default false
	 *
	 *
	 * @return array
	 */
	protected function apiCall($command = null, $params = null, $internal = false)
	{
		$_command = explode(".", $command);
		$module = __NAMESPACE__ . "\Commands\\" . $_command[0];
		$function = $_command[1];
		$json_result = $module::getLocal($this->getUserData(), $params, $internal)->{$function}();
		return json_decode($json_result, true)['data'];
	}

	/**
	 * returns an instance of the wanted ApiCommand (e.g.
	 * Customers, Domains, etc);
	 * this is used widely in the WebInterface
	 *
	 * @param array $userinfo
	 *            array of user-data
	 * @param array $params
	 *            array of parameters for the command
	 * @param boolean $internal
	 *            optional whether called internally, default false
	 *
	 * @return static
	 * @throws Exception
	 */
	public static function getLocal($userinfo = null, $params = null, $internal = false)
	{
		return new static(null, $params, $userinfo, $internal);
	}

	/**
	 * return user-data array
	 *
	 * @return array
	 */
	protected function getUserData()
	{
		return $this->user_data;
	}

	/**
	 * internal call flag
	 *
	 * @return boolean
	 */
	protected function isInternal()
	{
		return $this->internal_call;
	}

	/**
	 * returns an array of customer data for customer, or by customer-id/loginname for admin/reseller
	 *
	 * @param int $customerid
	 *            optional, required if loginname is empty
	 * @param string $loginname
	 *            optional, required of customerid is empty
	 * @param string $customer_resource_check
	 *            optional, when called as admin, check the resources of the target customer
	 *
	 * @return array
	 * @throws Exception
	 */
	protected function getCustomerData($customer_resource_check = '')
	{
		if ($this->isAdmin()) {
			$customerid = $this->getParam('customerid', true, 0);
			$loginname = $this->getParam('loginname', true, '');
			$customer = $this->apiCall('Customers.get', [
				'id' => $customerid,
				'loginname' => $loginname
			]);
			// check whether the customer has enough resources
			if (!empty($customer_resource_check) && $customer[$customer_resource_check . '_used'] >= $customer[$customer_resource_check] && $customer[$customer_resource_check] != '-1') {
				throw new Exception("Customer has no more resources available", 406);
			}
		} else {
			$customer = $this->getUserData();
		}
		return $customer;
	}

	/**
	 * return email template content from database or global language file if not found in DB
	 *
	 * @param array $customerdata
	 * @param string $group
	 * @param string $varname
	 * @param array $replace_arr
	 * @param string $default
	 *
	 * @return string
	 */
	protected function getMailTemplate($customerdata = null, $group = null, $varname = null, $replace_arr = [], $default = "")
	{
		// get template
		$stmt = Database::prepare("
			SELECT `value` FROM `" . TABLE_PANEL_TEMPLATES . "` WHERE `adminid`= :adminid
			AND `language`= :lang AND `templategroup`= :group AND `varname`= :var
		");
		$result = Database::pexecute_first($stmt, [
			"adminid" => $customerdata['adminid'],
			"lang" => $customerdata['def_language'],
			"group" => $group,
			"var" => $varname
		], true, true);
		$content = $default;
		if ($result) {
			$content = $result['value'] ?? $default;
		}
		// @fixme html_entity_decode
		$content = html_entity_decode(PhpHelper::replaceVariables($content, $replace_arr));
		return $content;
	}
}
