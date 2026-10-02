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
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Response;
use PDO;

/**
 * @since 0.10.0
 */
class Certificates extends ApiCommand implements ResourceEntity
{

	/**
	 * add new ssl-certificate entry for given domain by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain-id
	 * @param string $domainname
	 *            optional, the domainname
	 * @param string $ssl_cert_file
	 * @param string $ssl_key_file
	 * @param string $ssl_ca_file
	 *            optional
	 * @param string $ssl_cert_chainfile
	 *            optional
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		$domainid = $this->getParam('domainid', true, 0);
		$dn_optional = $domainid > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'domains')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$domain = $this->apiCall('SubDomains.get', [
			'id' => $domainid,
			'domainname' => $domainname
		]);
		$domainid = $domain['id'];

		// parameters
		$ssl_cert_file = $this->getParam('ssl_cert_file');
		$ssl_key_file = $this->getParam('ssl_key_file');
		$ssl_ca_file = $this->getParam('ssl_ca_file', true, '');
		$ssl_cert_chainfile = $this->getParam('ssl_cert_chainfile', true, '');

		// validate whether the domain does not already have an entry
		$has_cert = true;
		try {
			$this->apiCall('Certificates.get', [
				'id' => $domainid
			]);
		} catch (Exception $e) {
			if ($e->getCode() == 412) {
				$has_cert = false;
			} else {
				throw $e;
			}
		}
		if (!$has_cert) {
			$this->addOrUpdateCertificate($domain['id'], $ssl_cert_file, $ssl_key_file, $ssl_ca_file, $ssl_cert_chainfile, true);
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added ssl-certificate for '" . $domain['domain'] . "'");
			$result = $this->apiCall('Certificates.get', [
				'id' => $domain['id']
			]);
			return $this->response($result);
		}
		throw new Exception("Domain '" . $domain['domain'] . "' already has a certificate. Did you mean to call update?", 406);
	}

	/**
	 * insert or update certificates entry
	 *
	 * @param int $domainid
	 * @param string $ssl_cert_file
	 * @param string $ssl_key_file
	 * @param string $ssl_ca_file
	 * @param string $ssl_cert_chainfile
	 * @param boolean $do_insert
	 *            optional default false
	 *
	 * @return boolean
	 * @throws Exception
	 */
	private function addOrUpdateCertificate($domainid = 0, $ssl_cert_file = '', $ssl_key_file = '', $ssl_ca_file = '', $ssl_cert_chainfile = '', $do_insert = false)
	{
		if ($ssl_cert_file != '' && $ssl_key_file == '') {
			Response::standardError('sslcertificateismissingprivatekey', '', true);
		}

		$do_verify = true;
		$validtodate = null;
		$validtodate = null;
		$issuer = "";
		// no cert-file given -> forget everything
		if ($ssl_cert_file == '') {
			$ssl_key_file = '';
			$ssl_ca_file = '';
			$ssl_cert_chainfile = '';
			$do_verify = false;
		}

		// verify certificate content
		if ($do_verify) {
			// array openssl_x509_parse ( mixed $x509cert [, bool $shortnames = true ] )
			// openssl_x509_parse() returns information about the supplied x509cert, including fields such as
			// subject name, issuer name, purposes, valid from and valid to dates etc.
			$cert_content = openssl_x509_parse($ssl_cert_file);

			if (is_array($cert_content) && isset($cert_content['subject']) && isset($cert_content['subject']['CN'])) {
				// bool openssl_x509_check_private_key ( mixed $cert , mixed $key )
				// Checks whether the given key is the private key that corresponds to cert.
				if (openssl_x509_check_private_key($ssl_cert_file, $ssl_key_file) === false) {
					Response::standardError('sslcertificateinvalidcertkeypair', '', true);
				}

				// check optional stuff
				if ($ssl_ca_file != '') {
					$ca_content = openssl_x509_parse($ssl_ca_file);
					if (!is_array($ca_content)) {
						// invalid
						Response::standardError('sslcertificateinvalidca', '', true);
					}
				}
				if ($ssl_cert_chainfile != '') {
					$chain_content = openssl_x509_parse($ssl_cert_chainfile);
					if (!is_array($chain_content)) {
						// invalid
						Response::standardError('sslcertificateinvalidchain', '', true);
					}
				}
			} else {
				Response::standardError('sslcertificateinvalidcert', '', true);
			}
			// get data from certificate to store in the table
			$validfromdate = empty($cert_content['validFrom_time_t']) ? null : date("Y-m-d H:i:s", $cert_content['validFrom_time_t']);
			$validtodate = empty($cert_content['validTo_time_t']) ? null : date("Y-m-d H:i:s", $cert_content['validTo_time_t']);
			$issuer = preg_replace('/[^\p{L}0-9 ._\/\'&-]+/u', '', $cert_content['issuer']['O'] ?? "");
		}

		// Add/Update database entry
		$qrystart = "UPDATE ";
		$qrywhere = "WHERE ";
		if ($do_insert) {
			$qrystart = "INSERT INTO ";
			$qrywhere = ", ";
		}
		$stmt = Database::prepare($qrystart . " `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` SET
			`ssl_cert_file` = :ssl_cert_file,
			`ssl_key_file` = :ssl_key_file,
			`ssl_ca_file` = :ssl_ca_file,
			`ssl_cert_chainfile` = :ssl_cert_chainfile,
			`validfromdate` = :validfromdate,
			`validtodate` = :validtodate,
			`issuer` = :issuer
			" . $qrywhere . " `domainid`= :domainid
		");
		$params = [
			"ssl_cert_file" => $ssl_cert_file,
			"ssl_key_file" => $ssl_key_file,
			"ssl_ca_file" => $ssl_ca_file,
			"ssl_cert_chainfile" => $ssl_cert_chainfile,
			"validfromdate" => $validfromdate,
			"validtodate" => $validtodate,
			"issuer" => $issuer,
			"domainid" => $domainid
		];
		Database::pexecute($stmt, $params, true, true);
		// insert task to re-generate webserver-configs (#1260)
		Cronjob::inserttask(TaskId::REBUILD_VHOST);
		return true;
	}

	/**
	 * update ssl-certificate entry for given domain by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain-id
	 * @param string $domainname
	 *            optional, the domainname
	 * @param string $ssl_cert_file
	 * @param string $ssl_key_file
	 * @param string $ssl_ca_file
	 *            optional
	 * @param string $ssl_cert_chainfile
	 *            optional
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'domains')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$domain = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);

		// parameters
		$ssl_cert_file = $this->getParam('ssl_cert_file');
		$ssl_key_file = $this->getParam('ssl_key_file');
		$ssl_ca_file = $this->getParam('ssl_ca_file', true, '');
		$ssl_cert_chainfile = $this->getParam('ssl_cert_chainfile', true, '');
		$this->addOrUpdateCertificate($domain['id'], $ssl_cert_file, $ssl_key_file, $ssl_ca_file, $ssl_cert_chainfile, false);
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated ssl-certificate for '" . $domain['domain'] . "'");
		$result = $this->apiCall('Certificates.get', [
			'id' => $domain['id']
		]);
		return $this->response($result);
	}

	/**
	 * lists all certificate entries
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
		// select all my (accessible) certificates
		$certs_stmt_query = "SELECT s.*, d.domain, d.letsencrypt, c.customerid, c.loginname
			FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` s
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` d ON `d`.`id` = `s`.`domainid`
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON `c`.`customerid` = `d`.`customerid`
			WHERE ";

		$qry_params = [];
		$query_fields = [];
		if ($this->isAdmin() && $this->getUserDetail('customers_see_all') == '0') {
			// admin with only customer-specific permissions
			$certs_stmt_query .= "d.adminid = :adminid ";
			$qry_params['adminid'] = $this->getUserDetail('adminid');
		} elseif ($this->isAdmin() == false) {
			// customer-area
			$certs_stmt_query .= "d.customerid = :cid ";
			$qry_params['cid'] = $this->getUserDetail('customerid');
		} else {
			$certs_stmt_query .= "1 ";
		}
		$certs_stmt = Database::prepare($certs_stmt_query . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		$qry_params = array_merge($qry_params, $query_fields);
		Database::pexecute($certs_stmt, $qry_params, true, true);
		$result = [];
		while ($cert = $certs_stmt->fetch(PDO::FETCH_ASSOC)) {
			// respect froxlor-hostname
			if ($cert['domainid'] == 0) {
				$cert['domain'] = Settings::Get('system.hostname');
				$cert['letsencrypt'] = Settings::Get('system.le_froxlor_enabled');
				$cert['loginname'] = 'froxlor.panel';
			}

			// Set data from certificate
			$cert['isvalid'] = false;
			$cert['san'] = null;
			$cert_data = openssl_x509_parse($cert['ssl_cert_file']);
			if ($cert_data) {
				$cert['isvalid'] = (bool)$cert_data['validTo_time_t'] > time();
				// Set subject alt names from certificate
				if (isset($cert_data['extensions']['subjectAltName']) && !empty($cert_data['extensions']['subjectAltName'])) {
					$SANs = explode(",", $cert_data['extensions']['subjectAltName']);
					$SANs = array_map('trim', $SANs);
					foreach ($SANs as $san) {
						$san = str_replace("DNS:", "", $san);
						if ($san != $cert_data['subject']['CN'] && strpos($san, "othername:") === false) {
							$cert['san'][] = $san;
						}
					}
				}
			}
			// the private key for a Let's Encrypt managed domain is generated and stored
			// server-side only - froxlor's own UI never shows it for such domains either
			// (see Domain::canEditSSL()), so it must not round-trip through the API
			if ($cert['letsencrypt'] == '1') {
				unset($cert['ssl_key_file']);
			}
			$result[] = $cert;
		}
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * return ssl-certificate entry for given domain by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain-id
	 * @param string $domainname
	 *            optional, the domainname
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'domains')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$domain = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$domainid = $domain['id'];

		$stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid`= :domainid");
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get ssl-certificate for '" . $domain['domain'] . "'");
		$result = Database::pexecute_first($stmt, [
			"domainid" => $domainid
		]);
		if (!$result) {
			throw new Exception("Domain '" . $domain['domain'] . "' does not have a certificate.", 412);
		}
		// the private key for a Let's Encrypt managed domain is generated and stored
		// server-side only - froxlor's own UI never shows it for such domains either
		// (see Domain::canEditSSL()), so it must not round-trip through the API
		if ($domain['letsencrypt'] == '1') {
			unset($result['ssl_key_file']);
		}
		return $this->response($result);
	}

	/**
	 * returns the total number of certificates for the given user
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		// select all my (accessible) certificates
		$certs_stmt_query = "SELECT COUNT(*) as num_certs
			FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` s
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` d ON `d`.`id` = `s`.`domainid`
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON `c`.`customerid` = `d`.`customerid`
			WHERE ";
		$qry_params = [];
		$query_fields = [];
		if ($this->isAdmin() && $this->getUserDetail('customers_see_all') == '0') {
			// admin with only customer-specific permissions
			$certs_stmt_query .= "d.adminid = :adminid ";
			$qry_params['adminid'] = $this->getUserDetail('adminid');
		} elseif ($this->isAdmin() == false) {
			// customer-area
			$certs_stmt_query .= "d.customerid = :cid ";
			$qry_params['cid'] = $this->getUserDetail('customerid');
		} else {
			$certs_stmt_query .= "1 ";
		}
		$certs_stmt = Database::prepare($certs_stmt_query . $this->getSearchWhere($query_fields, true));
		$qry_params = array_merge($qry_params, $query_fields);
		$result = Database::pexecute_first($certs_stmt, $qry_params, true, true);
		if ($result) {
			return $this->response($result['num_certs']);
		}
		return $this->response(0);
	}

	/**
	 * delete certificates entry by id
	 *
	 * @param int $id
	 *
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		$id = $this->getParam('id');

		if ($this->isAdmin() == false) {
			$chk_stmt = Database::prepare("
				SELECT d.domain, d.letsencrypt FROM `" . TABLE_PANEL_DOMAINS . "` d
				LEFT JOIN `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` s ON s.domainid = d.id
				WHERE s.`id` = :id AND d.`customerid` = :cid
			");
			$chk = Database::pexecute_first($chk_stmt, [
				'id' => $id,
				'cid' => $this->getUserDetail('customerid')
			]);
		} elseif ($this->isAdmin()) {
			$chk_stmt = Database::prepare("
				SELECT d.domain, d.letsencrypt FROM `" . TABLE_PANEL_DOMAINS . "` d
				LEFT JOIN `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` s ON s.domainid = d.id
				WHERE s.`id` = :id" . ($this->getUserDetail('customers_see_all') == '0' ? " AND d.`adminid` = :aid" : ""));
			$params = [
				'id' => $id
			];
			if ($this->getUserDetail('customers_see_all') == '0') {
				$params['aid'] = $this->getUserDetail('adminid');
			}
			$chk = Database::pexecute_first($chk_stmt, $params);
			if ($chk == false && $this->getUserDetail('change_serversettings')) {
				// check whether it might be the froxlor-vhost certificate
				$chk_stmt = Database::prepare("
				SELECT \"" . Settings::Get('system.hostname') . "\" as domain, \"" . Settings::Get('system.le_froxlor_enabled') . "\" as letsencrypt FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "`
				WHERE `id` = :id AND `domainid` = '0'");
				$params = [
					'id' => $id
				];
				$chk = Database::pexecute_first($chk_stmt, $params);
				$chk['isFroxlorVhost'] = true;
			}
		}
		if ($chk !== false) {
			// additional access check by trying to get the certificate
			if (isset($chk['isFroxlorVhost']) && $chk['isFroxlorVhost'] == true) {
				$result = $chk;
			} else {
				$result = $this->apiCall('Certificates.get', [
					'domainname' => $chk['domain']
				]);
			}
			$del_stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE id = :id");
			Database::pexecute($del_stmt, [
				'id' => $id
			]);
			// trigger removing of certificate from acme.sh if let's encrypt
			if ($chk['letsencrypt'] == '1') {
				Cronjob::inserttask(TaskId::DELETE_DOMAIN_SSL, $chk['domain']);
			}
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] removed ssl-certificate for '" . $chk['domain'] . "'");
			return $this->response($result);
		}
		throw new Exception("Unable to determine SSL certificate. Maybe no access?", 406);
	}
}
