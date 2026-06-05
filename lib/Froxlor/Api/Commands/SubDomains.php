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
use Froxlor\Domain\Domain;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class SubDomains extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new subdomain
	 *
	 * @param string $subdomain
	 *            part before domain.tld to create as subdomain
	 * @param string $domain
	 *            domainname of main-domain
	 * @param int $alias
	 *            optional, domain-id of a domain that the new domain should be an alias of
	 * @param string $path
	 *            optional, destination path relative to the customers-homedir, default is customers-homedir
	 * @param string $url
	 *            optional, overwrites path value with an URL to generate a redirect, alternatively use the path
	 *            parameter also for URLs
	 * @param int $openbasedir_path
	 *            optional, either 0 for domains-docroot [default], 1 for customers-homedir or 2 for parent-directory of domains-docroot
	 * @param int $phpsettingid
	 *            optional, php-settings-id, if empty the $domain value is used
	 * @param int $redirectcode
	 *            optional, redirect-code-id from TABLE_PANEL_REDIRECTCODES
	 * @param int $speciallogfile
	 *            optional, whether to create an exclusive web-logfile for this domain (1) or not (0) or inherit value from parentdomain (2, default)
	 * @param bool $sslenabled
	 *            optional, whether or not SSL is enabled for this domain, regardless of the assigned ssl-ips, default
	 *            1 (true)
	 * @param bool $ssl_redirect
	 *            optional, whether to generate a https-redirect or not, default false; requires SSL to be enabled
	 * @param bool $letsencrypt
	 *            optional, whether to generate a Let's Encrypt certificate for this domain, default false; requires
	 *            SSL to be enabled
	 * @param bool $http2
	 *            optional, whether to enable http/2 for this subdomain (requires to be enabled in the settings),
	 *            default 0 (false)
	 * @param bool $http3
	 *            optional, whether to enable http/3 for this subdomain (requires to be enabled in the settings),
	 *            default 0 (false)
	 * @param int $hsts_maxage
	 *            optional max-age value for HSTS header, default 0
	 * @param bool $hsts_sub
	 *            optional whether or not to add subdomains to the HSTS header, default 0
	 * @param bool $hsts_preload
	 *            optional whether or not to preload HSTS header value, default 0
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if (($this->getUserDetail('subdomains_used') < $this->getUserDetail('subdomains') || $this->getUserDetail('subdomains') == '-1') || $this->isAdmin()) {
			// parameters
			$subdomain = $this->getParam('subdomain');
			$domain = $this->getParam('domain');

			// optional parameters
			$aliasdomain = $this->getParam('alias', true, 0);
			$path = $this->getParam('path', true, '');
			$url = $this->getParam('url', true, '');
			$openbasedir_path = $this->getParam('openbasedir_path', true, 0);
			$phpsettingid = $this->getParam('phpsettingid', true, 0);
			$redirectcode = $this->getParam('redirectcode', true, Settings::Get('customredirect.default'));
			$speciallogfile = intval($this->getParam('speciallogfile', true, 2));
			$isemaildomain = $this->getParam('isemaildomain', true, 0);
			if (Settings::Get('system.use_ssl')) {
				$sslenabled = $this->getBoolParam('sslenabled', true, 1);
				$ssl_redirect = $this->getBoolParam('ssl_redirect', true, 0);
				$letsencrypt = $this->getBoolParam('letsencrypt', true, 0);
				$http2 = $this->getBoolParam('http2', true, 0);
				$http3 = $this->getBoolParam('http3', true, 0);
				$hsts_maxage = $this->getParam('hsts_maxage', true, 0);
				$hsts_sub = $this->getBoolParam('hsts_sub', true, 0);
				$hsts_preload = $this->getBoolParam('hsts_preload', true, 0);
			} else {
				$sslenabled = 0;
				$ssl_redirect = 0;
				$letsencrypt = 0;
				$http2 = 0;
				$http3 = 0;
				$hsts_maxage = 0;
				$hsts_sub = 0;
				$hsts_preload = 0;
			}

			// get needed customer info to reduce the subdomain-usage-counter by one
			$customer = $this->getCustomerData('subdomains');

			// validation
			$subdomain = strtolower($subdomain);
			if (substr($subdomain, 0, 4) == 'xn--') {
				Response::standardError('domain_nopunycode', '', true);
			}

			$idna_convert = new IdnaWrapper();
			$subdomain = $idna_convert->encode(preg_replace([
				'/\:(\d)+$/',
				'/^https?\:\/\//'
			], '', Validate::validate($subdomain, 'subdomain', '', 'subdomainiswrong', [], true)));

			// merge the two parts together
			$completedomain = $subdomain . '.' . $domain;

			if (Settings::Get('system.validate_domain') && !Validate::validateDomain($completedomain)) {
				Response::standardError([
					'stringiswrong',
					'mydomain'
				], '', true);
			}
			if ($completedomain == strtolower(Settings::Get('system.hostname'))) {
				Response::standardError('admin_domain_emailsystemhostname', '', true);
			}

			// check whether the domain already exists
			$completedomain_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_DOMAINS . "`
				WHERE `domain` = :domain
				AND `customerid` = :customerid
				AND `email_only` = '0'
			");
			$completedomain_check = Database::pexecute_first($completedomain_stmt, [
				"domain" => $completedomain,
				"customerid" => $customer['customerid']
			], true, true);

			if ($completedomain_check) {
				// no exception so far - domain exists
				Response::standardError('domainexistalready', $completedomain, true);
			}

			// alias domain checked?
			if ($aliasdomain != 0) {
				// also check ip/port combination to be the same, #176
				$aliasdomain_stmt = Database::prepare("
					SELECT `d`.`id` FROM `" . TABLE_PANEL_DOMAINS . "` `d` , `" . TABLE_PANEL_CUSTOMERS . "` `c` , `" . TABLE_DOMAINTOIP . "` `dip`
					WHERE `d`.`aliasdomain` IS NULL
					AND `d`.`id` = :id
					AND `c`.`standardsubdomain` <> `d`.`id`
					AND `d`.`customerid` = :customerid
					AND `c`.`customerid` = `d`.`customerid`
					AND `d`.`id` = `dip`.`id_domain`
					AND `dip`.`id_ipandports`
					IN (SELECT `id_ipandports` FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_domain` = :id )
					GROUP BY `d`.`domain`
					ORDER BY `d`.`domain` ASC
				");
				$aliasdomain_check = Database::pexecute_first($aliasdomain_stmt, [
					"id" => $aliasdomain,
					"customerid" => $customer['customerid']
				], true, true);
				if ($aliasdomain_check['id'] != $aliasdomain) {
					Response::standardError('domainisaliasorothercustomer', '', true);
				}
				Domain::triggerLetsEncryptCSRForAliasDestinationDomain($aliasdomain, $this->logger());
			}

			// validate / correct path/url of domain
			$_doredirect = false;
			$path = $this->validateDomainDocumentRoot($path, $url, $customer, $completedomain, $_doredirect);

			if ($openbasedir_path > 2 && $openbasedir_path < 0) {
				$openbasedir_path = 0;
			}

			// get main domain for various checks
			$domain_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_DOMAINS . "`
				WHERE `domain` = :domain
				AND `customerid` = :customerid
				AND `parentdomainid` = '0'
				AND `email_only` = '0'
			");
			$domain_check = Database::pexecute_first($domain_stmt, [
				"domain" => $domain,
				"customerid" => $customer['customerid']
			], true, true);

			if (!$domain_check) {
				// the given main-domain
				Response::standardError('maindomainnonexist', $domain, true);
			} elseif ($subdomain == 'www' && $domain_check['wwwserveralias'] == '1') {
				// you cannot add 'www' as subdomain when the maindomain generates a www-alias
				Response::standardError('wwwnotallowed', '', true);
			} elseif ($completedomain_check && strtolower($completedomain_check['domain']) == strtolower($completedomain)) {
				// the domain does already exist as main-domain
				Response::standardError('domainexistalready', $completedomain, true);
			} elseif ((int)$domain_check['deactivated'] == 1) {
				// main domain is deactivated
				Response::standardError('maindomaindeactivated', $domain, true);
			}

			// if allowed, check for 'is email domain'-flag
			if ($domain_check['subcanemaildomain'] == '1' || $domain_check['subcanemaildomain'] == '2') {
				$isemaildomain = intval($isemaildomain);
			} else {
				$isemaildomain = $domain_check['subcanemaildomain'] == '3' ? 1 : 0;
			}

			if ($ssl_redirect != 0) {
				// a ssl-redirect only works if there actually is a
				// ssl ip/port assigned to the domain
				if (Domain::domainHasSslIpPort($domain_check['id']) == true) {
					$ssl_redirect = '1';
					$_doredirect = true;
				} else {
					Response::standardError('sslredirectonlypossiblewithsslipport', '', true);
				}
			}

			if ($letsencrypt != 0) {
				// let's encrypt only works if there actually is a
				// ssl ip/port assigned to the domain
				if (Domain::domainHasSslIpPort($domain_check['id']) == true) {
					$letsencrypt = '1';
				} else {
					Response::standardError('letsencryptonlypossiblewithsslipport', '', true);
				}
			}

			// validate dns if lets encrypt is enabled to check whether we can use it at all
			if ($letsencrypt == '1' && Settings::Get('system.le_domain_dnscheck') == '1') {
				$our_ips = Domain::getIpsOfDomain($domain_check['id']);
				$domain_ips = PhpHelper::gethostbynamel6($completedomain, true, Settings::Get('system.le_domain_dnscheck_resolver'));
				if ($domain_ips == false || count(array_intersect($our_ips, $domain_ips)) <= 0) {
					Response::standardError('invaliddnsforletsencrypt', '', true);
				}
			}

			// Temporarily deactivate ssl_redirect until Let's Encrypt certificate was generated
			if ($ssl_redirect > 0 && $letsencrypt == 1) {
				$ssl_redirect = 2;
			}

			// validate speciallogfile value
			if ($speciallogfile < 0 || $speciallogfile > 2) {
				$speciallogfile = 2; // inherit from parent-domain
			}

			// get the phpsettingid from parentdomain, #107
			$phpsid_stmt = Database::prepare("
				SELECT `phpsettingid` FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `id` = :id
			");
			$phpsid_result = Database::pexecute_first($phpsid_stmt, [
				"id" => $domain_check['id']
			], true, true);

			if (!isset($phpsid_result['phpsettingid']) || (int)$phpsid_result['phpsettingid'] <= 0) {
				// assign default config
				$phpsid_result['phpsettingid'] = 1;
			}

			if ($domain_check['phpenabled'] == 1) {
				// check whether the customer has chosen its own php-config
				if ($phpsettingid > 0 && $phpsettingid != $phpsid_result['phpsettingid']) {
					$phpsid_result['phpsettingid'] = intval($phpsettingid);
				}

				$allowed_phpconfigs = $customer['allowed_phpconfigs'];
				if (!empty($allowed_phpconfigs)) {
					$allowed_phpconfigs = json_decode($allowed_phpconfigs, true);
				} else {
					$allowed_phpconfigs = [];
				}
				// only with fcgid/fpm enabled will it be possible to select a php-setting
				if ((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1) {
					if (!in_array($phpsid_result['phpsettingid'], $allowed_phpconfigs)) {
						Response::standardError('notallowedphpconfigused', '', true);
					}
				}
			}

			// actually insert domain
			$stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_DOMAINS . "` SET
				`customerid` = :customerid,
				`adminid` = :adminid,
				`domain` = :domain,
				`domain_ace` = :domain_ace,
				`documentroot` = :documentroot,
				`aliasdomain` = :aliasdomain,
				`parentdomainid` = :parentdomainid,
				`wwwserveralias` = :wwwserveralias,
				`isemaildomain` = :isemaildomain,
				`iswildcarddomain` = :iswildcarddomain,
				`phpenabled` = :phpenabled,
				`openbasedir` = :openbasedir,
				`openbasedir_path` = :openbasedir_path,
				`speciallogfile` = :speciallogfile,
				`specialsettings` = :specialsettings,
				`ssl_specialsettings` = :ssl_specialsettings,
				`include_specialsettings` = :include_specialsettings,
				`ssl_redirect` = :ssl_redirect,
				`phpsettingid` = :phpsettingid,
				`letsencrypt` = :letsencrypt,
				`http2` = :http2,
				`http3` = :http3,
				`hsts` = :hsts,
				`hsts_sub` = :hsts_sub,
				`hsts_preload` = :hsts_preload,
				`ocsp_stapling` = :ocsp_stapling,
				`override_tls` = :override_tls,
				`ssl_protocols` = :ssl_protocols,
				`ssl_cipher_list` = :ssl_cipher_list,
				`tlsv13_cipher_list` = :tlsv13_cipher_list,
				`ssl_enabled` = :sslenabled,
				`dkim` = :dkim
			");
			$params = [
				"customerid" => $customer['customerid'],
				"adminid" => $customer['adminid'],
				"domain" => $completedomain,
				"domain_ace" => $idna_convert->decode($completedomain),
				"documentroot" => $path,
				"aliasdomain" => $aliasdomain != 0 ? $aliasdomain : null,
				"parentdomainid" => $domain_check['id'],
				"wwwserveralias" => $domain_check['wwwserveralias'] == '1' ? '1' : '0',
				"iswildcarddomain" => $domain_check['iswildcarddomain'] == '1' ? '1' : '0',
				"isemaildomain" => $isemaildomain,
				"openbasedir" => $domain_check['openbasedir'],
				"openbasedir_path" => $openbasedir_path,
				"phpenabled" => $domain_check['phpenabled'],
				"speciallogfile" => $speciallogfile == 2 ? $domain_check['speciallogfile'] : $speciallogfile,
				"specialsettings" => $domain_check['specialsettings'],
				"ssl_specialsettings" => $domain_check['ssl_specialsettings'],
				"include_specialsettings" => $domain_check['include_specialsettings'],
				"ssl_redirect" => $ssl_redirect,
				"phpsettingid" => $phpsid_result['phpsettingid'],
				"letsencrypt" => $letsencrypt,
				"http2" => $http2,
				"http3" => $http3,
				"hsts" => $hsts_maxage,
				"hsts_sub" => $hsts_sub,
				"hsts_preload" => $hsts_preload,
				"ocsp_stapling" => $domain_check['ocsp_stapling'],
				"override_tls" => $domain_check['override_tls'],
				"ssl_protocols" => $domain_check['ssl_protocols'],
				"ssl_cipher_list" => $domain_check['ssl_cipher_list'],
				"tlsv13_cipher_list" => $domain_check['tlsv13_cipher_list'],
				"sslenabled" => $sslenabled,
				"dkim" => $domain_check['dkim'],
			];
			Database::pexecute($stmt, $params, true, true);
			$subdomain_id = Database::lastInsertId();

			$stmt = Database::prepare("
				INSERT INTO `" . TABLE_DOMAINTOIP . "`
				(`id_domain`, `id_ipandports`)
				SELECT LAST_INSERT_ID(), `id_ipandports`
				FROM `" . TABLE_DOMAINTOIP . "`
				WHERE `id_domain` = :id_domain
			");
			Database::pexecute($stmt, [
				"id_domain" => $domain_check['id']
			]);

			if ($_doredirect) {
				Domain::addRedirectToDomain($subdomain_id, $redirectcode);
			}

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			// Using nameserver, insert a task which rebuilds the server config
			Cronjob::inserttask(TaskId::REBUILD_DNS);

			Customers::increaseUsage($customer['customerid'], 'subdomains_used');

			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] added subdomain '" . $completedomain . "'");

			$result = $this->apiCall('SubDomains.get', [
				'id' => $subdomain_id
			]);
			return $this->response($result);
		}
		throw new Exception("No more resources available", 406);
	}

	/**
	 * return a subdomain entry by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain-id
	 * @param string $domainname
	 *            optional, the domainname
	 * @param bool $with_ips
	 *            optional, default true
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
		$with_ips = $this->getParam('with_ips', true, true);

		// convert possible idn domain to punycode
		if (substr($domainname, 0, 4) != 'xn--') {
			$idna_convert = new IdnaWrapper();
			$domainname = $idna_convert->encode($domainname);
		}

		if ($this->isAdmin()) {
			if ($this->getUserDetail('customers_see_all') != 1) {
				// if it's a reseller or an admin who cannot see all customers, we need to check
				// whether the database belongs to one of his customers
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
				$customer_ids = [];
				foreach ($custom_list_result as $customer) {
					$customer_ids[] = $customer['customerid'];
				}
				if (count($customer_ids) > 0) {
					$result_stmt = Database::prepare("
						SELECT d.*, pd.`subcanemaildomain`, pd.`isbinddomain` as subisbinddomain
						FROM `" . TABLE_PANEL_DOMAINS . "` d, `" . TABLE_PANEL_DOMAINS . "` pd
						WHERE " . ($id > 0 ? "d.`id` = :iddn" : "d.`domain` = :iddn") . " AND d.`customerid` IN (" . implode(", ", $customer_ids) . ")
						AND ((d.`parentdomainid`!='0' AND pd.`id` = d.`parentdomainid`) OR (d.`parentdomainid`='0' AND pd.`id` = d.`id`))
					");
					$params = [
						'iddn' => ($id <= 0 ? $domainname : $id)
					];
				} else {
					throw new Exception("You do not have any customers yet", 406);
				}
			} else {
				$result_stmt = Database::prepare("
					SELECT d.*, pd.`subcanemaildomain`, pd.`isbinddomain` as subisbinddomain
					FROM `" . TABLE_PANEL_DOMAINS . "` d, `" . TABLE_PANEL_DOMAINS . "` pd
					WHERE " . ($id > 0 ? "d.`id` = :iddn" : "d.`domain` = :iddn") . "
					AND ((d.`parentdomainid`!='0' AND pd.`id` = d.`parentdomainid`) OR (d.`parentdomainid`='0' AND pd.`id` = d.`id`))
				");
				$params = [
					'iddn' => ($id <= 0 ? $domainname : $id)
				];
			}
		} else {
			if (!$this->isInternal() && Settings::IsInList('panel.customer_hide_options', 'domains')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$result_stmt = Database::prepare("
				SELECT d.*, pd.`subcanemaildomain`, pd.`isbinddomain` as subisbinddomain, pd.`domain` as parentdomain
				FROM `" . TABLE_PANEL_DOMAINS . "` d, `" . TABLE_PANEL_DOMAINS . "` pd
				WHERE d.`customerid`= :customerid AND " . ($id > 0 ? "d.`id` = :iddn" : "d.`domain` = :iddn") . "
				AND ((d.`parentdomainid`!='0' AND pd.`id` = d.`parentdomainid`) OR (d.`parentdomainid`='0' AND pd.`id` = d.`id`))
			");
			$params = [
				'customerid' => $this->getUserDetail('customerid'),
				'iddn' => ($id <= 0 ? $domainname : $id)
			];
		}
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			$result['ipsandports'] = [];
			if ($with_ips) {
				$result['ipsandports'] = $this->getIpsForDomain($result['id']);
			}
			$result['domain_hascert'] = $this->getHasCertValueForDomain((int)$result['id'], (int)$result['parentdomainid']);
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get subdomain '" . $result['domain'] . "'");
			return $this->response($result);
		}
		throw new Exception("Requested subdomain could not be found", 404);
	}

	private function getHasCertValueForDomain(int $domainid, int $parentdomainid): int
	{
		// nothing (ssl_global)
		$domain_hascert = 0;
		$ssl_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid` = :domainid");
		Database::pexecute($ssl_stmt, array(
			"domainid" => $domainid
		));
		$ssl_result = $ssl_stmt->fetch(PDO::FETCH_ASSOC);
		if (is_array($ssl_result) && isset($ssl_result['ssl_cert_file']) && $ssl_result['ssl_cert_file'] != '') {
			// own certificate (ssl_customer_green)
			$domain_hascert = 1;
		} else {
			// check if it's parent has one set (shared)
			if ($parentdomainid != 0) {
				$ssl_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid` = :domainid");
				Database::pexecute($ssl_stmt, array(
					"domainid" => $parentdomainid
				));
				$ssl_result = $ssl_stmt->fetch(PDO::FETCH_ASSOC);
				if (is_array($ssl_result) && isset($ssl_result['ssl_cert_file']) && $ssl_result['ssl_cert_file'] != '') {
					// parent has a certificate (ssl_shared)
					$domain_hascert = 2;
				}
			}
		}
		return $domain_hascert;
	}

	/**
	 * validate given path and replace with url if given and valid
	 *
	 * @param string $path
	 * @param string $url
	 * @param array $customer
	 * @param string $completedomain
	 * @param boolean $_doredirect
	 *
	 * @return string validated path
	 * @throws Exception
	 */
	private function validateDomainDocumentRoot($path = null, $url = null, $customer = null, $completedomain = null, &$_doredirect = false)
	{
		$_doredirect = false;
		$idna = new IdnaWrapper();

		// url mode: either $url or $path begins with http:// or https://
		$maybeUrl = !empty($url) ? $url : (preg_match('/^https?\:\/\//', $path) ? $path : '');
		if ($maybeUrl !== '') {
			$encoded = $idna->encode($maybeUrl);
			if (!Validate::validateUrl($encoded, true)) {
				Response::standardError('invaliddocumentrooturl', '', true);
			}
			$_doredirect = true;
			return $encoded;
		}

		// path mode: regular directory path
		$path = Validate::validate($path, 'path', Validate::REGEX_DIR, '', [], true);

		// default path if empty and setting active
		if (($path === '' || $path === '/') && Settings::Get('system.documentroot_use_default_value') == 1) {
			return FileDir::makeCorrectDir($customer['documentroot'] . '/' . $completedomain, $customer['documentroot']);
		}
		// check if path does not contain a colon
		if (strpos($path, ':') !== false) {
			Response::standardError('pathmaynotcontaincolon', '', true);
		}

		if (file_exists($customer['documentroot'] . '/' . $path) && !is_dir($customer['documentroot'] . '/' . $path)) {
			Response::standardError('pathexistsasfile', '', true);
		}

		return FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);
	}

	/**
	 * update subdomain entry by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain-id
	 * @param string $domainname
	 *            optional, the domainname
	 * @param int $alias
	 *            optional, domain-id of a domain that the new domain should be an alias of
	 * @param string $path
	 *            optional, destination path relative to the customers-homedir, default is customers-homedir
	 * @param string $url
	 *            optional, overwrites path value with an URL to generate a redirect, alternatively use the path
	 *            parameter also for URLs
	 * @param int $selectserveralias
	 *            optional, 0 = wildcard, 1 = www-alias, 2 = none
	 * @param bool $isemaildomain
	 *            optional
	 * @param int $openbasedir_path
	 *            optional, either 0 for domains-docroot, 1 for customers-homedir or 2 for parent-directory of domains-docroot
	 * @param int $phpsettingid
	 *            optional, php-settings-id, if empty the $domain value is used
	 * @param int $redirectcode
	 *            optional, redirect-code-id from TABLE_PANEL_REDIRECTCODES
	 * @param bool $speciallogfile
	 *            optional, whether to create an exclusive web-logfile for this domain
	 * @param bool $speciallogverified
	 *            optional, when setting $speciallogfile to false, this needs to be set to true to confirm the action,
	 *            default 0 (false)
	 * @param bool $sslenabled
	 *            optional, whether or not SSL is enabled for this domain, regardless of the assigned ssl-ips, default
	 *            1 (true)
	 * @param bool $ssl_redirect
	 *            optional, whether to generate a https-redirect or not, default false; requires SSL to be enabled
	 * @param bool $letsencrypt
	 *            optional, whether to generate a Let's Encrypt certificate for this domain, default false; requires
	 *            SSL to be enabled
	 * @param bool $http2
	 *            optional, whether to enable http/2 for this domain (requires to be enabled in the settings), default
	 *            0 (false)
	 * @param bool $http3
	 *            optional, whether to enable http/3 for this domain (requires to be enabled in the settings), default
	 *            0 (false)
	 * @param int $hsts_maxage
	 *            optional max-age value for HSTS header
	 * @param bool $hsts_sub
	 *            optional whether or not to add subdomains to the HSTS header
	 * @param bool $hsts_preload
	 *            optional whether or not to preload HSTS header value
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
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

		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];

		if ($this->isAdmin() == false && (int)$result['caneditdomain'] == 0) {
			throw new Exception(lng('error.domaincannotbeedited', [$result['domain']]), 406);
		}

		// parameters
		$aliasdomain = $this->getParam('alias', true, 0);
		$path = $this->getParam('path', true, $result['documentroot']);
		$url = $this->getParam('url', true, '');
		// default: 0 = wildcard, 1 = www-alias, 2 = none
		$_serveraliasdefault = $result['iswildcarddomain'] == '1' ? 0 : ($result['wwwserveralias'] == '1' ? 1 : 2);
		$selectserveralias = $this->getParam('selectserveralias', true, $_serveraliasdefault);
		$isemaildomain = $this->getBoolParam('isemaildomain', true, $result['isemaildomain']);
		$openbasedir_path = $this->getParam('openbasedir_path', true, $result['openbasedir_path']);
		$phpsettingid = $this->getParam('phpsettingid', true, $result['phpsettingid']);
		$redirectcode = $this->getParam('redirectcode', true, Domain::getDomainRedirectId($id));
		$speciallogfile = $this->getBoolParam('speciallogfile', true, $result['speciallogfile']);
		$speciallogverified = $this->getBoolParam('speciallogverified', true, 0);
		if (Settings::Get('system.use_ssl')) {
			$sslenabled = $this->getBoolParam('sslenabled', true, $result['ssl_enabled']);
			$ssl_redirect = $this->getBoolParam('ssl_redirect', true, $result['ssl_redirect']);
			$letsencrypt = $this->getBoolParam('letsencrypt', true, $result['letsencrypt']);
			$http2 = $this->getBoolParam('http2', true, $result['http2']);
			$http3 = $this->getBoolParam('http3', true, $result['http3']);
			$hsts_maxage = $this->getParam('hsts_maxage', true, $result['hsts']);
			$hsts_sub = $this->getBoolParam('hsts_sub', true, $result['hsts_sub']);
			$hsts_preload = $this->getBoolParam('hsts_preload', true, $result['hsts_preload']);
		} else {
			$sslenabled = 0;
			$ssl_redirect = 0;
			$letsencrypt = 0;
			$http2 = 0;
			$http3 = 0;
			$hsts_maxage = 0;
			$hsts_sub = 0;
			$hsts_preload = 0;
		}

		// get needed customer info to reduce the subdomain-usage-counter by one
		$customer = $this->getCustomerData();

		$alias_stmt = Database::prepare("SELECT COUNT(`id`) AS count FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `aliasdomain`= :aliasdomain");
		$alias_check = Database::pexecute_first($alias_stmt, [
			"aliasdomain" => $result['id']
		]);
		$alias_check = $alias_check['count'];

		// alias domain checked?
		if ($aliasdomain != 0) {
			$aliasdomain_stmt = Database::prepare("
				SELECT `id` FROM `" . TABLE_PANEL_DOMAINS . "` `d`,`" . TABLE_PANEL_CUSTOMERS . "` `c`
				WHERE `d`.`customerid`= :customerid
				AND `d`.`aliasdomain` IS NULL
				AND `d`.`id`<>`c`.`standardsubdomain`
				AND `c`.`customerid`= :customerid
				AND `d`.`id`= :id
			");
			$aliasdomain_check = Database::pexecute_first($aliasdomain_stmt, [
				"id" => $aliasdomain,
				"customerid" => $customer['customerid']
			], true, true);
			if ($aliasdomain_check['id'] != $aliasdomain) {
				Response::standardError('domainisaliasorothercustomer', '', true);
			}
			Domain::triggerLetsEncryptCSRForAliasDestinationDomain($aliasdomain, $this->logger());
		}

		// validate / correct path/url of domain
		$_doredirect = false;
		$path = $this->validateDomainDocumentRoot($path, $url, $customer, $result['domain'], $_doredirect);

		// set alias-fields according to selected alias mode
		$iswildcarddomain = ($selectserveralias == '0') ? '1' : '0';
		$wwwserveralias = ($selectserveralias == '1') ? '1' : '0';

		// if allowed, check for 'is email domain'-flag
		if ($isemaildomain != $result['isemaildomain']) {
			if ($result['parentdomainid'] != '0' && ($result['subcanemaildomain'] == '1' || $result['subcanemaildomain'] == '2')) {
				$isemaildomain = intval($isemaildomain);
			} elseif ($result['parentdomainid'] != '0') {
				$isemaildomain = $result['subcanemaildomain'] == '3' ? 1 : 0;
			}
		}

		// check changes of openbasedir-path variable
		if ($openbasedir_path > 2 && $openbasedir_path < 0) {
			$openbasedir_path = 0;
		}

		if ($ssl_redirect != 0) {
			// a ssl-redirect only works if there actually is a
			// ssl ip/port assigned to the domain
			if (Domain::domainHasSslIpPort($result['id']) == true) {
				$ssl_redirect = '1';
				$_doredirect = true;
			} else {
				Response::standardError('sslredirectonlypossiblewithsslipport', '', true);
			}
		}

		if ($letsencrypt != 0) {
			// let's encrypt only works if there actually is a
			// ssl ip/port assigned to the domain
			if (Domain::domainHasSslIpPort($result['id']) == true) {
				$letsencrypt = '1';
			} else {
				Response::standardError('letsencryptonlypossiblewithsslipport', '', true);
			}
		}

		// validate dns if lets encrypt is enabled to check whether we can use it at all
		if ($result['letsencrypt'] != $letsencrypt && $letsencrypt == '1' && Settings::Get('system.le_domain_dnscheck') == '1') {
			$our_ips = Domain::getIpsOfDomain($result['parentdomainid']);
			$domain_ips = PhpHelper::gethostbynamel6($result['domain'], true, Settings::Get('system.le_domain_dnscheck_resolver'));
			if ($domain_ips == false || count(array_intersect($our_ips, $domain_ips)) <= 0) {
				Response::standardError('invaliddnsforletsencrypt', '', true);
			}
		}

		// We can't enable let's encrypt for wildcard-domains
		if ($iswildcarddomain == '1' && $letsencrypt == '1') {
			Response::standardError('nowildcardwithletsencrypt', '', true);
		}

		// Temporarily deactivate ssl_redirect until Let's Encrypt certificate was generated
		if ($ssl_redirect > 0 && $letsencrypt == 1 && $result['letsencrypt'] != $letsencrypt) {
			$ssl_redirect = 2;
		}

		if ($speciallogfile != $result['speciallogfile'] && $speciallogverified != '1') {
			$speciallogfile = $result['speciallogfile'];
		}

		// is-email-domain flag changed - remove mail accounts and mail-addresses
		if (($result['isemaildomain'] == '1') && $isemaildomain == '0') {
			$params = [
				"customerid" => $customer['customerid'],
				"domainid" => $id
			];
			$stmt = Database::prepare("DELETE FROM `" . TABLE_MAIL_USERS . "` WHERE `customerid`= :customerid AND `domainid`= :domainid");
			Database::pexecute($stmt, $params, true, true);
			$stmt = Database::prepare("DELETE FROM `" . TABLE_MAIL_VIRTUAL . "` WHERE `customerid`= :customerid AND `domainid`= :domainid");
			Database::pexecute($stmt, $params, true, true);
			$idna_convert = new IdnaWrapper();
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] automatically deleted mail-table entries for '" . $idna_convert->decode($result['domain']) . "'");
		}

		$allowed_phpconfigs = $customer['allowed_phpconfigs'];
		if (!empty($allowed_phpconfigs)) {
			$allowed_phpconfigs = json_decode($allowed_phpconfigs, true);
		} else {
			$allowed_phpconfigs = [];
		}
		// only with fcgid/fpm enabled will it be possible to select a php-setting
		if ((int)$result['phpenabled'] == 1 && ((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1)) {
			if (!in_array($phpsettingid, $allowed_phpconfigs)) {
				Response::standardError('notallowedphpconfigused', '', true);
			}
		}

		// handle redirect
		if ($_doredirect) {
			Domain::updateRedirectOfDomain($id, $redirectcode);
		}

		if ($path != $result['documentroot']
			|| $isemaildomain != $result['isemaildomain']
			|| $wwwserveralias != $result['wwwserveralias']
			|| $iswildcarddomain != $result['iswildcarddomain']
			|| $aliasdomain != (int)$result['aliasdomain']
			|| $openbasedir_path != $result['openbasedir_path']
			|| $sslenabled != $result['ssl_enabled']
			|| $ssl_redirect != $result['ssl_redirect']
			|| $letsencrypt != $result['letsencrypt']
			|| $hsts_maxage != $result['hsts']
			|| $hsts_sub != $result['hsts_sub']
			|| $hsts_preload != $result['hsts_preload']
			|| $phpsettingid != $result['phpsettingid']
			|| $http2 != $result['http2']
			|| $http3 != $result['http3']
			|| ($speciallogfile != $result['speciallogfile'] && $speciallogverified == '1')
		) {
			$stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_DOMAINS . "` SET
					`documentroot` = :documentroot,
					`isemaildomain` = :isemaildomain,
					`wwwserveralias` = :wwwserveralias,
					`iswildcarddomain` = :iswildcarddomain,
					`aliasdomain` = :aliasdomain,
					`openbasedir_path` = :openbasedir_path,
					`ssl_enabled` = :sslenabled,
					`ssl_redirect` = :ssl_redirect,
					`letsencrypt` = :letsencrypt,
					`http2` = :http2,
					`http3` = :http3,
					`hsts` = :hsts,
					`hsts_sub` = :hsts_sub,
					`hsts_preload` = :hsts_preload,
					`phpsettingid` = :phpsettingid,
					`speciallogfile` = :speciallogfile
					WHERE `customerid`= :customerid AND `id`= :id
				");
			$params = [
				"documentroot" => $path,
				"isemaildomain" => $isemaildomain,
				"wwwserveralias" => $wwwserveralias,
				"iswildcarddomain" => $iswildcarddomain,
				"aliasdomain" => ($aliasdomain != 0 && $alias_check == 0) ? $aliasdomain : null,
				"openbasedir_path" => $openbasedir_path,
				"sslenabled" => $sslenabled,
				"ssl_redirect" => $ssl_redirect,
				"letsencrypt" => $letsencrypt,
				"http2" => $http2,
				"http3" => $http3,
				"hsts" => $hsts_maxage,
				"hsts_sub" => $hsts_sub,
				"hsts_preload" => $hsts_preload,
				"phpsettingid" => $phpsettingid,
				"speciallogfile" => $speciallogfile,
				"customerid" => $customer['customerid'],
				"id" => $id
			];
			Database::pexecute($stmt, $params, true, true);

			if ($result['aliasdomain'] != $aliasdomain && is_numeric($result['aliasdomain'])) {
				// trigger when domain id for alias destination has changed: both for old and new destination
				Domain::triggerLetsEncryptCSRForAliasDestinationDomain($result['aliasdomain'], $this->logger());
				Domain::triggerLetsEncryptCSRForAliasDestinationDomain($aliasdomain, $this->logger());
			}
			if ($result['wwwserveralias'] != $wwwserveralias || $result['letsencrypt'] != $letsencrypt) {
				// or when wwwserveralias or letsencrypt was changed
				Domain::triggerLetsEncryptCSRForAliasDestinationDomain($aliasdomain, $this->logger());
				if ((int)$aliasdomain === 0) {
					// in case the wwwserveralias is set on a main domain, $aliasdomain is 0
					// --> the call just above to triggerLetsEncryptCSRForAliasDestinationDomain
					// is a noop...let's repeat it with the domain id of the main domain
					Domain::triggerLetsEncryptCSRForAliasDestinationDomain($id, $this->logger());
				}
			}

			// check whether LE has been disabled, so we remove the certificate
			if ($letsencrypt == '0' && $result['letsencrypt'] == '1') {
				$del_stmt = Database::prepare("
						DELETE FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid` = :id
					");
				Database::pexecute($del_stmt, [
					'id' => $id
				], true, true);
				// remove domain from acme.sh / lets encrypt if used
				Cronjob::inserttask(TaskId::DELETE_DOMAIN_SSL, $result['domain']);
			}

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			Cronjob::inserttask(TaskId::REBUILD_DNS);
			$idna_convert = new IdnaWrapper();
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] edited domain '" . $idna_convert->decode($result['domain']) . "'");
		}
		$result = $this->apiCall('SubDomains.get', [
			'id' => $id
		]);
		return $this->response($result);
	}

	/**
	 * lists all customer domain/subdomain entries
	 *
	 * @param bool $with_ips
	 *            optional, default true
	 * @param int $customerid
	 *            optional, admin-only, select (sub)domains of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select (sub)domains of a specific customer by loginname
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
		$with_ips = $this->getParam('with_ips', true, true);
		if ($this->isAdmin()) {
			// if we're an admin, list all subdomains of all the admins customers
			// or optionally for one specific customer identified by id or loginname
			$customerid = $this->getParam('customerid', true, 0);
			$loginname = $this->getParam('loginname', true, '');

			if (!empty($customerid) || !empty($loginname)) {
				$result = $this->apiCall('Customers.get', [
					'id' => $customerid,
					'loginname' => $loginname
				]);
				$custom_list_result = [
					$result
				];
			} else {
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
			}
			$customer_ids = [];
			foreach ($custom_list_result as $customer) {
				$customer_ids[] = $customer['customerid'];
			}
			if (empty($customer_ids)) {
				throw new Exception("Required resource unsatisfied.", 405);
			}

			$select_fields = [
				'`d`.*'
			];
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'domains')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$customer_ids = [
				$this->getUserDetail('customerid')
			];

			$select_fields = [
				'`d`.`id`',
				'`d`.`customerid`',
				'`d`.`domain`',
				'`d`.`domain_ace`',
				'`d`.`documentroot`',
				'`d`.`isbinddomain`',
				'`d`.`isemaildomain`',
				'`d`.`caneditdomain`',
				'`d`.`iswildcarddomain`',
				'`d`.`parentdomainid`',
				'`d`.`letsencrypt`',
				'`d`.`registration_date`',
				'`d`.`termination_date`',
				'`d`.`deactivated`',
				'`d`.`email_only`',
			];
		}

		$query_fields = [];

		// prepare select statement
		$domains_stmt = Database::prepare("
			SELECT " . implode(",", $select_fields) . ", IF(`d`.`parentdomainid` > 0, `pd`.`domain_ace`, `d`.`domain_ace`) AS `parentdomainname`, `ad`.`id` AS `aliasdomainid`, `ad`.`domain` AS `aliasdomain`, `da`.`id` AS `domainaliasid`, `da`.`domain` AS `domainalias`
			FROM `" . TABLE_PANEL_DOMAINS . "` `d`
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` `ad` ON `d`.`aliasdomain`=`ad`.`id`
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` `da` ON `da`.`aliasdomain`=`d`.`id`
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` `pd` ON `pd`.`id`=`d`.`parentdomainid`
			WHERE `d`.`customerid` IN (" . implode(', ', $customer_ids) . ")
			" . $this->getSearchWhere($query_fields, true) . " GROUP BY `d`.`id` ORDER BY `parentdomainname` ASC, `d`.`parentdomainid` ASC " . $this->getOrderBy(true) . $this->getLimit());

		$result = [];
		Database::pexecute($domains_stmt, $query_fields, true, true);
		while ($row = $domains_stmt->fetch(PDO::FETCH_ASSOC)) {
			$row['ipsandports'] = [];
			if ($with_ips) {
				$row['ipsandports'] = $this->getIpsForDomain($row['id']);
			}
			$row['domain_hascert'] = $this->getHasCertValueForDomain((int)$row['id'], (int)$row['parentdomainid']);
			$result[] = $row;
		}
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * get ips connected to given domain as array
	 *
	 * @param number $domain_id
	 * @param bool $ssl_only
	 *            optional, return only ssl enabled ip's, default false
	 * @return array
	 */
	private function getIpsForDomain($domain_id = 0, $ssl_only = false)
	{
		$fields = '`ips`.ip, `ips`.port, `ips`.ssl';
		if ($this->isAdmin()) {
			$fields = '`ips`.*';
		}
		$resultips_stmt = Database::prepare("
			SELECT " . $fields . " FROM `" . TABLE_DOMAINTOIP . "` AS `dti`, `" . TABLE_PANEL_IPSANDPORTS . "` AS `ips`
			WHERE `dti`.`id_ipandports` = `ips`.`id` AND `dti`.`id_domain` = :domainid " . ($ssl_only ? " AND `ips`.`ssl` = '1'" : ""));

		Database::pexecute($resultips_stmt, [
			'domainid' => $domain_id
		]);

		$ipandports = [];
		while ($rowip = $resultips_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (filter_var($rowip['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$rowip['is_ipv6'] = true;
			}
			$ipandports[] = $rowip;
		}

		return $ipandports;
	}

	/**
	 * returns the total number of accessible subdomain entries
	 *
	 * @param int $customerid
	 *            optional, admin-only, select (sub)domains of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select (sub)domains of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin()) {
			// if we're an admin, list all databases of all the admins customers
			// or optionally for one specific customer identified by id or loginname
			$customerid = $this->getParam('customerid', true, 0);
			$loginname = $this->getParam('loginname', true, '');

			if (!empty($customerid) || !empty($loginname)) {
				$result = $this->apiCall('Customers.get', [
					'id' => $customerid,
					'loginname' => $loginname
				]);
				$custom_list_result = [
					$result
				];
			} else {
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
			}
			$customer_ids = [];
			foreach ($custom_list_result as $customer) {
				$customer_ids[] = $customer['customerid'];
			}
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'domains')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$customer_ids = [
				$this->getUserDetail('customerid')
			];
		}

		if (!empty($customer_ids)) {
			$query_fields = [];
			// prepare select statement
			$domains_stmt = Database::prepare("
				SELECT COUNT(*) as num_subdom
				FROM `" . TABLE_PANEL_DOMAINS . "` `d`
				WHERE `d`.`customerid` IN (" . implode(', ', $customer_ids) . ")
			" . $this->getSearchWhere($query_fields, true));
			$result = Database::pexecute_first($domains_stmt, $query_fields, true, true);
			if ($result) {
				return $this->response($result['num_subdom']);
			}
		}
		return $this->response(0);
	}

	/**
	 * delete a subdomain by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain-id
	 * @param string $domainname
	 *            optional, the domainname
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'domains')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];

		// get needed customer info to reduce the subdomain-usage-counter by one
		$customer = $this->getCustomerData();

		if (!$this->isAdmin() && $result['caneditdomain'] == 0) {
			throw new Exception("You cannot edit this resource", 405);
		}

		if ($result['isemaildomain'] == '1') {
			// check for e-mail addresses
			$emails_stmt = Database::prepare("
				SELECT COUNT(`id`) AS `count` FROM `" . TABLE_MAIL_VIRTUAL . "`
				WHERE `customerid` = :customerid AND `domainid` = :domainid
			");
			$emails = Database::pexecute_first($emails_stmt, [
				"customerid" => $customer['customerid'],
				"domainid" => $id
			], true, true);

			if ($emails['count'] != '0') {
				Response::standardError('domains_cantdeletedomainwithemail', '', true);
			}
		}

		if ((int)$result['aliasdomain'] !== 0) {
			Domain::triggerLetsEncryptCSRForAliasDestinationDomain($result['aliasdomain'], $this->logger());
		}

		// delete domain from table
		$stmt = Database::prepare("
			DELETE FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `customerid` = :customerid AND `id` = :id
		");
		Database::pexecute($stmt, [
			"customerid" => $customer['customerid'],
			"id" => $id
		], true, true);

		// remove connections to ips and domainredirects
		$del_stmt = Database::prepare("
			DELETE FROM `" . TABLE_DOMAINTOIP . "`
			WHERE `id_domain` = :domainid
		");
		Database::pexecute($del_stmt, [
			'domainid' => $id
		], true, true);

		// remove redirect-codes
		$del_stmt = Database::prepare("
			DELETE FROM `" . TABLE_PANEL_DOMAINREDIRECTS . "`
			WHERE `did` = :domainid
		");
		Database::pexecute($del_stmt, [
			'domainid' => $id
		], true, true);

		// remove certificate from domain_ssl_settings, fixes #1596
		$del_stmt = Database::prepare("
			DELETE FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "`
			WHERE `domainid` = :domainid
		");
		Database::pexecute($del_stmt, [
			'domainid' => $id
		], true, true);

		// remove possible existing DNS entries
		$del_stmt = Database::prepare("
			DELETE FROM `" . TABLE_DOMAIN_DNS . "`
			WHERE `domain_id` = :domainid
		");
		Database::pexecute($del_stmt, [
			'domainid' => $id
		], true, true);

		Cronjob::inserttask(TaskId::REBUILD_VHOST);
		// Using nameserver, insert a task which rebuilds the server config
		Cronjob::inserttask(TaskId::REBUILD_DNS);
		// remove domains DNS from powerDNS if used, #581
		Cronjob::inserttask(TaskId::DELETE_DOMAIN_PDNS, $result['domain']);
		// remove domain from acme.sh / lets encrypt if used
		Cronjob::inserttask(TaskId::DELETE_DOMAIN_SSL, $result['domain']);

		// reduce subdomain-usage-counter
		Customers::decreaseUsage($customer['customerid'], 'subdomains_used');

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_WARNING, "[API] deleted subdomain '" . $result['domain'] . "'");
		return $this->response($result);
	}
}
