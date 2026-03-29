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
use Froxlor\Dns\Dns;
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class DomainZones extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new dns zone for a given domain by id or domainname
	 *
	 * @param int $id
	 *            optional domain id
	 * @param string $domainname
	 *            optional domain name
	 * @param string $record
	 *            optional, default empty
	 * @param string $type
	 *            optional, zone-entry type (A, AAAA, TXT, etc.), default 'A'
	 * @param int $prio
	 *            optional, priority, default empty
	 * @param string $content
	 *            optional, default empty
	 * @param int $ttl
	 *            optional, default 18000
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if (Settings::Get('system.dnsenabled') != '1') {
			throw new Exception("DNS service not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && $this->getUserDetail('dnsenabled') != '1') {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		// get requested domain
		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];

		// parameters
		$record = $this->getParam('record', true, null);
		$type = $this->getParam('type', true, 'A');
		$prio = $this->getParam('prio', true, null);
		$content = $this->getParam('content', true, null);
		$ttl = $this->getParam('ttl', true, 18000);

		if ($result['parentdomainid'] != '0') {
			throw new Exception("DNS zones can only be generated for the main domain, not for subdomains", 406);
		}

		if ($result['subisbinddomain'] != '1') {
			Response::standardError('dns_domain_nodns', '', true);
		}

		$idna_convert = new IdnaWrapper();
		$domain = $idna_convert->encode($result['domain']);

		// select all entries
		$sel_stmt = Database::prepare("SELECT * FROM `" . TABLE_DOMAIN_DNS . "` WHERE domain_id = :did");
		Database::pexecute($sel_stmt, [
			'did' => $id
		], true, true);
		$dom_entries = $sel_stmt->fetchAll(PDO::FETCH_ASSOC);

		// validation
		$errors = [];
		if (empty(trim($record))) {
			$record = "@";
		}

		$record = trim(strtolower($record));

		if ($record != '@' && $record != '*') {
			// validate record
			if (strpos($record, '--') !== false) {
				$errors[] = lng('error.domain_nopunycode');
			} else {
				// check for wildcard-record
				$add_wildcard_again = false;
				if (substr($record, 0, 2) == '*.') {
					$record = substr($record, 2);
					$add_wildcard_again = true;
				}
				// convert entry
				$record = $idna_convert->encode($record);

				if ($add_wildcard_again) {
					$record = '*.' . $record;
				}

				if (strlen($record) > 63) {
					$errors[] = lng('error.dns_record_toolong');
				}
			}
		}

		// TODO regex validate content for invalid characters

		if ($ttl <= 0) {
			$ttl = 18000;
		}

		$content = trim($content);
		if (empty($content)) {
			$errors[] = lng('error.dns_content_empty');
		}

		if ($type != 'CNAME') {
			// check whether there is a CNAME-record for the same resource
			foreach ($dom_entries as $existing_entries) {
				if ($existing_entries['type'] == 'CNAME' && $existing_entries['record'] == $record) {
					$errors[] = lng('error.dns_other_nomorerr');
					break;
				}
			}
		}

		// types
		if ($type == 'A' && filter_var($content, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
			$errors[] = lng('error.dns_arec_noipv4');
		} elseif ($type == 'AAAA' && filter_var($content, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
			$errors[] = lng('error.dns_aaaarec_noipv6');
		} elseif ($type == 'CAA' && !empty($content)) {
			$re = '/(?\'critical\'\d+)\h*(?\'type\'iodef|issue|issuewild)\h*(?\'value\'(?\'issuevalue\'"(?\'domain\'(?=.{3,128}$)(?>(?>[a-zA-Z0-9]+[a-zA-Z0-9-]*[a-zA-Z0-9]+|[a-zA-Z0-9]+)\.)*(?>[a-zA-Z]{2,}|[a-zA-Z0-9]{2,}\.[a-zA-Z]{2,}))[;\h]*(?\'parameters\'(?>[a-zA-Z0-9]{1,60}=[a-zA-Z0-9:\.\/\-]{1,60}\h*)+)?")|(?\'iodefvalue\'"(?\'url\'(mailto:.*|http:\/\/.*|https:\/\/.*))"))/';
			preg_match($re, $content, $matches);

			if (empty($matches)) {
				$errors[] = lng('error.dns_content_invalid');
			} elseif (($matches['type'] == 'issue' || $matches['type'] == 'issuewild') && !Validate::validateDomain($matches['domain'])) {
				$errors[] = lng('error.dns_content_invalid');
			} elseif ($matches['type'] == 'iodef' && !Validate::validateUrl($matches['url'])) {
				$errors[] = lng('error.dns_content_invalid');
			} else {
				$content = $matches[0];
			}
		} elseif ($type == 'CNAME' || $type == 'DNAME') {
			// check for trailing dot
			if (substr($content, -1) == '.') {
				// remove it for checks
				$content = substr($content, 0, -1);
			} else {
				// add domain name
				$content .= '.' . $domain;
			}
			if (!Validate::validateDomain($content, true)) {
				$errors[] = lng('error.dns_cname_invaliddom');
			} else {
				// check whether there are RR-records for the same resource
				foreach ($dom_entries as $existing_entries) {
					if ($existing_entries['record'] == $record) {
						$errors[] = lng('error.dns_cname_nomorerr');
						break;
					}
				}
				// check www-alias setting
				if ($result['wwwserveralias'] == '1' && $result['iswildcarddomain'] == '0' && $record == 'www') {
					$errors[] = lng('error.no_wwwcnamae_ifwwwalias');
				}
			}
			// append trailing dot (again)
			$content .= '.';
		} elseif ($type == 'LOC' && !empty($content)) {
			if (!Validate::validateDnsLoc($content)) {
				$errors[] = lng('error.dns_loc_invalid');
			}
		} elseif ($type == 'MX') {
			if ($prio === null || $prio < 0) {
				$errors[] = lng('error.dns_mx_prioempty');
			}
			// check for trailing dot
			if (substr($content, -1) == '.') {
				// remove it for checks
				$content = substr($content, 0, -1);
			}
			if (!empty($content) && !Validate::validateDomain($content)) {
				$errors[] = lng('error.dns_mx_needdom');
			} else {
				// check whether there is a CNAME-record for the same resource
				foreach ($dom_entries as $existing_entries) {
					$fqdn = $existing_entries['record'] . '.' . $domain;
					if ($existing_entries['type'] == 'CNAME' && $fqdn == $content) {
						$errors[] = lng('error.dns_mx_noalias');
						break;
					}
				}
			}
			// append trailing dot (again)
			$content .= '.';
			// if content is only ".", the prio needs to be 0 which results in a "null mx" entry
			if ($content == '.' && $prio != 0) {
				$prio = 0;
			}
		} elseif ($type == 'NAPTR' && !empty($content)) {
			if (!Validate::validateDnsNaptr($content)) {
				$errors[] = lng('error.dns_naptr_invalid');
			}
		} elseif ($type == 'NS') {
			// check for trailing dot
			if (substr($content, -1) == '.') {
				// remove it for checks
				$content = substr($content, 0, -1);
			}
			if (!Validate::validateDomain($content)) {
				$errors[] = lng('error.dns_ns_invaliddom');
			}
			// append trailing dot (again)
			$content .= '.';
		} elseif ($type == 'RP' && !empty($content)) {
			if (!Validate::validateDnsRp($content)) {
				$errors[] = lng('error.dns_rp_invalid');
			}
		} elseif ($type == 'SRV') {
			if ($prio === null || $prio < 0) {
				$errors[] = lng('error.dns_srv_prioempty');
			}
			// check only last part of content, as it can look like:
			// _service._proto.name. TTL class SRV priority weight port target.
			$_split_content = explode(" ", $content);
			// SRV content must be [weight] [port] [target]
			if (count($_split_content) != 3) {
				$errors[] = lng('error.dns_srv_invalidcontent');
			}
			$target = trim($_split_content[count($_split_content) - 1]);
			if ($target != '.') {
				// check for trailing dot
				if (substr($target, -1) == '.') {
					// remove it for checks
					$target = substr($target, 0, -1);
				}
			}
			if ($target != '.' && !Validate::validateDomain($target, true)) {
				$errors[] = lng('error.dns_srv_needdom');
			} else {
				// check whether there is a CNAME-record for the same resource
				foreach ($dom_entries as $existing_entries) {
					$fqdn = $existing_entries['record'] . '.' . $domain;
					if ($existing_entries['type'] == 'CNAME' && $fqdn == $target) {
						$errors[] = lng('error.dns_srv_noalias');
						break;
					}
				}
			}
			// append trailing dot if there's none
			if (substr($content, -1) != '.') {
				$content .= '.';
			}
		} elseif ($type == 'SSHFP' && !empty($content)) {
			if (!Validate::validateDnsSshfp($content)) {
				$errors[] = lng('error.dns_sshfp_invalid');
			}
		} elseif ($type == 'TLSA' && !empty($content)) {
			if (!Validate::validateDnsTlsa($content)) {
				$errors[] = lng('error.dns_tlsa_invalid');
			}
		} elseif ($type == 'TXT' && !empty($content)) {
			// check that TXT content is enclosed in " "
			$content = Dns::encloseTXTContent($content);
		}

		$new_entry = [
			'record' => $record,
			'type' => $type,
			'prio' => (int)$prio,
			'content' => $content,
			'ttl' => (int)$ttl,
			'domain_id' => (int)$id
		];
		ksort($new_entry);

		// check for duplicate
		foreach ($dom_entries as $existing_entry) {
			// compare json-encoded string of array
			$check_entry = $existing_entry;
			// new entry has no ID yet
			unset($check_entry['id']);
			// sort by key
			ksort($check_entry);
			// format integer fields to real integer (as they are read as string from the DB)
			$check_entry['prio'] = (int)$check_entry['prio'];
			$check_entry['ttl'] = (int)$check_entry['ttl'];
			$check_entry['domain_id'] = (int)$check_entry['domain_id'];
			// encode both
			$check_entry = json_encode($check_entry);
			$new = json_encode($new_entry);
			// compare
			if ($check_entry === $new) {
				$errors[] = lng('error.dns_duplicate_entry');
				unset($check_entry);
				break;
			}
		}

		if (empty($errors)) {
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_DOMAIN_DNS . "` SET
				`record` = :record,
				`type` = :type,
				`prio` = :prio,
				`content` = :content,
				`ttl` = :ttl,
				`domain_id` = :domain_id
			");
			Database::pexecute($ins_stmt, $new_entry, true, true);
			$new_entry_id = Database::lastInsertId();

			// add temporary to the entries-array (no reread of DB necessary)
			$new_entry['id'] = $new_entry_id;
			$dom_entries[] = $new_entry;

			// re-generate bind configs
			Cronjob::inserttask(TaskId::REBUILD_DNS);

			$result = $this->apiCall('DomainZones.get', [
				'id' => $id
			]);
			return $this->response($result);
		}
		// return $errors
		throw new Exception(implode("\n", $errors), 406);
	}

	/**
	 * return a domain-dns entry by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain id
	 * @param string $domainname
	 *            optional, the domain name
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if (Settings::Get('system.dnsenabled') != '1') {
			throw new Exception("DNS service not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && $this->getUserDetail('dnsenabled') != '1') {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		// get requested domain
		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];

		if ($result['parentdomainid'] != '0') {
			throw new Exception("DNS zones can only be generated for the main domain, not for subdomains", 406);
		}

		if ($result['subisbinddomain'] != '1') {
			Response::standardError('dns_domain_nodns', '', true);
		}

		$zone = Dns::createDomainZone($id);
		$zonefile = (string)$zone;

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get dns-zone for '" . $result['domain'] . "'");
		return $this->response(explode("\n", $zonefile));
	}

	/**
	 * You cannot update a dns zone entry.
	 * You need to delete it and re-add it.
	 */
	public function update()
	{
		throw new Exception('You cannot update a dns zone entry. You need to delete it and re-add it.', 303);
	}

	/**
	 * List all entry records of a given domain by either id or domainname
	 *
	 * @param int $id
	 *            optional, the domain id
	 * @param string $domainname
	 *            optional, the domain name
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
	 * @return bool
	 * @throws Exception
	 */
	public function listing()
	{
		if (Settings::Get('system.dnsenabled') != '1') {
			throw new Exception("DNS service not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && $this->getUserDetail('dnsenabled') != '1') {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		// get requested domain
		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];
		$query_fields = [];
		$sel_stmt = Database::prepare("SELECT * FROM `" . TABLE_DOMAIN_DNS . "` WHERE `domain_id` = :did" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		$query_fields['did'] = $id;
		Database::pexecute($sel_stmt, $query_fields, true, true);
		$result = [];
		while ($row = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$result[] = $row;
		}
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of domainzone-entries for given domain
	 *
	 * @param int $id
	 *            optional, the domain id
	 * @param string $domainname
	 *            optional, the domain name
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if (Settings::Get('system.dnsenabled') != '1') {
			throw new Exception("DNS service not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && $this->getUserDetail('dnsenabled') != '1') {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		// get requested domain
		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];

		$query_fields = [];
		$sel_stmt = Database::prepare("SELECT COUNT(*) as num_dns FROM `" . TABLE_DOMAIN_DNS . "` WHERE `domain_id` = :did" . $this->getSearchWhere($query_fields, true));
		$params = array_merge(['did' => $id], $query_fields);
		$result = Database::pexecute_first($sel_stmt, $params, true, true);
		if ($result) {
			return $this->response($result['num_dns']);
		}
		return $this->response(0);
	}

	/**
	 * deletes a domain-dns entry by id
	 *
	 * @param int $entry_id
	 * @param int $id
	 *            optional, the domain id
	 * @param string $domainname
	 *            optional, the domain name
	 *
	 * @access admin, customer
	 * @return bool
	 * @throws Exception
	 */
	public function delete()
	{
		if (Settings::Get('system.dnsenabled') != '1') {
			throw new Exception("DNS service not enabled on this system", 405);
		}

		if ($this->isAdmin() == false && $this->getUserDetail('dnsenabled') != '1') {
			throw new Exception("You cannot access this resource", 405);
		}

		$entry_id = $this->getParam('entry_id');
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$domainname = $this->getParam('domainname', $dn_optional, '');

		// get requested domain
		$result = $this->apiCall('SubDomains.get', [
			'id' => $id,
			'domainname' => $domainname
		]);
		$id = $result['id'];

		$del_stmt = Database::prepare("DELETE FROM `" . TABLE_DOMAIN_DNS . "` WHERE `id` = :id AND `domain_id` = :did");
		Database::pexecute($del_stmt, [
			'id' => $entry_id,
			'did' => $id
		], true, true);
		if ($del_stmt->rowCount() > 0) {
			// re-generate bind configs
			Cronjob::inserttask(TaskId::REBUILD_DNS);
			return $this->response(true);
		}
		return $this->response(true, 304);
	}
}
