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
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;

/**
 * @since 0.10.0
 */
class EmailForwarders extends ApiCommand implements ResourceEntity
{

	/**
	 * add new email-forwarder entry for given email-address by either id or email-address
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to add the forwarder for
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param string $destination
	 *            email-address to add as forwarder
	 *
	 * @access admin,customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		if ($this->getUserDetail('email_forwarders_used') < $this->getUserDetail('email_forwarders') || $this->getUserDetail('email_forwarders') == '-1') {
			// parameter
			$id = $this->getParam('id', true, 0);
			$ea_optional = $id > 0;
			$emailaddr = $this->getParam('emailaddr', $ea_optional, '');
			$destination = $this->getParam('destination');

			// validation
			$idna_convert = new IdnaWrapper();
			$destination = $idna_convert->encode($destination);

			if (!empty($emailaddr)) {
				$idna_convert = new IdnaWrapper();
				$emailaddr = $idna_convert->encode($emailaddr);
			}

			$result = $this->apiCall('Emails.get', [
				'id' => $id,
				'emailaddr' => $emailaddr
			]);
			$id = $result['id'];

			// current destination array
			$result['destination_array'] = explode(' ', ($result['destination'] ?? ""));

			// prepare destination
			$destination = trim($destination);

			if (!Validate::validateEmail($destination)) {
				Response::standardError('destinationiswrong', $destination, true);
			} elseif ($destination == $result['email']) {
				Response::standardError('destinationalreadyexistasmail', $destination, true);
			} elseif (in_array($destination, $result['destination_array'])) {
				Response::standardError('destinationalreadyexist', $destination, true);
			}

			// get needed customer info to reduce the email-forwarder-counter by one
			$customer = $this->getCustomerData('email_forwarders');

			// add destination to address
			$result['destination'] .= ' ' . $destination;
			$stmt = Database::prepare("
				UPDATE `" . TABLE_MAIL_VIRTUAL . "` SET `destination` = :dest
				WHERE `customerid`= :cid AND `id`= :id
			");
			$params = [
				"dest" => FileDir::makeCorrectDestination($result['destination']),
				"cid" => $customer['customerid'],
				"id" => $id
			];
			Database::pexecute($stmt, $params, true, true);

			// update customer usage
			Customers::increaseUsage($customer['customerid'], 'email_forwarders_used');

			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added email forwarder for '" . $result['email_full'] . "'");

			$result = $this->apiCall('Emails.get', [
				'emailaddr' => $result['email_full']
			]);
			return $this->response($result);
		}
		throw new Exception("No more resources available", 406);
	}

	/**
	 * You cannot directly get an email forwarder.
	 * Try EmailForwarders.listing()
	 */
	public function get()
	{
		throw new Exception('You cannot directly get an email forwarder. Try EmailForwarders.listing()', 303);
	}

	/**
	 * You cannot update an email forwarder.
	 * You need to delete the entry and create a new one.
	 */
	public function update()
	{
		throw new Exception('You cannot update an email forwarder. You need to delete the entry and create a new one.', 303);
	}

	/**
	 * List email forwarders for a given email address
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to delete the forwarder from
	 * @param int $customerid
	 *            optional, admin-only, the customer-id
	 * @param string $loginname
	 *            optional, admin-only, the loginname
	 *
	 * @access admin,customer
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		$result['destination'] = explode(' ', $result['destination']);
		$destination = [];
		foreach ($result['destination'] as $index => $address) {
			$destination[] = [
				'id' => $index,
				'address' => $address
			];
		}

		return $this->response([
			'count' => count($destination),
			'list' => $destination
		]);
	}

	/**
	 * count email forwarders for a given email address
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to delete the forwarder from
	 * @param int $customerid
	 *            optional, admin-only, the customer-id
	 * @param string $loginname
	 *            optional, admin-only, the loginname
	 *
	 * @access admin,customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		$result['destination'] = explode(' ', $result['destination']);

		return $this->response(count($result['destination']));
	}

	/**
	 * delete email-forwarder entry for given email-address by either id or email-address and forwarder-id
	 *
	 * @param int $id
	 *            optional, the email-address-id
	 * @param string $emailaddr
	 *            optional, the email-address to delete the forwarder from
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param int $forwarderid
	 *            id of the forwarder to delete
	 *
	 * @access admin,customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'email')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// parameter
		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$emailaddr = $this->getParam('emailaddr', $ea_optional, '');
		$forwarderid = $this->getParam('forwarderid');

		// validation
		$result = $this->apiCall('Emails.get', [
			'id' => $id,
			'emailaddr' => $emailaddr
		]);
		$id = $result['id'];

		$result['destination'] = explode(' ', $result['destination']);
		if (isset($result['destination'][$forwarderid]) && $result['email'] != $result['destination'][$forwarderid]) {
			// get needed customer info to reduce the email-forwarder-counter by one
			$customer = $this->getCustomerData();

			// unset it from array
			unset($result['destination'][$forwarderid]);
			// rebuild destination-string
			$result['destination'] = implode(' ', $result['destination']);
			// update in DB
			$stmt = Database::prepare("
				UPDATE `" . TABLE_MAIL_VIRTUAL . "` SET `destination` = :dest
				WHERE `customerid`= :cid AND `id`= :id
			");
			$params = [
				"dest" => FileDir::makeCorrectDestination($result['destination']),
				"cid" => $customer['customerid'],
				"id" => $id
			];
			Database::pexecute($stmt, $params, true, true);

			// update customer usage
			Customers::decreaseUsage($customer['customerid'], 'email_forwarders_used');

			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] deleted email forwarder for '" . $result['email_full'] . "'");

			$result = $this->apiCall('Emails.get', [
				'emailaddr' => $result['email_full']
			]);
			return $this->response($result);
		}
		throw new Exception("Unknown forwarder id", 404);
	}
}
