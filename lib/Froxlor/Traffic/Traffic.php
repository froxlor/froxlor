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

namespace Froxlor\Traffic;

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Traffic as TrafficAPI;
use Froxlor\Database\Database;
use Froxlor\UI\Collection;

class Traffic
{
	/**
	 * @param array $userinfo
	 * @param ?string $range
	 * @return array
	 * @throws \Exception
	 */
	public static function getCustomerStats(array $userinfo, ?string $range = null, bool $overview = false): array
	{
		$trafficCollectionObj = (new Collection(TrafficAPI::class, $userinfo,
			self::getParamsByRange($range, ['customer_traffic' => true])));
		if (($userinfo['adminsession'] ?? 0) == 1) {
			$trafficCollectionObj->has('customer', Customers::class, 'customerid', 'customerid');
		}
		$trafficCollection = $trafficCollectionObj->get();

		// build stats for each user
		$users = [];
		$years = [];
		$months = [];
		$days = [];
		foreach ($trafficCollection['data']['list'] as $item) {
			$http = $item['http'];
			$ftp = ($item['ftp_up'] + $item['ftp_down']);
			$mail = $item['mail'];
			$total = $http + $ftp + $mail;

			if (empty($users[$item['customerid']])) {
				$users[$item['customerid']] = [
					'total' => 0.00,
					'http' => 0.00,
					'ftp' => 0.00,
					'mail' => 0.00,
				];
			}

			// per user total
			if (($userinfo['adminsession'] ?? 0) == 1) {
				$users[$item['customerid']]['loginname'] = $item['customer']['loginname'];
			}
			$users[$item['customerid']]['total'] += $total;
			$users[$item['customerid']]['http'] += $http;
			$users[$item['customerid']]['ftp'] += $ftp;
			$users[$item['customerid']]['mail'] += $mail;
			if (!$overview) {
				if (empty($years[$item['year']])) {
					$years[$item['year']] = [
						'total' => 0.00,
						'http' => 0.00,
						'ftp' => 0.00,
						'mail' => 0.00,
					];
				}
				if (empty($months[$item['month'] . '/' . $item['year']])) {
					$months[$item['month'] . '/' . $item['year']] = [
						'total' => 0.00,
						'http' => 0.00,
						'ftp' => 0.00,
						'mail' => 0.00,
					];
				}
				if (empty($days[$item['day'] . '.' . $item['month'] . '.' . $item['year']])) {
					$days[$item['day'] . '.' . $item['month'] . '.' . $item['year']] = [
						'total' => 0.00,
						'http' => 0.00,
						'ftp' => 0.00,
						'mail' => 0.00,
					];
				}
				// per year
				$years[$item['year']]['total'] += $total;
				$years[$item['year']]['http'] += $http;
				$years[$item['year']]['ftp'] += $ftp;
				$years[$item['year']]['mail'] += $mail;
				// per month
				$months[$item['month'] . '/' . $item['year']]['total'] += $total;
				$months[$item['month'] . '/' . $item['year']]['http'] += $http;
				$months[$item['month'] . '/' . $item['year']]['ftp'] += $ftp;
				$months[$item['month'] . '/' . $item['year']]['mail'] += $mail;
				// per day
				$days[$item['day'] . '.' . $item['month'] . '.' . $item['year']]['total'] += $total;
				$days[$item['day'] . '.' . $item['month'] . '.' . $item['year']]['http'] += $http;
				$days[$item['day'] . '.' . $item['month'] . '.' . $item['year']]['ftp'] += $ftp;
				$days[$item['day'] . '.' . $item['month'] . '.' . $item['year']]['mail'] += $mail;
			}
		}

		// calculate overview for given range from users
		$metrics = [
			'total' => 0.00,
			'http' => 0.00,
			'ftp' => 0.00,
			'mail' => 0.00,
		];
		foreach ($users as $user) {
			$metrics['total'] += $user['total'];
			$metrics['http'] += $user['http'];
			$metrics['ftp'] += $user['ftp'];
			$metrics['mail'] += $user['mail'];
		}

		$years_avail = [];
		if (!$overview) {
			// get all possible years for filter
			$sel_stmt = Database::prepare("SELECT DISTINCT year FROM `" . TABLE_PANEL_TRAFFIC . "` WHERE 1 ORDER BY `year` DESC");
			Database::pexecute($sel_stmt);
			$years_avail = $sel_stmt->fetchAll(\PDO::FETCH_ASSOC);
		}

		// sort users by total traffic
		uasort($users, function ($user_a, $user_b) {
			if ($user_a['total'] == $user_b['total']) {
				return 0;
			}
			return ($user_a['total'] < $user_b['total']) ? 1 : -1;
		});

		return [
			'metrics' => $metrics,
			'users' => $users,
			'years' => $years,
			'months' => $months,
			'days' => $days,
			'range' => $range,
			'years_avail' => $years_avail
		];
	}

	/**
	 * @param ?string $range
	 * @param array $params
	 * @return array
	 * @throws \Exception
	 */
	private static function getParamsByRange(?string $range = null, array $params = []): array
	{
		$dateParams = [];

		if (preg_match("/year:([0-9]{4})/", $range, $matches)) {
			$dateParams = ['year' => $matches[1]];
		} elseif (preg_match("/months:([1-9]([0-9]+)?)/", $range, $matches)) {
			$dt = (new \DateTime())->sub(new \DateInterval('P' . $matches[1] . 'M'))->format('U');
			$dateParams = ['date_from' => $dt];
		} elseif (preg_match("/days:([1-9]([0-9]+)?)/", $range, $matches)) {
			$dt = (new \DateTime())->sub(new \DateInterval('P' . $matches[1] . 'D'))->format('U');
			$dateParams = ['date_from' => $dt];
		} elseif (preg_match("/hours:([1-9]([0-9]+)?)/", $range, $matches)) {
			$dt = (new \DateTime())->sub(new \DateInterval('PT' . $matches[1] . 'H'))->format('U');
			$dateParams = ['date_from' => $dt];
		} elseif (preg_match("/currentmonth/", $range, $matches)) {
			$dt = (new \DateTime("first day of this month"))->setTime(0, 0, 0, 1)->format('U');
			$dateParams = ['date_from' => $dt];
		} elseif (preg_match("/currentyear/", $range, $matches)) {
			$dt = \DateTime::createFromFormat("d.m.Y", '01.01.' . date('Y'))->setTime(0, 0, 0, 1)->format('U');
			$dateParams = ['date_from' => $dt];
		}

		return array_merge($dateParams, $params);
	}
}
