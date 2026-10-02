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

namespace Froxlor\Domain;

use Froxlor\Database\Database;
use PDO;

class IpAddr
{
	/**
	 * @return array
	 */
	public static function getIpAddresses(): array
	{
		$result_stmt = Database::query("
			SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` ORDER BY `ip` ASC, `port` ASC
		");

		$system_ipaddress_array = [];

		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (!isset($system_ipaddress_array[$row['ip']]) && !in_array($row['ip'], $system_ipaddress_array)) {
				$system_ipaddress_array[$row['ip']] = $row['ip'];
			}
		}

		return $system_ipaddress_array;
	}

	/**
	 * @return array
	 * @throws \Exception
	 */
	public static function getSslIpPortCombinations(): array
	{
		return [
				'' => lng('panel.none_value')
			] + self::getIpPortCombinations(true);
	}

	/**
	 * @param bool $ssl
	 * @return array
	 * @throws \Exception
	 */
	public static function getIpPortCombinations(bool $ssl = false): array
	{
		global $userinfo;

		$additional_conditions_params = [];
		$additional_conditions_array = [];

		if (!empty($userinfo) && $userinfo['ip'] != '-1') {
			$admin_ip_stmt = Database::prepare("
				SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `id` = IN (:ipid)
			");
			$myips = implode(",", json_decode($userinfo['ip'], true));
			Database::pexecute($admin_ip_stmt, [
				'ipid' => $myips
			]);
			$additional_conditions_array[] = "`ip` IN (:adminips)";
			$additional_conditions_params['adminips'] = $myips;
		}

		if ($ssl !== null) {
			$additional_conditions_array[] = "`ssl` = :ssl";
			$additional_conditions_params['ssl'] = ($ssl === true ? '1' : '0');
		}

		$additional_conditions = '';
		if (count($additional_conditions_array) > 0) {
			$additional_conditions = " WHERE " . implode(" AND ", $additional_conditions_array) . " ";
		}

		$result_stmt = Database::prepare("
			SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` " . $additional_conditions . " ORDER BY `ip` ASC, `port` ASC
		");

		Database::pexecute($result_stmt, $additional_conditions_params);
		$system_ipaddress_array = [];

		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (filter_var($row['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$row['ip'] = '[' . $row['ip'] . ']';
			}
			$system_ipaddress_array[$row['id']] = $row['ip'] . ':' . $row['port'];
		}

		return $system_ipaddress_array;
	}
}
