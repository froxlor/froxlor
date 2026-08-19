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

namespace Froxlor\System;

class IPTools
{

	/**
	 * Converts CIDR to a netmask address
	 *
	 * @thx to https://stackoverflow.com/a/5711080/3020926
	 * @param string $cidr
	 *
	 * @return string
	 */
	public static function cidr2NetmaskAddr(string $cidr): string
	{
		$ta = substr($cidr, strpos($cidr, '/') + 1) * 1;
		$netmask = str_split(str_pad(str_pad('', $ta, '1'), 32, '0'), 8);

		foreach ($netmask as &$element) {
			$element = bindec($element);
		}

		return implode('.', $netmask);
	}

	/**
	 * Checks whether the given $ip is in range of given ip/cidr range
	 *
	 * @param array $ip_cidr 0 => ip, 1 => netmask in decimal, e.g. [0 => '123.123.123.123', 1 => 24]
	 * @param string $ip ip-address to check
	 *
	 * @return bool
	 */
	public static function ip_in_range(array $ip_cidr, string $ip): bool
	{
		$netip = $ip_cidr[0];
		if (self::is_ipv6($netip)) {
			return self::ipv6_in_range($ip_cidr, $ip);
		}
		$netmask = $ip_cidr[1];
		// defense in depth: an out-of-range netmask must never be treated as a
		// wildcard match - e.g. netmask 12345 underflows pow(2, 32 - $netmask) to a
		// wildcard of ~0, so ~$wildcard_decimal becomes 0 and matches every address
		if (!is_numeric($netmask) || $netmask < 1 || $netmask > 32) {
			return false;
		}
		$range_decimal = ip2long($netip);
		$ip_decimal = ip2long($ip);
		$wildcard_decimal = pow(2, (32 - $netmask)) - 1;
		$netmask_decimal = ~$wildcard_decimal;
		return (($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal));
	}

	/**
	 * Checks if an $address (IP) is IPv6
	 *
	 * @param string $address
	 *
	 * @return string|bool ip address on success, false on failure
	 */
	public static function is_ipv6(string $address)
	{
		return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
	}

	/**
	 * Checks whether the given ipv6 $ip is in range of given ip/cidr range
	 *
	 * @param array $ip_cidr 0 => ip, 1 => netmask in decimal, e.g. [0 => '123:123::1', 1 => 64]
	 * @param string $ip ip-address to check
	 *
	 * @return bool
	 */
	private static function ipv6_in_range(array $ip_cidr, string $ip): bool
	{
		$in_range = false;

		// defense in depth: reject an out-of-range prefix length up front instead of
		// letting it reach gmp_init()/inet6_prefix_to_mask(), which throws/uncaughtly
		// errors on invalid input rather than failing closed with a clean false
		if (!is_numeric($ip_cidr[1]) || $ip_cidr[1] < 1 || $ip_cidr[1] > 128) {
			return false;
		}

		$size = 128 - $ip_cidr[1];
		if ($size == 0) {
			return inet_ntop(inet_pton($ip_cidr[0])) == inet_ntop(inet_pton($ip));
		}
		$addr = gmp_init('0x' . str_replace(':', '', self::inet6_expand($ip_cidr[0])));
		$mask = gmp_init('0x' . str_replace(':', '', self::inet6_expand(self::inet6_prefix_to_mask($ip_cidr[1]))));
		$prefix = gmp_and($addr, $mask);
		$start = gmp_strval(gmp_add($prefix, '0x1'), 16);
		$end = '0b';
		for ($i = 0; $i < $size; $i++) {
			$end .= '1';
		}
		$end = gmp_strval(gmp_add($prefix, gmp_init($end)), 16);
		$start_result = '';
		for ($i = 0; $i < 8; $i++) {
			$start_result .= substr($start, $i * 4, 4);
			if ($i != 7) {
				$start_result .= ':';
			}
		}
		$end_result = '';
		for ($i = 0; $i < 8; $i++) {
			$end_result .= substr($end, $i * 4, 4);
			if ($i != 7) {
				$end_result .= ':';
			}
		}

		$first = self::ip2long6($start_result);
		$last = self::ip2long6($end_result);
		$ip = self::ip2long6($ip);

		$in_range = ($ip >= $first && $ip <= $last);
		return $in_range;
	}

	/**
	 * @param string $addr
	 * @return false|string
	 */
	private static function inet6_expand(string $addr)
	{
		// Check if there are segments missing, insert if necessary
		if (strpos($addr, '::') !== false) {
			$part = explode('::', $addr);
			$part[0] = explode(':', $part[0]);
			$part[1] = explode(':', $part[1]);
			$missing = [];
			for ($i = 0; $i < (8 - (count($part[0]) + count($part[1]))); $i++) {
				$missing[] = '0000';
			}
			$missing = array_merge($part[0], $missing);
			$part = array_merge($missing, $part[1]);
		} else {
			$part = explode(":", $addr);
		}
		// Pad each segment until it has 4 digits
		foreach ($part as &$p) {
			while (strlen($p) < 4) {
				$p = '0' . $p;
			}
		}
		unset($p);
		// Join segments
		$result = implode(':', $part);
		// Quick check to make sure the length is as expected
		if (strlen($result) == 39) {
			return $result;
		} else {
			return false;
		}
	}

	/**
	 * @param int $prefix
	 * @return false|string
	 */
	private static function inet6_prefix_to_mask(int $prefix)
	{
		/* Make sure the prefix is a number between 1 and 127 (inclusive) */
		if ($prefix < 0 || $prefix > 128) {
			return false;
		}
		$mask = '0b';
		$mask .= str_repeat('1', $prefix);
		for ($i = strlen($mask) - 2; $i < 128; $i++) {
			$mask .= '0';
		}
		$mask = gmp_strval(gmp_init($mask), 16);
		$result = '';
		for ($i = 0; $i < 8; $i++) {
			$result .= substr($mask, $i * 4, 4);
			if ($i != 7) {
				$result .= ':';
			}
		} // for
		return inet_ntop(inet_pton($result));
	}

	/**
	 * @param string $ip
	 * @return string
	 */
	private static function ip2long6(string $ip): string
	{
		$ip_n = inet_pton($ip);
		$bits = 15; // 16 x 8 bit = 128bit
		$ipv6long = '';
		while ($bits >= 0) {
			$bin = sprintf("%08b", (ord($ip_n[$bits])));
			$ipv6long = $bin . $ipv6long;
			$bits--;
		}
		return gmp_strval(gmp_init($ipv6long, 2), 10);
	}
}
