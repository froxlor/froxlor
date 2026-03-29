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

namespace Froxlor\Validate;

use Exception;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\System\IPTools;
use Froxlor\UI\Response;

class Validate
{

	const REGEX_DIR = '/^|(\/[\w-]+)+$/';

	const REGEX_PORT = '/^(([1-9])|([1-9][0-9])|([1-9][0-9][0-9])|([1-9][0-9][0-9][0-9])|([1-5][0-9][0-9][0-9][0-9])|(6[0-4][0-9][0-9][0-9])|(65[0-4][0-9][0-9])|(655[0-2][0-9])|(6553[0-5]))$/Di';

	const REGEX_CONF_TEXT = '/^[^\0]*$/';

	const REGEX_DESC_TEXT = '/^[^\0\r\n<>]*$/';

	const REGEX_YYYY_MM_DD = '/^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$/';

	/**
	 * Validates the given string by matching against the pattern, prints an error on failure and exits.
	 * If the default pattern is used and the string does not match, we try to replace the 'bad' values and log the action.
	 *
	 * @param string $str the string to be tested (user input)
	 * @param string $fieldname to be used in error messages
	 * @param string $pattern the regular expression to be used for testing
	 * @param string|array $lng id for the error
	 * @param string|array $emptydefault fallback value
	 * @param bool $throw_exception whether to display error or throw an exception, default false
	 *
	 * @return string|void the clean string or error
	 * @throws Exception
	 */
	public static function validate(
		string $str,
		string $fieldname,
		string $pattern = '',
		       $lng = '',
		       $emptydefault = [],
		bool   $throw_exception = false
	)
	{
		if (!is_array($emptydefault)) {
			$emptydefault_array = [
				$emptydefault
			];
			unset($emptydefault);
			$emptydefault = $emptydefault_array;
			unset($emptydefault_array);
		}

		// Check if the $str is one of the values which represent the default for an 'empty' value
		if (is_array($emptydefault) && !empty($emptydefault) && in_array($str, $emptydefault)) {
			return $str;
		}

		if ($pattern == '') {
			$pattern = '/^[^\r\n\t\f\0]*$/D';

			if (!preg_match($pattern, $str)) {
				// Allows letters a-z, digits, space (\\040), hyphen (\\-), underscore (\\_) and backslash (\\\\),
				// everything else is removed from the string.
				$allowed = "/[^a-z0-9\\040\\.\\-\\_\\\\]/i";
				$str = preg_replace($allowed, "", $str);
				$log = FroxlorLogger::getInstanceOf();
				$log->logAction(FroxlorLogger::USR_ACTION, LOG_WARNING, "cleaned bad formatted string (" . $str . ")");
			}
		}

		if (preg_match($pattern, $str)) {
			return $str;
		}

		if ($lng == '') {
			$lng = 'stringformaterror';
		}

		Response::standardError($lng, $fieldname, $throw_exception);
	}

	/**
	 * Checks whether it is a valid ip
	 *
	 * @param string $ip ip-address to check
	 * @param bool $return_bool whether to return bool or call \Froxlor\UI\Response::standard_error()
	 * @param string $lng index for error-message (if $return_bool is false)
	 * @param bool $allow_localhost whether to allow 127.0.0.1
	 * @param bool $allow_priv whether to allow private network addresses
	 * @param bool $allow_cidr whether to allow CIDR values e.g. 10.10.10.10/16
	 * @param bool $cidr_as_netmask whether to format CIDR notation to netmask notation
	 * @param bool $throw_exception whether to throw an exception on failure
	 *
	 * @return string|bool|void ip address on success, false on failure (or nothing if error is displayed)
	 * @throws Exception
	 */
	public static function validate_ip2(
		string $ip,
		bool   $return_bool = false,
		string $lng = 'invalidip',
		bool   $allow_localhost = false,
		bool   $allow_priv = false,
		bool   $allow_cidr = false,
		bool   $cidr_as_netmask = false,
		bool   $throw_exception = false
	)
	{
		$cidr = "";
		if ($allow_cidr) {
			$org_ip = $ip;
			$ip_cidr = explode("/", $ip);
			if (count($ip_cidr) === 2) {
				$cidr_range_max = 32;
				if (IPTools::is_ipv6($ip_cidr[0])) {
					$cidr_range_max = 128;
				}
				if (strlen($ip_cidr[1]) <= 3 && in_array((int)$ip_cidr[1], array_values(range(1, $cidr_range_max)),
						true) === false) {
					if ($return_bool) {
						return false;
					}
					Response::standardError($lng, $ip, $throw_exception);
				}
				if ($cidr_as_netmask && IPTools::is_ipv6($ip_cidr[0])) {
					// MySQL does not handle CIDR of IPv6 addresses, return error
					if ($return_bool) {
						return false;
					}
					Response::standardError($lng, $ip, $throw_exception);
				}
				$ip = $ip_cidr[0];
				if ($cidr_as_netmask && strlen($ip_cidr[1]) <= 3) {
					$ip_cidr[1] = IPTools::cidr2NetmaskAddr($org_ip);
				}
				$cidr = "/" . $ip_cidr[1];
			} else {
				$ip = $org_ip;
			}
		} elseif (strpos($ip, "/") !== false) {
			if ($return_bool) {
				return false;
			}
			Response::standardError($lng, $ip, $throw_exception);
		}

		$filter_lan = $allow_priv ? FILTER_FLAG_NO_RES_RANGE : (FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_NO_PRIV_RANGE);

		if ((filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || filter_var($ip, FILTER_VALIDATE_IP,
					FILTER_FLAG_IPV4)) && filter_var($ip, FILTER_VALIDATE_IP, $filter_lan)) {
			return $ip . $cidr;
		}

		// special case where localhost ip is allowed (mysql-access-hosts for example)
		if ($allow_localhost && ($ip == '127.0.0.1' || $ip == '::1')) {
			return $ip . $cidr;
		}

		if ($return_bool) {
			return false;
		}
		Response::standardError($lng, $ip, $throw_exception);
	}

	/**
	 * Returns whether a URL is in a correct format or not
	 *
	 * @param string $url URL to be tested
	 * @param bool $allow_private_ip optional, default is false
	 *
	 * @return bool
	 */
	public static function validateUrl(string $url, bool $allow_private_ip = false): bool
	{
		if (strtolower(substr($url, 0, 7)) != "http://" && strtolower(substr($url, 0, 8)) != "https://") {
			$url = 'http://' . $url;
		}

		// Parse parts
		$parts = parse_url($url);
		if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
			return false;
		}

		// Check allowed schemes
		if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
			return false;
		}

		// Check if host is valid domain or valid IP (v4 or v6)
		$host = $parts['host'];
		if (substr($host, 0, 1) == '[' && substr($host, -1) == ']') {
			$host = substr($host, 1, -1);
		}

		$opts = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_NO_PRIV_RANGE;
		$opts6 = FILTER_FLAG_IPV6 | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_NO_PRIV_RANGE;
		if ($allow_private_ip) {
			$opts = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_RES_RANGE;
			$opts6 = FILTER_FLAG_IPV6 | FILTER_FLAG_NO_RES_RANGE;
		}
		if (filter_var($host, FILTER_VALIDATE_IP, $opts)) {
			return true;
		} elseif (substr($parts['host'], 0, 1) == '[' && substr($parts['host'], -1) == ']' && filter_var($host, FILTER_VALIDATE_IP, $opts6)) {
			return true;
		} elseif (!preg_match('/^([0-9]{1,3}\.)+[0-9]{1,3}$/', $host) && self::validateDomain($host) !== false) {
			return true;
		}

		return false;
	}

	/**
	 * Check if the submitted string is a valid domainname
	 *
	 * @param string $domainname The domainname which should be checked.
	 * @param bool $allow_underscore optional if true, allows the underscore character in a domain label (DKIM etc.)
	 *
	 * @return string|boolean the domain-name if the domain is valid, false otherwise
	 */
	public static function validateDomain(string $domainname, bool $allow_underscore = false)
	{
		$char_validation = '([a-z\d](-*[a-z\d])*)(\.?([a-z\d](-*[a-z\d])*))*\.(xn\-\-)?([a-z\d])+';
		if ($allow_underscore) {
			$char_validation = '([a-z\d\_](-*[a-z\d\_])*)(\.([a-z\d\_](-*[a-z\d])*))*(\.?([a-z\d](-*[a-z\d])*))+\.(xn\-\-)?([a-z\d])+';
		}

		// valid chars check && overall length check && length of each label
		if (preg_match("/^" . $char_validation . "$/i", $domainname) && preg_match("/^.{1,253}$/",
				$domainname) && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domainname)) {
			return $domainname;
		}
		return false;
	}

	/**
	 * validate a local-hostname by regex
	 *
	 * @param string $hostname
	 *
	 * @return string|boolean hostname on success, else false
	 */
	public static function validateLocalHostname(string $hostname)
	{
		$pattern = '/^[a-z0-9][a-z0-9\-]{0,62}$/i';
		if (preg_match($pattern, $hostname)) {
			return $hostname;
		}
		return false;
	}

	/**
	 * Returns if an email-address is in correct format or not
	 *
	 * @param string $email The email address to check
	 *
	 * @return mixed
	 */
	public static function validateEmail(string $email)
	{
		$email = strtolower($email);
		// as of php-7.1
		if (defined('FILTER_FLAG_EMAIL_UNICODE')) {
			return filter_var($email, FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE);
		}
		return filter_var($email, FILTER_VALIDATE_EMAIL);
	}

	/**
	 * Returns if a username is in correct format or not.
	 *
	 * @param string $username The username to check
	 * @param bool $unix_names optional, default true, checks whether it must be UNIX compatible
	 * @param int $mysql_max optional, number of max mysql username characters, default empty
	 *
	 * @return bool
	 */
	public static function validateUsername(string $username, bool $unix_names = true, int $mysql_max = 0): bool
	{
		if (empty($mysql_max) || $mysql_max <= 0) {
			$mysql_max = Database::getSqlUsernameLength() - 1;
		} else {
			$mysql_max--;
		}
		if (!$unix_names) {
			if (strpos($username, '--') === false) {
				return (preg_match('/^[a-z][a-z0-9\-_]{0,' . $mysql_max . '}[a-z0-9]{1}$/Di', $username) != false);
			}
			return false;
		}
		return (preg_match('/^[a-z][a-z0-9]{0,' . $mysql_max . '}$/Di', $username) != false);
	}

	/**
	 * validate sql interval string
	 *
	 * @param string $interval
	 *
	 * @return bool
	 */
	public static function validateSqlInterval(string $interval = ''): bool
	{
		if (!empty($interval) && strstr($interval, ' ') !== false) {
			/*
			 * [0] = ([0-9]+)
			 * [1] = valid SQL-Interval expression
			 */
			$valid_expr = [
				'SECOND',
				'MINUTE',
				'HOUR',
				'DAY',
				'WEEK',
				'MONTH',
				'YEAR'
			];

			$interval_parts = explode(' ', $interval);

			if (count($interval_parts) == 2 && preg_match('/[0-9]+/',
					$interval_parts[0]) && in_array(strtoupper($interval_parts[1]), $valid_expr)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * validates whether a given base64 string decodes to an image
	 *
	 * @param string $base64string
	 * @return bool
	 * @throws Exception
	 */
	public static function validateBase64Image(string $base64string)
	{

		if (!extension_loaded('gd')) {
			Response::standardError('phpgdextensionnotavailable', null, true);
		}

		// Decode the base64 string
		$data = base64_decode($base64string);

		// Create an image from the decoded data
		$image = @imagecreatefromstring($data);

		// Check if the image was created successfully
		if (!$image) {
			return false;
		}

		// Get the MIME type of the image
		$mime = image_type_to_mime_type(getimagesizefromstring($data)[2]);

		// Check if the MIME type is a valid image MIME type
		if (strpos($mime, 'image/') !== 0) {
			return false;
		}

		// If everything is okay, return true
		return true;
	}

	public static function validateDnsLoc(string $input)
	{
		$pattern = '/^
        (\d{1,2})\s+                # latitude degrees
        (\d{1,2})\s+                # latitude minutes
        (\d{1,2}(?:\.\d+)?)\s+      # latitude seconds
        ([NS])\s+                   # latitude direction
        (\d{1,3})\s+                # longitude degrees
        (\d{1,2})\s+                # longitude minutes
        (\d{1,2}(?:\.\d+)?)\s+      # longitude seconds
        ([EW])\s+                   # longitude direction
        (-?\d+(?:\.\d+)?)m          # altitude
        (?:\s+(\d+(?:\.\d+)?)m      # size (optional)
        (?:\s+(\d+(?:\.\d+)?)m      # horiz precision (optional)
        (?:\s+(\d+(?:\.\d+)?)m)?    # vert precision (optional)
        )?)?$/x';

		if (!preg_match($pattern, $input, $matches)) {
			return false;
		}

		[
			,
			$latDeg, $latMin, $latSec, $latDir,
			$lonDeg, $lonMin, $lonSec, $lonDir,
			$alt,
			$size, $hPrec, $vPrec
		] = $matches + array_fill(0, 13, null);

		// Range checks
		if ($latDeg > 90) return false;
		if ($latMin > 59) return false;
		if ($latSec >= 60) return false;

		if ($lonDeg > 180) return false;
		if ($lonMin > 59) return false;
		if ($lonSec >= 60) return false;

		return $input;
	}

	public static function validateDnsRp(string $input)
	{
		$parts = preg_split('/\s+/', trim($input));

		if (count($parts) !== 2) {
			return false;
		}

		[$mboxDname, $txtDname] = $parts;

		// remove trailing dot if any
		$mboxDname = rtrim($mboxDname, '.');
		$txtDname = rtrim($txtDname, '.');

		if (!self::validateDomain($mboxDname)) {
			return false;
		}

		if (!self::validateDomain($txtDname)) {
			return false;
		}

		return $input;
	}

	public static function validateDnsSshfp(string $input)
	{
		$parts = preg_split('/\s+/', trim($input));

		if (count($parts) !== 3) {
			return false;
		}

		[$algorithm, $type, $fingerprint] = $parts;

		// ---- algorithm ----
		$validAlgorithms = [1, 2, 3, 4, 6];

		if (!ctype_digit($algorithm) || !in_array((int)$algorithm, $validAlgorithms, true)) {
			return false;
		}

		// ---- fingerprint type ----
		$validTypes = [1, 2];

		if (!ctype_digit($type) || !in_array((int)$type, $validTypes, true)) {
			return false;
		}

		// ---- check fingerprint ----
		if (!ctype_xdigit($fingerprint)) {
			return false;
		}

		$type = (int)$type;

		switch ($type) {
			case 1: // SHA-1
				$expectedLength = 40;
				break;

			case 2: // SHA-256
				$expectedLength = 64;
				break;

			default:
				$expectedLength = 0;
				break;
		}

		if (strlen($fingerprint) !== $expectedLength) {
			return false;
		}

		return $input;
	}

	public static function validateDnsTlsa(string $input)
	{
		$parts = preg_split('/\s+/', trim($input));

		if (count($parts) !== 4) {
			return false;
		}

		[$usage, $selector, $matchingType, $data] = $parts;

		// ---- usage ----
		$validUsage = [0, 1, 2, 3];

		if (!ctype_digit($usage) || !in_array((int)$usage, $validUsage, true)) {
			return false;
		}

		// ---- selector ----
		$validSelector = [0, 1];

		if (!ctype_digit($selector) || !in_array((int)$selector, $validSelector, true)) {
			return false;
		}

		// ---- matching type ----
		$validMatching = [0, 1, 2];

		if (!ctype_digit($matchingType) || !in_array((int)$matchingType, $validMatching, true)) {
			return false;
		}

		// ---- certificate association data ----
		if (!ctype_xdigit($data)) {
			return false;
		}

		$matchingType = (int)$matchingType;

		if ($matchingType === 1 && strlen($data) !== 64) {
			return false; // SHA-256
		}

		if ($matchingType === 2 && strlen($data) !== 128) {
			return false; // SHA-512
		}

		if ($matchingType === 0 && strlen($data) < 2) {
			return false; // at least 1 byte hex
		}

		return $input;
	}

	public static function validateDnsNaptr(string $input): bool
	{
		// Split respecting quoted strings
		$pattern = '/^
        (\d{1,5})\s+                # order
        (\d{1,5})\s+                # preference
        "([^"]*)"\s+                # flags
        "([^"]*)"\s+                # services
        "([^"]*)"\s+                # regexp
        (\S+)                      # replacement
    $/x';

		if (!preg_match($pattern, $input, $matches)) {
			return false;
		}

		[, $order, $preference, $flags, $services, $regexp, $replacement] = $matches;

		// 1. order & preference: 0–65535
		if ($order < 0 || $order > 65535 || $preference < 0 || $preference > 65535) {
			return false;
		}

		// 2. flags: allowed chars (RFC says single letters typically, but allow multiple)
		if (!preg_match('/^[A-Za-z0-9]*$/', $flags)) {
			return false;
		}

		// 3. services: usually like "E2U+sip"
		if (!preg_match('/^[A-Za-z0-9+:\-]*$/', $services)) {
			return false;
		}

		// 4. regexp: delimiter-based substitution (very loose validation)
		// Example: !^.*$!sip:info@example.com!
		if ($regexp !== '') {
			$delim = $regexp[0];
			if (substr_count($regexp, $delim) < 3) {
				return false;
			}
		}

		// 5. replacement: must be "." or valid domain
		if ($replacement !== '.') {
			if (!filter_var($replacement, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
				return false;
			}
		}

		return true;
	}
}
