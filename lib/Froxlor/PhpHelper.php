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

namespace Froxlor;

use Exception;
use Froxlor\UI\Panel\UI;
use Net_DNS2_Exception;
use Net_DNS2_Resolver;
use Throwable;
use voku\helper\AntiXSS;

class PhpHelper
{
	/**
	 * Wrapper around htmlentities to handle arrays, with the advantage that you
	 * can select which fields should be handled by htmlentities
	 *
	 * @param array|string $subject The subject array
	 * @param array|string $fields The fields which should be checked for, separated by spaces
	 * @param int $quote_style See php documentation about this
	 * @param string $charset See php documentation about this
	 *
	 * @return array|string The string or an array with htmlentities converted strings
	 * @author Florian Lippert <flo@syscp.org> (2003-2009)
	 */
	public static function htmlentitiesArray($subject, $fields = '', $quote_style = ENT_QUOTES, $charset = 'UTF-8')
	{
		if (is_array($subject)) {
			if (!is_array($fields)) {
				$fields = self::arrayTrim(explode(' ', $fields));
			}

			foreach ($subject as $field => $value) {
				if ((!is_array($fields) || empty($fields)) || (in_array($field, $fields))) {
					// Just call ourselve to manage multi-dimensional arrays
					$subject[$field] = self::htmlentitiesArray($value, $fields, $quote_style, $charset);
				}
			}
		} else {
			$subject = empty($subject) ? "" : htmlentities($subject, $quote_style, $charset);
		}

		return $subject;
	}

	/**
	 * Returns array with all empty-values removed
	 *
	 * @param array $source The array to trim
	 * @return array The trim'med array
	 */
	public static function arrayTrim(array $source): array
	{
		$source = array_map('trim', $source);
		return array_filter($source, function ($value) {
			return $value !== '';
		});
	}

	/**
	 * froxlor php error handler
	 *
	 * @param int $errno
	 * @param string $errstr
	 * @param string $errfile
	 * @param int $errline
	 *
	 * @return void|boolean
	 */
	public static function phpErrHandler($errno, $errstr, $errfile, $errline)
	{
		if (!(error_reporting() & $errno)) {
			// This error code is not included in error_reporting
			return;
		}

		if (!isset($_SERVER['SHELL']) || (isset($_SERVER['SHELL']) && $_SERVER['SHELL'] == '')) {
			// prevent possible file-path-disclosure
			$errfile = str_replace(Froxlor::getInstallDir(), "", $errfile);
			// build alert
			$type = 'danger';
			if ($errno == E_NOTICE || $errno == E_DEPRECATED || $errno == E_STRICT) {
				$type = 'info';
			} elseif ($errno = E_WARNING) {
				$type = 'warning';
			}
			$err_display = '<div class="alert alert-' . $type . ' my-1" role="alert">';
			$err_display .= '<strong>#' . $errno . ' ' . $errstr . '</strong><br>';
			$err_display .= $errfile . ':' . $errline;
			// later depended on whether to show or now
			$err_display .= '<br><p><pre>';
			$debug = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
			foreach ($debug as $dline) {
				$err_display .= $dline['function'] . '() called at [' . str_replace(Froxlor::getInstallDir(), '',
						($dline['file'] ?? 'unknown')) . ':' . ($dline['line'] ?? 0) . ']<br>';
			}
			$err_display .= '</pre></p>';
			// end later
			$err_display .= '</div>';
			// set errors to session
			ErrorBag::addError($err_display);
			// return true to ignore php standard error-handler
			return true;
		}

		// of on shell, use the php standard error-handler
		return false;
	}

	/**
	 * @param Throwable $exception
	 * @return void
	 */
	public static function phpExceptionHandler(Throwable $exception)
	{
		if (!isset($_SERVER['SHELL']) || $_SERVER['SHELL'] == '') {
			// show
			UI::initTwig(true);
			UI::twig()->addGlobal('install_mode', '1');
			UI::view('misc/alert_nosession.html.twig', [
				'page_title' => 'Uncaught exception',
				'heading' => 'Uncaught exception',
				'type' => 'danger',
				'alert_msg' => $exception->getCode() . ' ' . $exception->getMessage(),
				'alert_info' => $exception->getTraceAsString()
			]);
			die();
		}
	}

	/**
	 * @param ...$configdirs
	 * @return array|null
	 */
	public static function loadConfigArrayDir(...$configdirs)
	{
		if (count($configdirs) <= 0) {
			return null;
		}

		$data = [];
		$data_files = [];
		$has_data = false;

		foreach ($configdirs as $data_dirname) {
			if (is_dir($data_dirname)) {
				$data_dirhandle = opendir($data_dirname);
				while (false !== ($data_filename = readdir($data_dirhandle))) {
					if ($data_filename != '.'
						&& $data_filename != '..'
						&& $data_filename != ''
						&& substr($data_filename, -4) == '.php'
					) {
						$data_files[] = $data_dirname . $data_filename;
					}
				}
				$has_data = true;
			}
		}

		if ($has_data) {
			sort($data_files);
			foreach ($data_files as $data_filename) {
				$data = array_merge_recursive($data, include $data_filename);
			}
		}

		return $data;
	}

	/**
	 * ipv6 aware gethostbynamel function
	 *
	 * @param string $host
	 * @param boolean $try_a default true
	 * @param string|null $nameserver set additional resolver nameserver to use (e.g. 1.1.1.1)
	 * @return bool|array
	 */
	public static function gethostbynamel6(string $host, bool $try_a = true, ?string $nameserver = null)
	{
		$ips = [];

		// Limit CNAME traversal so misconfigured DNS loops cannot block callers.
		$max_depth = 10;

		try {
			// set the default nameservers to use, use the system default if none are provided
			$resolver = new Net_DNS2_Resolver($nameserver ? ['nameservers' => [$nameserver]] : []);

			// 1. Query direct A records on the input hostname
			if ($try_a) {
				try {
					$answer = $resolver->query($host, 'A')->answer;
					foreach ($answer as $rr) {
						if ($rr instanceof \Net_DNS2_RR_A) {
							$ips[] = inet_ntop(inet_pton($rr->address));
						}
					}
				} catch (Net_DNS2_Exception $e) {
					// no A record or query failed; continue to AAAA
				}
			}

			// 2. Query direct AAAA records on the input hostname
			try {
				$answer = $resolver->query($host, 'AAAA')->answer;
				foreach ($answer as $rr) {
					if ($rr instanceof \Net_DNS2_RR_AAAA) {
						$ips[] = inet_ntop(inet_pton($rr->address));
					}
				}
			} catch (Net_DNS2_Exception $e) {
				// no AAAA record or query failed; continue to CNAME
			}

			// Follow CNAME chains explicitly; Net_DNS2 does not always include the
			// target A/AAAA records when querying the original hostname.
			$depth = 0;
			$seen = [$host];
			$current = $host;
			while ($depth < $max_depth) {
				$depth++;
				try {
					$answer = $resolver->query($current, 'CNAME')->answer;
				} catch (Net_DNS2_Exception $e) {
					break; // no CNAME found; stop following the chain
				}
				if (empty($answer)) {
					break; // no CNAME record; stop following the chain
				}
				$cname_target = null;
				foreach ($answer as $rr) {
					if ($rr instanceof \Net_DNS2_RR_CNAME) {
						$cname_target = $rr->cname;
						break;
					}
				}
				if ($cname_target === null) {
					break; // no valid CNAME record found; stop
				}
				if (in_array($cname_target, $seen, true)) {
					break; // loop detected; stop
				}
				$seen[] = $cname_target;

				// 3a. Resolve A records from the CNAME target
				if ($try_a) {
					try {
						$answer = $resolver->query($cname_target, 'A')->answer;
						foreach ($answer as $rr) {
							if ($rr instanceof \Net_DNS2_RR_A) {
								$ips[] = inet_ntop(inet_pton($rr->address));
							}
						}
					} catch (Net_DNS2_Exception $e) {
						// continue following the chain even if A fails
					}
				}

				// 3b. Resolve AAAA records from the CNAME target
				try {
					$answer = $resolver->query($cname_target, 'AAAA')->answer;
					foreach ($answer as $rr) {
						if ($rr instanceof \Net_DNS2_RR_AAAA) {
							$ips[] = inet_ntop(inet_pton($rr->address));
						}
					}
				} catch (Net_DNS2_Exception $e) {
					// continue following the chain even if AAAA fails
				}

				$current = $cname_target;
			}
		} catch (Net_DNS2_Exception $e) {
			// fallback to php's dns_get_record if Net_DNS2 has no resolver available, but this may cause
			// problems if the system's dns is not configured correctly; for example, the acme pre-check
			// will fail because some providers put a local ip in /etc/hosts
			$current = $host;
			$depth = 0;
			$seen = [$host];
			while ($depth < $max_depth) {
				$depth++;
				// 1. Query direct A records on the current name
				if ($try_a) {
					$answer = @dns_get_record($current, DNS_A);
					foreach ($answer as $rr) {
						if (isset($rr['ip'])) {
							$ips[] = inet_ntop(inet_pton($rr['ip']));
						}
					}
				}

				// 2. Query direct AAAA records on the current name
				$answer = @dns_get_record($current, DNS_AAAA);
				foreach ($answer as $rr) {
					if (isset($rr['ipv6'])) {
						$ips[] = inet_ntop(inet_pton($rr['ipv6']));
					}
				}

				// 3. Follow CNAME chain
				$answer = @dns_get_record($current, DNS_CNAME);
				if (empty($answer)) {
					break; // no CNAME found; stop following the chain
				}
				$cname_target = null;
				foreach ($answer as $rr) {
					if (isset($rr['cname'])) {
						$cname_target = $rr['cname'];
						break;
					}
				}
				if ($cname_target === null) {
					break; // no valid CNAME record found; stop
				}
				if (in_array($cname_target, $seen, true)) {
					break; // loop detected; stop
				}
				$seen[] = $cname_target;
				$current = $cname_target;
			}
		}

		return count($ips) > 0 ? $ips : false;
	}

	/**
	 * Function randomStr
	 *
	 * generate a pseudo-random string of bytes
	 *
	 * @param int $length
	 * @return string
	 * @throws Exception
	 */
	public static function randomStr(int $length): string
	{
		if (function_exists('openssl_random_pseudo_bytes')) {
			return openssl_random_pseudo_bytes($length);
		}
		return random_bytes($length);
	}

	/**
	 * Return human-readable sizes
	 *
	 * @param int $size size in bytes
	 * @param ?string $max maximum unit
	 * @param string $system 'si' for SI, 'bi' for binary prefixes
	 * @param string $retstring string-format
	 *
	 * @return string
	 */
	public static function sizeReadable(
		$size,
		?string $max = '',
		string $system = 'si',
		string $retstring = '%01.2f %s'
	): string
	{
		// Pick units
		$systems = [
			'si' => [
				'prefix' => [
					'B',
					'KB',
					'MB',
					'GB',
					'TB',
					'PB'
				],
				'size' => 1000
			],
			'bi' => [
				'prefix' => [
					'B',
					'KiB',
					'MiB',
					'GiB',
					'TiB',
					'PiB'
				],
				'size' => 1024
			]
		];
		$sys = $systems[$system] ?? $systems['si'];

		// Max unit to display
		$depth = count($sys['prefix']) - 1;
		if ($max && false !== $d = array_search($max, $sys['prefix'])) {
			$depth = $d;
		}
		// Loop
		$i = 0;
		while ($size >= $sys['size'] && $i < $depth) {
			$size /= $sys['size'];
			$i++;
		}

		return sprintf($retstring, $size, $sys['prefix'][$i]);
	}

	/**
	 * Replaces all occurrences of variables defined in the second argument
	 * in the first argument with their values.
	 *
	 * @param string $text The string that should be searched for variables
	 * @param array $vars The array containing the variables with their values
	 *
	 * @return string The submitted string with the variables replaced.
	 */
	public static function replaceVariables(string $text, array $vars): string
	{
		$pattern = "/\{([a-zA-Z0-9\-_]+)\}/";
		$matches = [];

		if (count($vars) > 0 && preg_match_all($pattern, $text, $matches)) {
			for ($i = 0; $i < count($matches[1]); $i++) {
				$current = $matches[1][$i];

				if (isset($vars[$current])) {
					$var = $vars[$current];
					$text = str_replace("{" . $current . "}", $var, $text);
				}
			}
		}

		return str_replace('\n', "\n", $text);
	}

	/**
	 * @param string $needle
	 * @param array $haystack
	 * @param array $keys
	 * @param string $currentKey
	 * @return true
	 */
	public static function recursive_array_search(
		string $needle,
		array  $haystack,
		array  &$keys = [],
		string $currentKey = ''
	): bool
	{
		foreach ($haystack as $key => $value) {
			if (empty($value)) {
				continue;
			}
			$pathkey = empty($currentKey) ? $key : $currentKey . '.' . $key;
			if (is_array($value)) {
				self::recursive_array_search($needle, $value, $keys, $pathkey);
			} else {
				if (stripos($value, $needle) !== false) {
					$keys[] = $pathkey;
				}
			}
		}
		return true;
	}

	/**
	 * function to check a super-global passed by reference,
	 * so it gets automatically updated
	 *
	 * @param array $global
	 * @param AntiXSS $antiXss
	 */
	public static function cleanGlobal(array &$global, AntiXSS &$antiXss)
	{
		$ignored_fields = [
			'system_default_vhostconf',
			'system_default_sslvhostconf',
			'system_apache_globaldiropt',
			'specialsettings',
			'ssl_specialsettings',
			'default_vhostconf_domain',
			'ssl_default_vhostconf_domain',
			'filecontent',
			'admin_password',
			'password',
			'new_customer_password',
			'privileged_password',
			'email_password',
			'directory_password',
			'ftp_password',
			'mysql_password',
			'mysql_root_pass',
			'mysql_unprivileged_pass',
			'admin_pass',
			'admin_pass_confirm',
			'panel_password_special_char',
			'old_password',
			'new_password',
			'new_password_confirm',
		];
		if (!empty($global)) {
			$tmp = $global;
			foreach ($tmp as $index => $value) {
				if (!in_array($index, $ignored_fields)) {
					$global[$index] = $antiXss->xss_clean($value);
				}
			}
		}
	}

	/**
	 * Generate php file from array.
	 *
	 * @param array $array
	 * @param string|null $comment
	 * @param bool $asReturn
	 * @return string
	 */
	public static function parseArrayToPhpFile(array $array, ?string $comment = null, bool $asReturn = false): string
	{
		$str = sprintf("<?php\n// %s\n\n", $comment ?? 'autogenerated froxlor file');

		if ($asReturn) {
			return $str . sprintf("return %s;\n", rtrim(self::parseArrayToString($array), "\n,"));
		}

		foreach ($array as $var => $arr) {
			$str .= sprintf("\$%s = %s;\n", $var, rtrim(self::parseArrayToString($arr), "\n,"));
		}
		return $str;
	}

	/**
	 * Parse array to array string.
	 *
	 * @param array $array
	 * @param ?string $key
	 * @param int $depth
	 * @return string
	 */
	public static function parseArrayToString(array $array, ?string $key = null, int $depth = 1): string
	{
		$str = '';
		if (!is_null($key)) {
			$str .= self::tabPrefix(($depth - 1), "'{$key}' => [\n");
		} else {
			$str .= self::tabPrefix(($depth - 1), "[\n");
		}
		foreach ($array as $key => $value) {
			if (!is_array($value)) {
				if (is_bool($value)) {
					$str .= self::tabPrefix($depth, sprintf("'%s' => %s,\n", $key, $value ? 'true' : 'false'));
				} elseif (is_int($value)) {
					$str .= self::tabPrefix($depth, "'{$key}' => $value,\n");
				} else {
					if ($key == 'password') {
						// special case for passwords (nowdoc)
						$str .= self::tabPrefix($depth, "'{$key}' => <<<'EOT'\n{$value}\nEOT,\n");
					} else {
						// escape backslashes first, then single quotes:
						$escaped = str_replace(['\\', "'"], ['\\\\', "\\'"], $value);
						$str .= self::tabPrefix($depth, "'{$key}' => '{$escaped}',\n");
					}
				}
			} else {
				$str .= self::parseArrayToString($value, $key, ($depth + 1));
			}
		}
		$str .= self::tabPrefix(($depth - 1), "],\n");
		return $str;
	}

	/**
	 * Apply tabs with given depth to string.
	 *
	 * @param int $depth
	 * @param string $str
	 * @return string
	 */
	private static function tabPrefix(int $depth, string $str = ''): string
	{
		$tab = '';
		for ($i = 1; $i <= $depth; $i++) {
			$tab .= "\t";
		}
		return $tab . $str;
	}

	public static function array_merge_recursive_distinct(array &$array1, array &$array2)
	{
		$merged = $array1;
		foreach ($array2 as $key => &$value) {
			if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
				$merged[$key] = self::array_merge_recursive_distinct($merged[$key], $value);
			} else {
				$merged[$key] = $value;
			}
		}
		return $merged;
	}
}
