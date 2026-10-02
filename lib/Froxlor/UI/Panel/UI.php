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

declare(strict_types=1);

namespace Froxlor\UI\Panel;

use DirectoryIterator;
use Exception;
use Froxlor\CurrentUser;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\Linker;
use Twig\Environment;
use Twig\Extension\DebugExtension;
use Twig\Loader\FilesystemLoader;

class UI
{

	/**
	 * twig object
	 *
	 * @var Environment
	 */
	private static $twig = null;

	/**
	 * twig buffer
	 *
	 * @var array
	 */
	private static $twigbuf = [];

	/**
	 * linker class object
	 */
	private static $linker = null;

	/**
	 * current logged in user
	 *
	 * @var array
	 */
	private static $userinfo = [];

	/**
	 * default fallback theme
	 *
	 * @var string
	 */
	private static $default_theme = 'Froxlor';

	private static $install_mode = false;

	public static function requestIsHttps(): bool
	{
		$isHttps =
			$_SERVER['HTTPS']
			?? $_SERVER['REQUEST_SCHEME']
			?? $_SERVER['HTTP_X_FORWARDED_PROTO']
			?? null;

		return $isHttps && (strcasecmp('on', $isHttps) == 0 || strcasecmp('https', $isHttps) == 0);
	}

	/**
	 * Extract the cookie host from HTTP_HOST, stripping the port.
	 */
	public static function getCookieHost(): ?string
	{
		if (empty($_SERVER['HTTP_HOST']))
			return null;

		$colonPosition = strrpos($_SERVER['HTTP_HOST'], ':');
		// There's no port in the host
		if ($colonPosition === false)
			return $_SERVER['HTTP_HOST'];

		$closingSquareBracketPosition = strrpos($_SERVER['HTTP_HOST'], ']');
		// The host is an IPv4 address or hostname with port
		if ($closingSquareBracketPosition === false)
			return substr($_SERVER['HTTP_HOST'], 0, $colonPosition);

		// The host is an IPv6 address with port
		return substr($_SERVER['HTTP_HOST'], 0, $closingSquareBracketPosition + 1);
	}

	/**
	 * send various security related headers
	 */
	public static function sendHeaders()
	{
		session_set_cookie_params([
			'lifetime' => self::$install_mode ? 7200 : 600, // will be renewed based on settings in lib/init.php
			'path' => '/',
			'domain' => self::getCookieHost(),
			'secure' => self::requestIsHttps(),
			'httponly' => true,
			'samesite' => 'Lax'
		]);
		session_start();

		header("Content-Type: text/html; charset=UTF-8");

		// prevent Froxlor pages from being cached
		header("Cache-Control: no-store, no-cache, must-revalidate");
		header("Pragma: no-cache");
		header('Last-Modified: ' . gmdate('D, d M Y H:i:s \G\M\T', time()));
		header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T', time()));

		// Prevent inline - JS to be executed (i.e. XSS) in browsers which support this,
		// Inline-JS is no longer allowed and used
		// See: http://people.mozilla.org/~bsterne/content-security-policy/index.html
		// New stuff see: https://www.owasp.org/index.php/List_of_useful_HTTP_headers and https://www.owasp.org/index.php/Content_Security_Policy
		$csp_content = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'self'; frame-src 'self'; frame-ancestors 'self';";
		header("Content-Security-Policy: " . $csp_content);
		header("X-Content-Security-Policy: " . $csp_content);
		header("X-WebKit-CSP: " . $csp_content);

		// Don't allow to load Froxlor in an iframe to prevent i.e. clickjacking
		header("X-Frame-Options: DENY");

		// Internet Explorer shall not guess the Content-Type, see:
		// http://blogs.msdn.com/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx
		header("X-Content-Type-Options: nosniff");

		// ensure that default timezone is set
		if (function_exists("date_default_timezone_set") && function_exists("date_default_timezone_get")) {
			@date_default_timezone_set(@date_default_timezone_get());
		}
	}

	public static function sendSslHeaders()
	{
		/**
		 * If Froxlor was called via HTTPS -> enforce it for the next time by settings HSTS header according to settings
		 */
		if (isset($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) != 'off')) {
			$maxage = Settings::Get('system.hsts_maxage');
			if (empty($maxage)) {
				$maxage = 0;
			}
			$hsts_header = "Strict-Transport-Security: max-age=" . $maxage;
			if (Settings::Get('system.hsts_incsub') == '1') {
				$hsts_header .= "; includeSubDomains";
			}
			if (Settings::Get('system.hsts_preload') == '1') {
				$hsts_header .= "; preload";
			}
			header($hsts_header);
		}
	}

	/**
	 * initialize Twig template engine
	 */
	public static function initTwig(bool $install_mode = false)
	{
		self::$install_mode = $install_mode;
		// init twig template engine
		$loader = new FilesystemLoader(Froxlor::getInstallDir() . '/templates/');
		$twig_params = [
			'auto_reload' => true,
			'debug' => false,
		];
		if (is_writable(Froxlor::getInstallDir() . '/cache')) {
			$twig_params['cache'] = Froxlor::getInstallDir() . '/cache';
		}
		self::$twig = new Environment($loader, $twig_params);
		self::$twig->addExtension(new DebugExtension());
		self::$twig->addExtension(new CustomReflection());
		self::$twig->addExtension(new FroxlorTwig());
		// empty buffer
		self::$twigbuf = [];
	}

	/**
	 * twig wrapper
	 *
	 * @return Environment
	 */
	public static function twig(): ?Environment
	{
		return self::$twig;
	}

	public static function getLinker(): Linker
	{
		return self::$linker;
	}

	public static function setLinker($linker = null)
	{
		self::$linker = $linker;
	}

	public static function setCurrentUser($userinfo = null)
	{
		self::$userinfo = $userinfo;
	}

	public static function getCurrentUser(): array
	{
		return self::$userinfo;
	}

	/**
	 * returns an array of available themes
	 *
	 * @return array
	 * @throws Exception
	 */
	public static function getThemes(): array
	{
		$themespath = FileDir::makeCorrectDir(Froxlor::getInstallDir() . '/templates/');
		$themes_available = [];

		if (is_dir($themespath)) {
			$its = new DirectoryIterator($themespath);

			foreach ($its as $it) {
				if ($it->isDir() && $it->getFilename() != '.' && $it->getFilename() != '..' && $it->getFilename() != 'misc') {
					$theme = $themespath . $it->getFilename();
					if (file_exists($theme . '/config.json')) {
						$themeconfig = json_decode(file_get_contents($theme . '/config.json'), true);
						if (array_key_exists('variants', $themeconfig) && is_array($themeconfig['variants'])) {
							foreach ($themeconfig['variants'] as $variant => $data) {
								if ($variant == "default") {
									$themes_available[$it->getFilename()] = $it->getFilename();
								} elseif (array_key_exists('description', $data)) {
									$themes_available[$it->getFilename() . '_' . $variant] = $data['description'];
								} else {
									$themes_available[$it->getFilename() . '_' . $variant] = $it->getFilename() . ' (' . $variant . ')';
								}
							}
						} else {
							$themes_available[$it->getFilename()] = $it->getFilename();
						}
					}
				}
			}
		}
		return $themes_available;
	}

	public static function view($name, array $context = [])
	{
		self::twigBuffer($name, $context);
		self::twigOutputBuffer();
	}

	/**
	 * wrapper for twig's "render" function to buffer the output
	 *
	 * @see \Twig\Environment::render()
	 */
	public static function twigBuffer($name, array $context = [])
	{
		$template_file = self::validateThemeTemplate($name);

		self::$twigbuf[] = [
			$template_file => $context
		];
	}

	public static function validateThemeTemplate(string $name, string $theme = "")
	{
		if (empty(trim($theme))) {
			$theme = self::getTheme();
		}
		$template_file = $theme . '/' . $name;
		if (!file_exists(Froxlor::getInstallDir() . '/templates/' . $template_file)) {
			PhpHelper::phpErrHandler(E_USER_WARNING, "Template '" . $template_file . "' could not be found, trying fallback theme", __FILE__, __LINE__);
			$template_file = self::$default_theme . '/'. $name;
			if (!file_exists(Froxlor::getInstallDir() . '/templates/' . $template_file)) {
				PhpHelper::phpErrHandler(E_USER_ERROR, "Unknown template '" . $template_file . "'", __FILE__, __LINE__);
			}
		}
		return $template_file;
	}

	public static function getTheme()
	{
		// fallback
		$theme = self::$default_theme;
		if (!self::$install_mode) {
			// system default
			if (Froxlor::versionCompare2(Settings::Get('panel.version'), '2.0.0-beta1') == -1) {
				// pre 2.0
				Settings::Set('panel.default_theme', 'Froxlor');
			} else {
				$theme = (Settings::Get('panel.default_theme') !== null) ? Settings::Get('panel.default_theme') : $theme;
				// customer theme
				if (CurrentUser::hasSession() && CurrentUser::getField('theme') != $theme) {
					$theme = CurrentUser::getField('theme');
				}
			}
		}
		// check for template-variant
		if (preg_match("/([a-z0-9.\-]+)_([a-z0-9.\-]+)/i", $theme, $matches)) {
			$theme = $matches[1];
		}
		if (!file_exists(Froxlor::getInstallDir() . '/templates/' . $theme)) {
			PhpHelper::phpErrHandler(E_USER_WARNING, "Theme '" . $theme . "' could not be found.", __FILE__, __LINE__);
			$theme = self::$default_theme;
		}
		return $theme;
	}

	/**
	 * echo output buffer and empty buffer-content
	 */
	public static function twigOutputBuffer()
	{
		$output = "";
		foreach (self::$twigbuf as $buf) {
			foreach ($buf as $name => $context) {
				try {
					$output .= self::$twig->render($name, $context);
				} catch (Exception $e) {
					// whoops, template error
					$errtpl = 'alert_nosession.html.twig';
					if (self::activeUserSession()) {
						$errtpl = 'alert.html.twig';
					}
					$edata = [
						'type' => "danger",
						'heading' => "Template error",
						'alert_msg' => $e->getMessage(),
						'alert_info' => $e->getTraceAsString()
					];
					try {
						// try with user theme if set
						$output .= self::$twig->render(self::getTheme() . '/misc/' . $errtpl, $edata);
					} catch (Exception $e) {
						// try with default theme if different from user theme
						if (self::getTheme() != self::$default_theme) {
							$output .= self::$twig->render(self::$default_theme . '/misc/' . $errtpl, $edata);
						} else {
							throw $e;
						}
					}
				}
			}
		}
		echo $output;
		// empty buffer
		self::$twigbuf = [];
	}

	public static function activeUserSession(): bool
	{
		return !empty(self::$userinfo);
	}
}
