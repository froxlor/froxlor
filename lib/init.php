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

// define default theme for configurehint, etc.
$_deftheme = 'Froxlor';

require dirname(__DIR__) . '/lib/functions.php';

// validate correct php version
if (version_compare("7.4.0", PHP_VERSION, ">=")) {
	die(view($_deftheme . '/misc/phprequirementfailed.html.twig', [
		'{{ basehref }}' => '',
		'{{ froxlor_min_version }}' => '7.4.0',
		'{{ current_version }}' => PHP_VERSION,
		'{{ current_year }}' => date('Y', time()),
	]));
}

// validate vendor autoloader
if (!file_exists(dirname(__DIR__) . '/vendor/autoload.php')) {
	die(view($_deftheme . '/misc/vendormissinghint.html.twig', [
		'{{ basehref }}' => '',
		'{{ froxlor_install_dir }}' => dirname(__DIR__),
		'{{ current_year }}' => date('Y', time()),
	]));
}

require dirname(__DIR__) . '/vendor/autoload.php';

use Froxlor\CurrentUser;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Http\RateLimiter;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Install\Update;
use Froxlor\Language;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Mailer;
use Froxlor\UI\HTML;
use Froxlor\UI\Linker;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\Install\Requirements;

// include MySQL-tabledefinitions
require Froxlor::getInstallDir() . '/lib/tables.inc.php';

UI::sendHeaders();
UI::initTwig();

/**
 * Register Globals Security Fix
 */
Request::cleanAll();

unset($_);
unset($key);

$filename = htmlentities(basename($_SERVER['SCRIPT_NAME']));

// check whether the userdata file exists
if (!file_exists(Froxlor::getInstallDir() . '/lib/userdata.inc.php')) {
	UI::twig()->addGlobal('install_mode', '1');
	echo UI::twig()->render($_deftheme . '/misc/configurehint.html.twig');
	die();
}

// check whether we can read the userdata file
if (!is_readable(Froxlor::getInstallDir() . '/lib/userdata.inc.php')) {
	// get possible owner
	$posixusername = posix_getpwuid(posix_getuid());
	$posixgroup = posix_getgrgid(posix_getgid());
	UI::twig()->addGlobal('install_mode', '1');
	echo UI::twig()->render($_deftheme . '/misc/ownershiphint.html.twig', [
		'user' => $posixusername['name'],
		'group' => $posixgroup['name'],
		'installdir' => Froxlor::getInstallDir()
	]);
	die();
}

// include MySQL-Username/Passwort etc.
require Froxlor::getInstallDir() . '/lib/userdata.inc.php';
if (!isset($sql) || !is_array($sql)) {
	UI::twig()->addGlobal('install_mode', '1');
	echo UI::twig()->render($_deftheme . '/misc/configurehint.html.twig');
	die();
}

/**
 * Show nice note if requested domain is "unknown" to froxlor and thus is being lead to its vhost
 */
$req_host = UI::getCookieHost();
if ($req_host != Settings::Get('system.hostname') &&
	    Settings::Get('panel.is_configured') == 1 &&
		!filter_var($req_host, FILTER_VALIDATE_IP) && (
		empty(Settings::Get('system.froxloraliases')) ||
		(!empty(Settings::Get('system.froxloraliases')) && !in_array($req_host, array_map('trim', explode(',', Settings::Get('system.froxloraliases')))))
)) {
	// not the froxlor system-hostname, show info page for domains not configured in froxlor
	$redirect_file = FileDir::getUnknownDomainTemplate($req_host ?? "non-detectable http-host");
	header('Location: '.$redirect_file);
	die();
}

// validate php-extensions requirements
$loadedExtensions = get_loaded_extensions();
$missingExtensions = [];
foreach (Requirements::REQUIRED_EXTENSIONS as $requiredExtension) {
	if (in_array($requiredExtension, $loadedExtensions)) {
		continue;
	}
	$missingExtensions[] = $requiredExtension;
}
if (!empty($missingExtensions)) {
	UI::twig()->addGlobal('install_mode', '1');
	echo UI::twig()->render($_deftheme . '/misc/missingextensionhint.html.twig', [
		'phpversion' => phpversion(),
		'missing_extensions' => implode(", ", $missingExtensions),
	]);
	die();
}

// set error-handler
@set_error_handler([
	'\\Froxlor\\PhpHelper',
	'phpErrHandler'
]);
@set_exception_handler([
	'\\Froxlor\\PhpHelper',
	'phpExceptionHandler'
]);

// send ssl-related headers (later than the others because we need a working database-connection and installation)
UI::sendSslHeaders();
RateLimiter::run();

// create a new idna converter
$idna_convert = new IdnaWrapper();

// re-read user data if logged in
if (CurrentUser::hasSession()) {
	CurrentUser::reReadUserData();
}

/**
 * Language management
 */

// set default language before anything else to
// ensure that we can display messages
Language::setLanguage(Settings::Get('panel.standardlanguage'));

// set language by given user
if (CurrentUser::hasSession()) {
	if (!empty(CurrentUser::getField('language')) && isset(Language::getLanguages()[CurrentUser::getField('language')])) {
		Language::setLanguage(CurrentUser::getField('language'));
	} else {
		Language::setLanguage(CurrentUser::getField('def_language'));
	}
}

// Initialize our link - class
$linker = new Linker('index.php');
UI::setLinker($linker);

/**
 * Global Theme-variable
 */
if (Update::versionInUpdate(Settings::Get('panel.version'), '2.0.0-beta1')) {
	$theme = $_deftheme;
} else {
	$theme = (Settings::Get('panel.default_theme') !== null) ? Settings::Get('panel.default_theme') : $_deftheme;
	// Overwrite with customer/admin theme if defined
	if (CurrentUser::hasSession() && CurrentUser::getField('theme') != $theme) {
		$theme = CurrentUser::getField('theme');
	}
}

// Check if a different variant of the theme is used
$themevariant = "default";
if (preg_match("/([a-z0-9.\-]+)_([a-z0-9.\-]+)/i", $theme, $matches)) {
	$theme = $matches[1];
	$themevariant = $matches[2];
}

// check for existence of the theme
if (@file_exists('templates/' . $theme . '/config.json')) {
	$_themeoptions = json_decode(file_get_contents('templates/' . $theme . '/config.json'), true);
} else {
	$_themeoptions = null;
}

// check for existence of variant in theme
if (is_array($_themeoptions) && (!array_key_exists('variants', $_themeoptions) || !array_key_exists(
			$themevariant,
			$_themeoptions['variants']
		))) {
	$themevariant = "default";
}

if (is_array($_themeoptions) && array_key_exists('global', $_themeoptions)) {
	$_themeoptions['variants'][$themevariant] = PhpHelper::array_merge_recursive_distinct($_themeoptions['global'], $_themeoptions['variants'][$themevariant]);
}

// check for custom header-graphic
$hl_path = 'templates/' . $theme . '/assets/img';

// default is theme-image
$header_logo = $hl_path . '/' . ($_themeoptions['variants'][$themevariant]['img']['ui'] ?? 'logo_white.png');
$header_logo_login = $hl_path . '/' . ($_themeoptions['variants'][$themevariant]['img']['login'] ?? 'logo_white.png');

if (Settings::Get('panel.logo_overridetheme') == 1 || Settings::Get('panel.logo_overridecustom') == 1) {
	// logo settings shall overwrite theme logo and possible custom logo
	$header_logo = Settings::Get('panel.logo_image_header') ?: $header_logo;
	$header_logo_login = Settings::Get('panel.logo_image_login') ?: $header_logo_login;
}
if (Settings::Get('panel.logo_overridecustom') == 0 && file_exists($hl_path . '/logo_custom.png')) {
	// custom theme image (logo_custom.png) is not being overwritten by logo_image_* setting
	$header_logo = $hl_path . '/logo_custom.png';
	$header_logo_login = $hl_path . '/logo_custom.png';
	if (file_exists($hl_path . '/logo_custom_login.png')) {
		$header_logo_login = $hl_path . '/logo_custom_login.png';
	}
}

$color_scheme = $_themeoptions['variants'][$themevariant]['color-scheme'] ?? 'auto';

UI::twig()->addGlobal('header_logo_login', $header_logo_login);
UI::twig()->addGlobal('header_logo', $header_logo);
UI::twig()->addGlobal('color_scheme', $color_scheme);

/**
 * Redirects to index.php (login page) if no session exists
 */
if (!CurrentUser::hasSession() && AREA != 'login') {
	unset($_SESSION['userinfo']);
	CurrentUser::setData();
	$_SESSION = [
		"lastscript" => basename($_SERVER["SCRIPT_NAME"]),
		"lastqrystr" => $_SERVER["QUERY_STRING"]
	];
	Response::redirectTo('index.php');
	exit();
}

$userinfo = CurrentUser::getData();
UI::twig()->addGlobal('userinfo', $userinfo);
UI::setCurrentUser($userinfo);
// Initialize logger
if (CurrentUser::hasSession()) {
	// Initialize logging
	$log = FroxlorLogger::getInstanceOf($userinfo);
	if ((CurrentUser::isAdmin() && AREA != 'admin') || (!CurrentUser::isAdmin() && AREA != 'customer')) {
		// user tries to access an area not meant for him -> redirect to corresponding index
		Response::redirectTo((CurrentUser::isAdmin() ? 'admin' : 'customer') . '_index.php');
		exit();
	}
}

/**
 * Fills variables for navigation, header and footer
 */
$navigation = [];
if (AREA == 'admin' || AREA == 'customer') {
	if (Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) {
		/*
		 * if froxlor-files have been updated
		 * but not yet configured by the admin
		 * we only show logout and the update-page
		 */
		$navigation_data = [
			'admin' => [
				'server' => [
					'label' => lng('admin.server'),
					'required_resources' => 'change_serversettings',
					'elements' => [
						[
							'url' => 'admin_updates.php?page=overview',
							'label' => lng('update.update'),
							'required_resources' => 'change_serversettings'
						]
					]
				]
			]
		];
		$navigation = HTML::buildNavigation($navigation_data['admin'], CurrentUser::getData());
	} else {
		$navigation_data = PhpHelper::loadConfigArrayDir('lib/navigation/');
		$navigation = HTML::buildNavigation($navigation_data[AREA], CurrentUser::getData());
	}
}
UI::twig()->addGlobal('nav_entries', $navigation);

$theme_assets = [];
foreach (['css', 'js'] as $asset) {
	if (is_array($_themeoptions) && array_key_exists($asset, $_themeoptions['variants'][$themevariant])) {
		if (is_array($_themeoptions['variants'][$themevariant][$asset])) {
			foreach ($_themeoptions['variants'][$themevariant][$asset] as $assetfile) {
				if (file_exists('templates/' . $theme . '/' . $assetfile)) {
					$theme_assets[] .= 'templates/' . $theme . '/' . $assetfile;
				}
			}
		}
	}
}

UI::twig()->addGlobal('theme_assets', $theme_assets);
unset($theme_assets);

$action = Request::any('action');
$page = Request::any('page', 'overview');
$gSearchText = Request::any('searchtext');

// clear request data
if (!$action && isset($_SESSION)) {
	unset($_SESSION['requestData']);
}

UI::twig()->addGlobal('action', $action);
UI::twig()->addGlobal('page', $page);
UI::twig()->addGlobal('area', AREA);
UI::twig()->addGlobal('gSearchText', $gSearchText);

// Initialize the mailingsystem
$mail = new Mailer(true);

// initialize csrf
if (CurrentUser::hasSession()) {
	// create new csrf token if not set
	if (!$csrf_token = CurrentUser::getField('csrf_token')) {
		$csrf_token = Froxlor::genSessionId(20);
		CurrentUser::setField('csrf_token', $csrf_token);
	}
	// set csrf token for twig
	UI::twig()->addGlobal('csrf_token', $csrf_token);
	// check if csrf token is valid
	if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'PATCH', 'DELETE'])) {
		$current_token = Request::post('csrf_token', $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
		if ($current_token != CurrentUser::getField('csrf_token')) {
			http_response_code(403);
			Response::dynamicError('CSRF validation failed');
		}
	}
	// update cookie lifetime
	$cookie_params = [
		'expires' => time() + min(Settings::Get('session.sessiontimeout'), 31536000),
		'path' => '/',
		'domain' => UI::getCookieHost(),
		'secure' => UI::requestIsHttps(),
		'httponly' => true,
		'samesite' => 'Lax'
	];
	setcookie(session_name(), $_COOKIE[session_name()], $cookie_params);
} else {
	UI::twig()->addGlobal('csrf_token', Froxlor::genSessionId(20));
}
