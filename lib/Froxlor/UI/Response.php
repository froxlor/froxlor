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

namespace Froxlor\UI;

use Exception;
use Froxlor\UI\Panel\UI;

class Response
{

	/**
	 * Sends a header ( 'Location ...' ) to the browser.
	 *
	 * @param string $destination
	 *            Destination
	 * @param array $get_variables
	 *            Get-Variables
	 * @param boolean $isRelative
	 *            if the target we are creating for a redirect
	 *            should be a relative or an absolute url
	 *
	 * @return boolean false if params is not an array
	 */
	public static function redirectTo($destination, $get_variables = null, $isRelative = true)
	{
		if (is_array($get_variables)) {
			$linker = new Linker($destination);

			foreach ($get_variables as $key => $value) {
				$linker->add($key, $value);
			}

			if ($isRelative) {
				$linker->protocol = '';
				$linker->hostname = '';
				$path = './';
			} else {
				if (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') {
					$linker->protocol = 'https';
				} else {
					$linker->protocol = 'http';
				}

				$linker->hostname = $_SERVER['HTTP_HOST'];

				if (dirname($_SERVER['PHP_SELF']) == '/') {
					$path = '/';
				} else {
					$path = dirname($_SERVER['PHP_SELF']) . '/';
				}
				$linker->filename = $path . $destination;
			}
			header('Location: ' . $linker->getLink());
			exit;
		} elseif ($get_variables == null) {
			$linker = new Linker($destination);
			header('Location: ' . $linker->getLink());
			exit;
		}

		return false;
	}

	/**
	 * Prints one or more errormessages on screen
	 *
	 * @param array $errors
	 *            Errormessages
	 * @param string $replacer
	 *            A %s in the errormessage will be replaced by this string.
	 * @param bool $throw_exception
	 *
	 * @throws Exception
	 * @author Ron Brand <ron.brand@web.de>
	 * @author Florian Lippert <flo@syscp.org> (2003-2009)
	 */
	public static function standardError($errors = '', $replacer = '', $throw_exception = false)
	{
		$_SESSION['requestData'] = $_POST;
		$replacer = htmlentities($replacer);

		if (!is_array($errors)) {
			$errors = [
				$errors
			];
		}

		$link_ref = '';
		if (isset($_SERVER['HTTP_REFERER']) && strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) !== false) {
			$link_ref = htmlentities($_SERVER['HTTP_REFERER']);
		}

		$error = '';
		foreach ($errors as $single_error) {
			if (strpos($single_error, ".") === false) {
				$single_error = 'error.' . $single_error;
			}
			$single_error = lng($single_error, [htmlentities($replacer)]);
			if (empty($error)) {
				$error = $single_error;
			} else {
				$error .= ' ' . $single_error;
			}
		}

		if ($throw_exception) {
			throw new Exception(strip_tags($error), 400);
		}
		UI::view('misc/alert.html.twig', [
			'type' => 'danger',
			'btntype' => 'light',
			'heading' => lng('error.error'),
			'alert_msg' => $error,
			'redirect_link' => $link_ref
		]);
		exit;
	}

	public static function dynamicError($message, bool $nosession = false)
	{
		$_SESSION['requestData'] = $_POST;
		$link_ref = '';
		if (isset($_SERVER['HTTP_REFERER']) && strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) !== false) {
			$link_ref = htmlentities($_SERVER['HTTP_REFERER']);
		}

		$tpl = $nosession ? 'misc/alert_nosession.html.twig' : 'misc/alert.html.twig';
		UI::view($tpl, [
			'type' => 'danger',
			'btntype' => 'light',
			'heading' => lng('error.error'),
			'alert_msg' => $message,
			'redirect_link' => $link_ref
		]);
		exit;
	}

	/**
	 * Prints one or more errormessages on screen
	 *
	 * @param array $success_message
	 *            Errormessages
	 * @param string $replacer
	 *            A %s in the errormessage will be replaced by this string.
	 * @param array $params
	 * @param bool $throw_exception
	 *
	 * @throws Exception
	 * @author Florian Lippert <flo@syscp.org> (2003-2009)
	 */
	public static function standardSuccess($success_message = '', $replacer = '', $params = [], $throw_exception = false)
	{
		if (strpos($success_message, ".") === false) {
			$success_message = 'success.' . $success_message;
		}
		$success_message = lng($success_message, [htmlentities($replacer)]);

		if ($throw_exception) {
			throw new Exception(strip_tags($success_message), 200);
		}

		if (is_array($params) && isset($params['filename'])) {
			$redirect_url = $params['filename'];
			unset($params['filename']);

			$first = true;
			foreach ($params as $varname => $value) {
				if ($value != '') {
					$redirect_url .= ($first ? '?' : '&amp;') . $varname . '=' . $value;
					if ($first) {
						$first = false;
					}
				}
			}
		} else {
			$redirect_url = '';
		}

		UI::view('misc/alert.html.twig', [
			'type' => 'success',
			'btntype' => 'light',
			'heading' => lng('success.success'),
			'alert_msg' => $success_message,
			'redirect_link' => $redirect_url
		]);
		exit;
	}
}
