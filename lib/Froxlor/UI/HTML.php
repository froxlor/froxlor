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

use Froxlor\Settings;

class HTML
{

	/**
	 * Build Navigation Sidebar
	 *
	 * @param array $navigation data
	 * @param array $userinfo the userinfo of the user
	 *
	 * @return array the content of the navigation bar according to user-permissions
	 */
	public static function buildNavigation(array $navigation, array $userinfo)
	{
		$returnvalue = [];

		// sanitize user-given input (url-manipulation)
		$req_page = Request::get('page');
		if (!empty($req_page) && is_array($req_page)) {
			$req_page = (string)array_shift($req_page);
		}
		// need to preserve this
		$_GET['page'] = $req_page;

		$req_action = Request::get('action');
		if (!empty($req_action) && is_array($req_action)) {
			$req_action = (string)array_shift($req_action);
		}
		// need to preserve this
		$_GET['action'] = $req_action;

		foreach ($navigation as $box) {
			if ((!isset($box['show_element']) || $box['show_element'] === true) && (!isset($box['required_resources']) || $box['required_resources'] == '' || (isset($userinfo[$box['required_resources']]) && ((int)$userinfo[$box['required_resources']] > 0 || $userinfo[$box['required_resources']] == '-1')))) {
				$navigation_links = [];
				$box_active = false;
				if (isset($box['url']) && $box['url'] == basename($_SERVER["SCRIPT_FILENAME"])) {
					$box_active = true;
				}
				foreach ($box['elements'] as $element) {
					if ((!isset($element['show_element']) || $element['show_element'] === true) && (!isset($element['required_resources']) || $element['required_resources'] == '' || (isset($userinfo[$element['required_resources']]) && ((int)$userinfo[$element['required_resources']] > 0 || $userinfo[$element['required_resources']] == '-1')))) {
						$target = '';
						$active = false;
						$navurl = '#';
						if (isset($element['url']) && trim($element['url']) != '') {
							if (isset($element['new_window']) && $element['new_window'] == true) {
								$target = ' target="_blank"';
							}

							if (
								((empty($req_page) && substr_count($element['url'], "page=") == 0) || (!empty($req_page) && substr_count($element['url'], "page=" . $req_page) > 0))
								&& substr_count($element['url'], basename($_SERVER["SCRIPT_FILENAME"])) > 0
							) {
								$active = true;
								$box_active = true;
							}

							$navurl = htmlspecialchars($element['url']);
							$navlabel = $element['label'];
							$icon = $element['icon'] ?? null;
						} else {
							$navlabel = $element['label'];
							$icon = $element['icon'] ?? null;
						}

						$navigation_links[] = [
							'url' => $navurl,
							'target' => $target,
							'active' => $active,
							'label' => $navlabel,
							'icon' => $icon,
							'add_shortlink' => $element['add_shortlink'] ?? null,
							'is_external' => $element['is_external'] ?? false,
						];
					}
				}

				if (!empty($navigation_links)) {
					$target = '';
					if (isset($box['url']) && trim($box['url']) != '') {
						if (isset($box['new_window']) && $box['new_window'] == true) {
							$target = ' target="_blank"';
						}

						$navurl = htmlspecialchars($box['url']);
						$navlabel = $box['label'];
						$icon = $box['icon'] ?? null;
					} else {
						$navurl = "#";
						$navlabel = $box['label'];
						$icon = $box['icon'] ?? null;
					}

					$returnvalue[] = [
						'url' => $navurl,
						'target' => $target,
						'label' => $navlabel,
						'icon' => $icon,
						'items' => $navigation_links,
						'active' => ((int)Settings::Get('panel.menu_collapsed') == 0 ? 1 : $box_active)
					];
				}
			}
		}

		return $returnvalue;
	}

	/**
	 * Return HTML Code for an option within a <select>
	 *
	 * @param string $title
	 *            The caption
	 * @param string $value
	 *            The Value which will be returned
	 * @param string $selvalue
	 *            Values which will be selected by default.
	 * @param bool $title_trusted
	 *            Whether the title may contain html or not
	 * @param bool $value_trusted
	 *            Whether the value may contain html or not
	 * @param int $id
	 * @param bool $disabled
	 *
	 * @return string HTML Code
	 *
	 * @deprecated
	 */
	public static function makeoption($title, $value, $selvalue = null, $title_trusted = false, $value_trusted = false, $id = null, $disabled = false)
	{
		if ($selvalue !== null && ((is_array($selvalue) && in_array($value, $selvalue)) || $value == $selvalue)) {
			$selected = 'selected="selected"';
		} else {
			$selected = '';
		}

		if ($disabled) {
			$selected .= ' disabled="disabled"';
		}

		if (!$title_trusted) {
			$title = htmlspecialchars($title);
		}

		if (!$value_trusted) {
			$value = htmlspecialchars($value);
		}

		$id_str = ' ';
		if ($id !== null) {
			$id_str = 'id="' . $id . '"';
		}

		$option = '<option value="' . $value . '" ' . $id_str . $selected . ' >' . $title . '</option>';
		return $option;
	}

	/**
	 * Output boolean confirm-dialog
	 *
	 * @param string $text
	 *            The question
	 * @param string $yesfile
	 *            File which will be called with POST if user clicks yes
	 * @param array $params
	 *            Values which will be given to $yesfile. Format: array(variable1=>value1, variable2=>value2,
	 *            variable3=>value3)
	 * @param string $replacer
	 *            value of a possible existing string-replacer in the question
	 * @param array $back_link
	 *
	 * @return string
	 * @author Froxlor team <team@froxlor.org> (2010-)
	 *
	 */
	public static function askYesNo(string $text, string $yesfile, array $params = [], string $replacer = '', array $back_link = [])
	{
		$text = lng('question.' . $text, [htmlspecialchars($replacer)]);

		Panel\UI::view('form/yesnoquestion.html.twig', [
			'action' => $yesfile,
			'url_params' => $params,
			'question' => $text,
			'back_link' => $back_link
		]);
		exit();
	}

	public static function askYesNoWithCheckbox(string $text, string $chk_text, string $yesfile, array $params = [], string $replacer = '', bool $show_checkbox = true)
	{
		$text = lng('question.' . $text, [htmlspecialchars($replacer)]);
		$chk_text = lng('question.' . $chk_text);

		Panel\UI::view('form/yesnoquestion.html.twig', [
			'action' => $yesfile,
			'url_params' => $params,
			'question' => $text,
			'with_checkbox' => [
				'chk_text' => $chk_text,
				'show' => $show_checkbox
			]
		]);
		exit();
	}

	public static function askOTP(string $text, string $targetfile, array $params = [], string $replacer = '', array $back_link = [])
	{
		$text = lng('question.' . $text, [htmlspecialchars($replacer)]);

		Panel\UI::view('form/otpquestion.html.twig', [
			'action' => $targetfile,
			'url_params' => $params,
			'question' => $text,
			'back_link' => $back_link
		]);
		exit();
	}

	public static function askUserPasswd(string $text, string $targetfile, array $params = [], string $replacer = '', array $back_link = [])
	{
		$text = lng('question.' . $text, [htmlspecialchars($replacer)]);

		Panel\UI::view('form/askuserpasswd.html.twig', [
			'action' => $targetfile,
			'url_params' => $params,
			'question' => $text,
			'back_link' => $back_link
		]);
		exit();
	}
}
