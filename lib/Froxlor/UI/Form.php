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

use Froxlor\CurrentUser;
use Froxlor\FroxlorTwoFactorAuth;
use Froxlor\Settings;
use Froxlor\Validate\Check;

class Form
{
	public static function buildForm(array $form, string $part = ''): array
	{
		$fields = [];

		if (\Froxlor\Validate\Form::validateFormDefinition($form)) {
			foreach ($form['groups'] as $groupname => $groupdetails) {
				// check for advanced mode sections
				if (isset($groupdetails['advanced_mode']) && $groupdetails['advanced_mode'] && (int)Settings::Get('panel.settings_mode') == 0) {
					continue;
				}
				// show overview
				if ($part == '' || $part == 'all') {
					if (isset($groupdetails['title']) && $groupdetails['title'] != '') {
						$fields[] = self::getFormOverviewGroupOutput($groupname, $groupdetails);
					}
				} elseif ($part != '' && $groupname == $part) {
					// only show one section
					/**
					 * this part checks for the 'websrv_avail' entry in the settings-array
					 * if found, we check if the current webserver is in the array.
					 * If this
					 * is not the case, we change the setting type to "hidden", #502
					 */
					$do_show = true;
					if (isset($groupdetails['websrv_avail']) && is_array($groupdetails['websrv_avail'])) {
						$websrv = Settings::Get('system.webserver');
						if (!in_array($websrv, $groupdetails['websrv_avail'])) {
							$do_show = false;
						}
					}

					// visible = Settings::Get('phpfpm.enabled') for example would result in false if not enabled
					// and therefore not shown as intended. Only check if do_show is still true as it might
					// be false due to websrv_avail
					if (isset($groupdetails['visible']) && $do_show) {
						$do_show = $groupdetails['visible'];
					}

					$fields['_group'] = [
						'title' => $groupdetails['title'] ?? 'unknown group',
						'do_show' => $do_show
					];

					if (\Froxlor\Validate\Form::validateFieldDefinition($groupdetails)) {
						// Collect form field output
						foreach ($groupdetails['fields'] as $fieldname => $fielddetails) {
							// check for advanced mode sections
							if (isset($fielddetails['advanced_mode']) && $fielddetails['advanced_mode'] && (int)Settings::Get('panel.settings_mode') == 0) {
								continue;
							}
							$fields[$fieldname] = self::getFormFieldOutput($fieldname, $fielddetails);
							$fields[$fieldname] = array_merge($fields[$fieldname], self::prefetchFormFieldData($fieldname, $fielddetails));
						}
					}
				}
			}
		}

		return $fields;
	}

	public static function getFormOverviewGroupOutput($groupname, $groupdetails)
	{
		$activated = true;
		if (isset($groupdetails['fields'])) {
			foreach ($groupdetails['fields'] as $fielddetails) {
				if (isset($fielddetails['overview_option']) && $fielddetails['overview_option'] == true) {
					if ($fielddetails['type'] != 'checkbox') {
						// throw exception here as this is most likely an internal issue
						// if we messed up the arrays
						Response::standardError('overviewsettingoptionisnotavalidfield', '', true);
					}
					$activated = (int)Settings::Get($fielddetails['settinggroup'] . '.' . $fielddetails['varname']);
					break;
				}
			}
		}

		$item = [
			'title' => $groupdetails['title'],
			'icon' => $groupdetails['icon'] ?? 'fa-solid fa-circle-question',
			'part' => $groupname,
			'activated' => $activated
		];

		/**
		 * this part checks for the 'websrv_avail' entry in the settings
		 * if found, we check if the current webserver is in the array.
		 * If this is not the case, we change the setting type to "hidden", #502
		 */
		if (isset($groupdetails['websrv_avail']) && is_array($groupdetails['websrv_avail'])) {
			$websrv = Settings::Get('system.webserver');
			if (!in_array($websrv, $groupdetails['websrv_avail'])) {
				$item['info'] = lng('serversettings.option_unavailable_websrv', [implode(", ", $groupdetails['websrv_avail'])]);
				$item['visible'] = false;
			}
		}

		return $item;
	}

	public static function getFormFieldOutput($fieldname, $fielddata): array
	{
		$returnvalue = [];
		if (is_array($fielddata) && isset($fielddata['type']) && $fielddata['type'] != '') {
			if (!isset($fielddata['value'])) {
				if (isset($fielddata['default'])) {
					$fielddata['value'] = $fielddata['default'];
				} else {
					$fielddata['value'] = null;
				}
			}

			// set value according to type
			switch ($fielddata['type']) {
				case 'select':
					$fielddata['selected'] = $fielddata['value'];
					unset($fielddata['value']);
					if (isset($fielddata['select_mode']) && $fielddata['select_mode'] == 'multiple') {
						$fielddata['selected'] = array_flip(explode(",", $fielddata['selected']));
					}
					break;
				case 'checkbox':
					$fielddata['checked'] = (bool)$fielddata['value'];
					$fielddata['value'] = 1;
					break;
			}

			/**
			 * this part checks for the 'websrv_avail' entry in the settings-array
			 * if found, we check if the current webserver is in the array.
			 * If this
			 * is not the case, we change the setting type to "hidden", #502
			 */
			$do_show = true;
			if (isset($fielddata['websrv_avail']) && is_array($fielddata['websrv_avail'])) {
				$websrv = Settings::Get('system.webserver');
				if (!in_array($websrv, $fielddata['websrv_avail'])) {
					$do_show = false;
					$fielddata['note'] = lng('serversettings.option_unavailable_websrv', [implode(", ", $fielddata['websrv_avail'])]);
				}
			}

			// visible = Settings::Get('phpfpm.enabled') for example would result in false if not enabled
			// and therefore not shown as intended. Only check if do_show is still true as it might
			// be false due to websrv_avail
			if (isset($fielddata['visible']) && $do_show) {
				$do_show = $fielddata['visible'];
				if (!$do_show) {
					$fielddata['note'] = lng('serversettings.option_unavailable');
				}
			}

			// OTP security validation for sensitive settings
			if (!Settings::Config('disable_otp_security_check') && isset($fielddata['required_otp']) && $do_show) {
				$otp_enabled_system = (bool)Settings::Get('2fa.enabled');
				$otp_enabled_user = (int)CurrentUser::getField('type_2fa') != 0;
				$do_show = !$fielddata['required_otp'] || ($otp_enabled_system && $otp_enabled_user);
				if (!$do_show) {
					$fielddata['note'] = lng('serversettings.option_requires_otp');
					if (!$otp_enabled_system) {
						$fielddata['disabled'] = true;
						$fielddata['note'] .= '<br>' . lng('2fa.2fa_not_activated');
					} elseif (!$otp_enabled_user) {
						$fielddata['disabled'] = true;
						$fielddata['note'] .= '<br>' . lng('2fa.2fa_not_activated_for_user');
					}
					// show field in any case
					$do_show = true;
				}
			}

			if (!$do_show) {
				$fielddata['visible'] = false;
			}

			$returnvalue = $fielddata;
		}
		return $returnvalue;
	}

	public static function prefetchFormFieldData($fieldname, $fielddata)
	{
		$returnvalue = [];
		if (is_array($fielddata) && isset($fielddata['type']) && $fielddata['type'] == 'select') {
			if ((empty($fielddata['select_var']) || !is_array($fielddata['select_var'])) && (isset($fielddata['option_options_method']))
			) {
				$returnvalue['select_var'] = call_user_func($fielddata['option_options_method']);
			}
		}
		return $returnvalue;
	}

	public static function processForm(&$form, &$input, $url_params = [], $part = null, bool $settings_all = false, $settings_part = null, bool $only_enabledisable = false)
	{
		if (\Froxlor\Validate\Form::validateFormDefinition($form)) {
			$submitted_fields = [];
			$changed_fields = [];
			$saved_fields = [];

			foreach ($form['groups'] as $groupname => $groupdetails) {
				if (($settings_part && $part == $groupname) || $settings_all || $only_enabledisable) {
					if (\Froxlor\Validate\Form::validateFieldDefinition($groupdetails)) {
						// Prefetch form fields
						foreach ($groupdetails['fields'] as $fieldname => $fielddetails) {
							if (!$only_enabledisable || isset($fielddetails['overview_option'])) {
								$groupdetails['fields'][$fieldname] = array_merge($fielddetails, self::prefetchFormFieldData($fieldname, $fielddetails));
								$form['groups'][$groupname]['fields'][$fieldname] = $groupdetails['fields'][$fieldname];
							}
						}
					}
				}
			}

			foreach ($form['groups'] as $groupname => $groupdetails) {
				if (($settings_part && $part == $groupname) || $settings_all || $only_enabledisable) {
					if (\Froxlor\Validate\Form::validateFieldDefinition($groupdetails)) {
						// Validate fields
						foreach ($groupdetails['fields'] as $fieldname => $fielddetails) {
							if (((isset($fielddetails['visible']) && $fielddetails['visible']) || !isset($fielddetails['visible'])) && (!$only_enabledisable || ($only_enabledisable && isset($fielddetails['overview_option'])))) {
								$newfieldvalue = self::getFormFieldData($fieldname, $fielddetails, $input);
								if ($newfieldvalue != $fielddetails['value']) {
									if (($error = \Froxlor\Validate\Form::validateFormField($fieldname, $fielddetails, $newfieldvalue)) !== true) {
										Response::standardError($error, $fieldname);
									} else {
										$changed_fields[$fieldname] = $newfieldvalue;
									}
								}

								$submitted_fields[$fieldname] = $newfieldvalue;
							}
						}
					}
				}
			}

			foreach ($form['groups'] as $groupname => $groupdetails) {
				if (($settings_part && $part == $groupname) || $settings_all || $only_enabledisable) {
					if (\Froxlor\Validate\Form::validateFieldDefinition($groupdetails)) {
						// Check fields for plausibility
						foreach ($groupdetails['fields'] as $fieldname => $fielddetails) {
							if (!isset($submitted_fields[$fieldname])) {
								// skip unset fields due to unavailability for this system/settings-set
								continue;
							}
							if (!$only_enabledisable || ($only_enabledisable && isset($fielddetails['overview_option']))) {
								if (($plausibility_check = self::checkPlausibilityFormField($fieldname, $fielddetails, $submitted_fields[$fieldname], $submitted_fields)) !== false) {
									if (is_array($plausibility_check) && isset($plausibility_check[0])) {
										if ($plausibility_check[0] == Check::FORMFIELDS_PLAUSIBILITY_CHECK_OK) {
											// Nothing to do here, everything's okay
										} elseif ($plausibility_check[0] == Check::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR) {
											unset($plausibility_check[0]);
											$error = $plausibility_check[1];
											unset($plausibility_check[1]);
											$targetname = implode(' ', $plausibility_check);
											Response::standardError($error, $targetname);
										} elseif ($plausibility_check[0] == Check::FORMFIELDS_PLAUSIBILITY_CHECK_QUESTION) {
											unset($plausibility_check[0]);
											$question = $plausibility_check[1];
											unset($plausibility_check[1]);
											$targetname = implode(' ', $plausibility_check);
											if (!isset($input[$question])) {
												if (is_array($url_params) && isset($url_params['filename'])) {
													$filename = $url_params['filename'];
													unset($url_params['filename']);
												} else {
													$filename = '';
												}
												HTML::askYesNo($question, $filename, array_merge($url_params, $submitted_fields, [
													$question => $question
												]), $targetname);
											}
										} else {
											Response::standardError('plausibilitychecknotunderstood');
										}
									}
								}
								if (!Settings::Config('disable_otp_security_check') && isset($fielddetails['required_otp']) && isset($changed_fields[$fieldname])) {
									$otp_enabled_system = (bool)Settings::Get('2fa.enabled');
									$otp_enabled_user = (int)CurrentUser::getField('type_2fa') != 0;
									$do_update = !$fielddetails['required_otp'] || ($otp_enabled_system && $otp_enabled_user);
									if ($do_update) {
										// setting that requires OTP verification
										if (empty($input['otp_verification'])) {
											// in case email 2fa is enabled, send it now
											CurrentUser::sendOtpEmail();
											// build up form
											if (is_array($url_params) && isset($url_params['filename'])) {
												$filename = $url_params['filename'];
												unset($url_params['filename']);
											} else {
												$filename = '';
											}
											HTML::askOTP('please_enter_otp', $filename, array_merge($url_params, $submitted_fields));
										} else {
											// validate given OTP code
											$code = trim($input['otp_verification']);
											$tfa = new FroxlorTwoFactorAuth('Froxlor ' . Settings::Get('system.hostname'));
											$result = $tfa->verifyCode(CurrentUser::getField('data_2fa'), $code, 3);
											if (!$result) {
												Response::standardError('otpnotvalidated');
											}
										}
									} else {
										// do not update this setting
										unset($changed_fields[$fieldname]);
									}
								}

							}
						}
					}
				}
			}

			foreach ($form['groups'] as $groupname => $groupdetails) {
				if (($settings_part && $part == $groupname) || $settings_all || $only_enabledisable) {
					if (\Froxlor\Validate\Form::validateFieldDefinition($groupdetails)) {
						// Save fields
						foreach ($groupdetails['fields'] as $fieldname => $fielddetails) {
							if (!$only_enabledisable || (isset($fielddetails['overview_option']))) {
								if (isset($changed_fields[$fieldname])) {
									if (($saved_field = self::saveFormField($fieldname, $fielddetails, self::manipulateFormFieldData($fieldname, $fielddetails, $changed_fields[$fieldname]))) !== false) {
										$saved_fields = array_merge($saved_fields, $saved_field);
									} else {
										Response::standardError('errorwhensaving', $fieldname);
									}
								}
							}
						}
					}
				}
			}

			// Save form
			return self::saveForm($form, $saved_fields);
		}
		return false;
	}

	public static function getFormFieldData($fieldname, $fielddata, &$input)
	{
		if (is_array($fielddata) && isset($fielddata['type']) && $fielddata['type'] != '' && method_exists('\\Froxlor\\UI\\Data', 'getFormFieldData' . ucfirst($fielddata['type']))) {
			$newfieldvalue = call_user_func([
				'\\Froxlor\\UI\\Data',
				'getFormFieldData' . ucfirst($fielddata['type'])
			], $fieldname, $fielddata, $input);
		} else {
			if (isset($input[$fieldname])) {
				$newfieldvalue = $input[$fieldname];
			} elseif (isset($fielddata['default'])) {
				$newfieldvalue = $fielddata['default'];
			} else {
				$newfieldvalue = false;
			}
		}

		return trim($newfieldvalue);
	}

	public static function checkPlausibilityFormField($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		$returnvalue = '';
		if (is_array($fielddata) && isset($fielddata['plausibility_check_method']) && $fielddata['plausibility_check_method'] != '' && method_exists($fielddata['plausibility_check_method'][0], $fielddata['plausibility_check_method'][1])) {
			$returnvalue = call_user_func($fielddata['plausibility_check_method'], $fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues);
		} else {
			$returnvalue = false;
		}
		return $returnvalue;
	}

	public static function saveFormField($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = '';
		if (is_array($fielddata) && isset($fielddata['save_method']) && $fielddata['save_method'] != '') {
			$returnvalue = call_user_func([
				'\\Froxlor\\Settings\\Store',
				$fielddata['save_method']
			], $fieldname, $fielddata, $newfieldvalue);
		} elseif (is_array($fielddata) && !isset($fielddata['save_method'])) {
			$returnvalue = [];
		} else {
			$returnvalue = false;
		}
		return $returnvalue;
	}

	public static function manipulateFormFieldData($fieldname, $fielddata, $newfieldvalue)
	{
		if (is_array($fielddata) && isset($fielddata['type']) && $fielddata['type'] != '' && method_exists('\\Froxlor\\UI\\Data', 'manipulateFormFieldData' . ucfirst($fielddata['type']))) {
			$newfieldvalue = call_user_func([
				'\\Froxlor\\UI\\Data',
				'manipulateFormFieldData' . ucfirst($fielddata['type'])
			], $fieldname, $fielddata, $newfieldvalue);
		}

		return $newfieldvalue;
	}

	public static function saveForm($fielddata, $newfieldvalue)
	{
		$returnvalue = '';
		if (is_array($fielddata) && isset($fielddata['save_method']) && $fielddata['save_method'] != '') {
			$returnvalue = call_user_func([
				'\\Froxlor\\Settings\\Store',
				$fielddata['save_method']
			], $fielddata, $newfieldvalue);
		} elseif (is_array($fielddata) && !isset($fielddata['save_method'])) {
			$returnvalue = true;
		} else {
			$returnvalue = false;
		}
		return $returnvalue;
	}
}
