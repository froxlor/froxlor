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

namespace Froxlor\Validate\Form;

use Froxlor\FileDir;
use Froxlor\Validate\Validate;

class Data
{
	public static function validateFormFieldText($fieldname, $fielddata, $newfieldvalue)
	{
		return self::validateFormFieldString($fieldname, $fielddata, $newfieldvalue);
	}

	public static function validateFormFieldPassword($fieldname, $fielddata, $newfieldvalue)
	{
		return self::validateFormFieldString($fieldname, $fielddata, $newfieldvalue);
	}

	public static function validateFormFieldString($fieldname, $fielddata, $newfieldvalue)
	{
		if (isset($fielddata['string_delimiter']) && $fielddata['string_delimiter'] != '') {
			$newfieldvalues = array_map('trim', explode($fielddata['string_delimiter'], $newfieldvalue));
			unset($fielddata['string_delimiter']);

			$returnvalue = true;
			foreach ($newfieldvalues as $single_newfieldvalue) {
				/**
				 * don't use tabs in value-fields, #81
				 */
				$single_newfieldvalue = str_replace("\t", " ", $single_newfieldvalue);
				$single_returnvalue = self::validateFormFieldString($fieldname, $fielddata, $single_newfieldvalue);
				if ($single_returnvalue !== true) {
					$returnvalue = $single_returnvalue;
					break;
				}
			}
		} else {
			$returnvalue = false;

			/**
			 * don't use tabs in value-fields, #81
			 */
			$newfieldvalue = str_replace("\t", " ", $newfieldvalue);

			if (isset($fielddata['string_type']) && $fielddata['string_type'] == 'mail') {
				$returnvalue = ($newfieldvalue == Validate::validateEmail($newfieldvalue));
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'url') {
				$returnvalue = ($newfieldvalue == Validate::validateUrl($newfieldvalue));
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'dir') {
				// check for empty value (it might be allowed)
				if (trim($newfieldvalue) == '') {
					$newfieldvalue = '';
					$returnvalue = 'stringmustntbeempty';
				} else {
					// add trailing slash to validate path if needed
					// refs #331
					if (substr($newfieldvalue, -1) != '/') {
						$newfieldvalue .= '/';
					}
					$returnvalue = ($newfieldvalue == FileDir::makeCorrectDir($newfieldvalue));
				}
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'confdir') {
				// check for empty value (it might be allowed)
				if (trim($newfieldvalue) == '') {
					$newfieldvalue = '';
					$returnvalue = 'stringmustntbeempty';
				} else {
					// add trailing slash to validate path if needed
					// refs #331
					if (substr($newfieldvalue, -1) != '/') {
						$newfieldvalue .= '/';
					}
					// if this is a configuration directory, check for stupidity of admins :p
					if (FileDir::checkDisallowedPaths($newfieldvalue) !== true) {
						$newfieldvalue = '';
						$returnvalue = 'givendirnotallowed';
					} else {
						$returnvalue = ($newfieldvalue == FileDir::makeCorrectDir($newfieldvalue));
					}
				}
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'file') {
				// check for empty value (it might be allowed)
				if (trim($newfieldvalue) == '') {
					$newfieldvalue = '';
					$returnvalue = 'stringmustntbeempty';
				} else {
					$returnvalue = ($newfieldvalue == FileDir::makeCorrectFile($newfieldvalue));
				}
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'filedir') {
				// check for empty value (it might be allowed)
				if (trim($newfieldvalue) == '') {
					$newfieldvalue = '';
					$returnvalue = 'stringmustntbeempty';
				} else {
					$returnvalue = (($newfieldvalue == FileDir::makeCorrectDir($newfieldvalue)) || ($newfieldvalue == FileDir::makeCorrectFile($newfieldvalue)));
				}
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'validate_ip') {
				// check for empty value (it might be allowed)
				if (trim($newfieldvalue) == '') {
					$newfieldvalue = '';
					$returnvalue = 'stringmustntbeempty';
				} else {
					$newfieldvalue = Validate::validate_ip2($newfieldvalue, true);
					$returnvalue = ($newfieldvalue !== false ? true : 'invalidip');
				}
			} elseif (isset($fielddata['string_type']) && $fielddata['string_type'] == 'validate_ip_incl_private') {
				// check for empty value (it might be allowed)
				if (trim($newfieldvalue) == '') {
					$newfieldvalue = '';
					$returnvalue = 'stringmustntbeempty';
				} else {
					$newfieldvalue = Validate::validate_ip2($newfieldvalue, true, 'invalidip', true, true, true);
					$returnvalue = ($newfieldvalue !== false ? true : 'invalidip');
				}
			} elseif (preg_match('/^[^\r\n\t\f\0]*$/D', $newfieldvalue)) {
				$returnvalue = true;
			}

			if (isset($fielddata['string_regexp']) && $fielddata['string_regexp'] != '') {
				if (preg_match($fielddata['string_regexp'], $newfieldvalue)) {
					$returnvalue = true;
				} else {
					$returnvalue = false;
				}
			}

			if (isset($fielddata['string_emptyallowed']) && $fielddata['string_emptyallowed'] === true && $newfieldvalue === '') {
				$returnvalue = true;
			} elseif (isset($fielddata['string_emptyallowed']) && $fielddata['string_emptyallowed'] === false && $newfieldvalue === '') {
				$returnvalue = 'stringmustntbeempty';
			}
		}

		if ($returnvalue === true) {
			return true;
		} elseif ($returnvalue === false) {
			return 'stringformaterror';
		} else {
			return $returnvalue;
		}
	}

	public static function validateFormFieldEmail($fieldname, $fielddata, $newfieldvalue)
	{
		$fielddata['string_type'] = 'mail';
		return self::validateFormFieldString($fieldname, $fielddata, $newfieldvalue);
	}

	public static function validateFormFieldUrl($fieldname, $fielddata, $newfieldvalue)
	{
		$fielddata['string_type'] = 'url';
		return self::validateFormFieldString($fieldname, $fielddata, $newfieldvalue);
	}

	public static function validateFormFieldCheckbox($fieldname, $fielddata, $newfieldvalue)
	{
		if ($newfieldvalue === '1' || $newfieldvalue === 1 || $newfieldvalue === true || strtolower($newfieldvalue) === 'yes' || strtolower($newfieldvalue) === 'ja' || $newfieldvalue === '0' || $newfieldvalue === 0 || $newfieldvalue === false || strtolower($newfieldvalue) === 'no' || strtolower($newfieldvalue) === 'nein' || strtolower($newfieldvalue) === '') {
			return true;
		} else {
			return 'noboolean';
		}
	}

	public static function validateFormFieldDate($fieldname, $fielddata, $newfieldvalue)
	{
		if ($newfieldvalue == '0000-00-00' || preg_match('/^(19|20)\d\d[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])$/', $newfieldvalue)) {
			$returnvalue = true;
		} else {
			$returnvalue = false;
		}

		return $returnvalue;
	}

	public static function validateFormFieldFile($fieldname, $fielddata, $newfieldvalue)
	{
		return true;
	}

	public static function validateFormFieldHidden($fieldname, $fielddata, $newfieldvalue)
	{
		/**
		 * don't show error on cronjob-timestamps changing
		 * because it might be possible that the cronjob ran
		 * while settings have been edited (bug #52)
		 */
		if ($newfieldvalue === $fielddata['value'] || $fieldname == 'system_last_tasks_run' || $fieldname == 'system_last_traffic_run' || $fieldname == 'system_lastcronrun') {
			return true;
		} else {
			return 'hiddenfieldvaluechanged';
		}
	}

	public static function validateFormFieldNumber($fieldname, $fielddata, $newfieldvalue)
	{
		if (isset($fielddata['min']) && (int)$newfieldvalue < (int)$fielddata['min']) {
			return ('intvaluetoolow');
		}

		if (isset($fielddata['max']) && (int)$newfieldvalue > (int)$fielddata['max']) {
			return ('intvaluetoohigh');
		}

		return true;
	}

	public static function validateFormFieldSelect($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = true;

		if (isset($fielddata['select_mode']) && $fielddata['select_mode'] == 'multiple') {
			$options = explode(',', $newfieldvalue);
			foreach ($options as $option) {
				$returnvalue = ($returnvalue && isset($fielddata['select_var'][$option]));
			}
		} else {
			$returnvalue = isset($fielddata['select_var'][$newfieldvalue]);
		}

		if ($returnvalue === true || (isset($fielddata['visible']) && $fielddata['visible'] == false)) {
			return true;
		} else {
			if (isset($fielddata['option_emptyallowed']) && $fielddata['option_emptyallowed']) {
				return true;
			}
			return 'not in option (field: ' . $fieldname . ')';
		}
	}

	public static function validateFormFieldTextarea($fieldname, $fielddata, $newfieldvalue)
	{
		$returnvalue = 'stringformaterror';

		if (isset($fielddata['string_regexp']) && $fielddata['string_regexp'] != '') {
			if (preg_match($fielddata['string_regexp'], $newfieldvalue)) {
				$returnvalue = true;
			}
		} elseif (preg_match('/^[^\0]*$/', $newfieldvalue)) {
			$returnvalue = true;
		}

		return $returnvalue;
	}

	public static function validateFormFieldImage($fieldname, $fielddata, $newfieldvalue)
	{
		// validation is handled in \Froxlor\Settings\Store::storeSettingImage()
		return true;
	}
}
