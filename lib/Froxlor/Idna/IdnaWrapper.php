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

namespace Froxlor\Idna;

use Algo26\IdnaConvert\IdnaConvert;
use InvalidArgumentException;

/**
 * Class for wrapping a specific idna conversion class and offering a standard interface
 *
 * @author     Michael Duergner <michael@duergner.com> (2003-2009)
 */
class IdnaWrapper
{

	/**
	 * idna converter we use
	 *
	 * @var object
	 */
	private $idna_converter;

	/**
	 * Class constructor.
	 * Creates a new idna converter
	 */
	public function __construct()
	{
		// Instantiate it
		$this->idna_converter = new IdnaConvert();
	}

	/**
	 * Encode a domain name, an email address or a list of one of both.
	 *
	 * @param string $to_encode May be either a single domain name, e single email address or a list of one
	 *            separated either by ',', ';' or ' '.
	 *
	 * @return string Returns either a single domain name, a single email address or a list of one of
	 *         both separated by the same string as the input.
	 */
	public function encode(string $to_encode): string
	{
		$to_encode = $this->isUtf8($to_encode) ? $to_encode : mb_convert_encoding($to_encode, 'UTF-8');
		try {
			return $this->idna_converter->encode($to_encode);
		} catch (InvalidArgumentException $iae) {
			if ($iae->getCode() == 100) {
				return $to_encode;
			}
			throw $iae;
		}
	}

	/**
	 * check whether a string is utf-8 encoded or not
	 *
	 * @param string $string
	 *
	 * @return boolean
	 */
	private function isUtf8(string $string)
	{
		if (function_exists("mb_detect_encoding")) {
			if (mb_detect_encoding($string, 'UTF-8, ISO-8859-1') === 'UTF-8') {
				return true;
			}
			return false;
		}
		$strlen = strlen($string);
		for ($i = 0; $i < $strlen; $i++) {
			$ord = ord($string[$i]);
			if ($ord < 0x80) {
				continue; // 0bbbbbbb
			} elseif (($ord & 0xE0) === 0xC0 && $ord > 0xC1) {
				$n = 1; // 110bbbbb (exkl C0-C1)
			} elseif (($ord & 0xF0) === 0xE0) {
				$n = 2; // 1110bbbb
			} elseif (($ord & 0xF8) === 0xF0 && $ord < 0xF5) {
				$n = 3; // 11110bbb (exkl F5-FF)
			} else {
				// ungültiges UTF-8-Zeichen
				return false;
			}
			// $n Folgebytes? // 10bbbbbb
			for ($c = 0; $c < $n; $c++) {
				if (++$i === $strlen || (ord($string[$i]) & 0xC0) !== 0x80) {
					// ungültiges UTF-8-Zeichen
					return false;
				}
			}
		}
		// kein ungültiges UTF-8-Zeichen gefunden
		return true;
	}

	/**
	 * Decode a domain name, an email address or a list of one of both.
	 *
	 * @param string $to_decode May be either a single domain name, e single email address or a list of one
	 *            separated either by ',', ';' or ' '.
	 *
	 * @return string Returns either a single domain name, a single email address or a list of one of
	 *         both separated by the same string as the input.
	 */
	public function decode(string $to_decode): string
	{
		return $this->idna_converter->decode($to_decode);
	}
}
