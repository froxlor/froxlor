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

use RecursiveArrayIterator;
use RecursiveIteratorIterator;

class Language
{
	protected static ?array $lng = null;
	protected static string $defaultLanguage = 'en';
	protected static ?string $requestedLanguage = null;

	/**
	 * @return array
	 */
	public static function getLanguages(): array
	{
		$languages = [];
		$directory = dirname(__DIR__, 2) . '/lng';

		foreach (array_diff(scandir($directory), ['..', '.', 'index.html']) as $language) {
			$iso = explode('.', $language)[0];
			$languages[$iso] = self::getTranslation('languages.' . $iso);
		}

		return $languages;
	}

	public static function getTranslation(string $identifier, array $arguments = [])
	{
		// initialize
		if (is_null(self::$lng)) {
			// load fallback language
			self::$lng = self::loadLanguage(self::$defaultLanguage);

			// load user requested language
			if (self::$requestedLanguage) {
				self::$lng = array_merge(self::$lng, self::loadLanguage(self::$requestedLanguage));
			}

			// load fallback from browser if nothing requested
			$iso = trim(substr(strtok(strtok(($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'en'), ','), ';'), 0, 5));
			if (!self::$requestedLanguage && strlen($iso) == 2 && $iso !== self::$defaultLanguage) {
				self::$lng = array_merge(self::$lng, self::loadLanguage($iso));
			}
		}

		// shortcut for identifier with => [title, description]
		if (!isset(self::$lng[$identifier]) && isset(self::$lng[$identifier . '.title'])) {
			return [
				'title' => vsprintf(self::$lng[$identifier . '.title'] ?? $identifier, $arguments),
				'description' => vsprintf(self::$lng[$identifier . '.description'] ?? $identifier, $arguments),
			];
		}
		// search by identifier
		return vsprintf(self::$lng[$identifier] ?? $identifier, $arguments);
	}

	/**
	 * @TODO: Possible iso: de, de-DE, de-AT (fallback to de)
	 *
	 * @param $iso
	 * @return array
	 */
	private static function loadLanguage($iso): array
	{
		// Reject path traversal attempts
		if ($iso !== basename($iso) || str_contains($iso, '..')) {
			return [];
		}
		$languageFile = dirname(__DIR__, 2) . sprintf('/lng/%s.lng.php', $iso);

		if (!file_exists($languageFile)) {
			return [];
		}

		// load default language
		$lng = require $languageFile;

		// multidimensional array to dot notation keys
		$reItIt = new RecursiveIteratorIterator(new RecursiveArrayIterator($lng));
		$result = [];
		foreach ($reItIt as $leafValue) {
			$keys = [];
			foreach (range(0, $reItIt->getDepth()) as $depth) {
				$keys[] = $reItIt->getSubIterator($depth)->key();
			}
			$result[join('.', $keys)] = $leafValue;
		}

		return $result;
	}

	public static function setDefaultLanguage(string $string)
	{
		self::$defaultLanguage = $string;
	}

	public static function setLanguage(string $string)
	{
		self::$requestedLanguage = $string;
		self::$lng = null;
	}
}
