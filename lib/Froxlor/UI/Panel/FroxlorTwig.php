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

use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\System\Markdown;
use Parsedown;
use Twig\Extension\AbstractExtension;
use Twig\TwigFilter;
use Twig\TwigFunction;
use Twig\TwigTest;

class FroxlorTwig extends AbstractExtension
{

	public function getFilters()
	{
		return [
			new TwigFilter('formatBytes', [
				$this,
				'formatBytesFilter'
			]),
			new TwigFilter('formatIP', [
				$this,
				'formatIPFilter'
			]),
			new TwigFilter('idnDecode', [
				$this,
				'idnDecodeFilter'
			]),
			new TwigFilter('markdown', [
				$this,
				'callMarkdown'
			])
		];
	}

	public function getTests()
	{
		return [
			new TwigTest('numeric', function ($value) {
				return is_numeric($value);
			})
		];
	}

	public function getFunctions()
	{
		return [
			new TwigFunction('get_setting', [
				$this,
				'getSetting'
			]),
			new TwigFunction('get_config', [
				$this,
				'getConfig'
			]),
			new TwigFunction('lng', [
				$this,
				'getLang'
			]),
			new TwigFunction('linker', [
				$this,
				'getLink'
			]),
			new TwigFunction('mix', [
				$this,
				'getMix'
			]),
			new TwigFunction('vite', [
				$this,
				'getVite'
			])
		];
	}

	public function formatBytesFilter($size, $suffix = "B", $factor = 1)
	{
		$size *= $factor;
		$units = [
			'',
			'K',
			'M',
			'G',
			'T',
			'P',
			'E',
			'Z',
			'Y'
		];
		$power = $size > 0 ? floor(log($size, 1024)) : 0;
		if ($power < 0) {
			$size = 0.00;
			$power = 0;
		}
		return number_format($size / pow(1024, $power), 2, '.', ',') . ' ' . $units[$power] . $suffix;
	}

	public function formatIPFilter($addr)
	{
		return inet_ntop(inet_pton($addr));
	}

	public function idnDecodeFilter($entity)
	{
		$idna_convert = new IdnaWrapper();
		return $idna_convert->decode($entity);
	}

	public function getSetting($setting = null)
	{
		return Settings::Get($setting);
	}

	public function getConfig($config = null)
	{
		return Settings::Config($config);
	}

	public function getLang($identifier = null, array $arguments = [])
	{
		return lng($identifier, $arguments);
	}

	public function getLink($linkopts)
	{
		return UI::getLinker()->getLink($linkopts);
	}

	public function callMarkdown($string): string
	{
		return Markdown::cleanCustomNotes($string ?? "");
	}

	/**
	 *
	 * {@inheritdoc}
	 */
	public function getName()
	{
		return 'froxlortwig';
	}

	public function getMix($mix = '')
	{
		return mix($mix);
	}

	public function getVite($basehref = '', $vite = [], $defaults = [])
	{
		return vite($basehref, $vite ?? $defaults);
	}
}
