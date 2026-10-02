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

namespace Froxlor\UI\Panel;

use reflectionClass;
use RuntimeException;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class CustomReflection extends AbstractExtension
{

	/**
	 *
	 * {@inheritdoc}
	 */
	public function getFunctions()
	{
		return [
			new TwigFunction('call_static', [
				$this,
				'callStaticMethod'
			]),
			new TwigFunction('get_static', [
				$this,
				'getStaticProperty'
			])
		];
	}

	public function callStaticMethod($class, $method, array $args = [])
	{
		$refl = new reflectionClass($class);
		// Check that method is static AND public
		if ($refl->hasMethod($method) && $refl->getMethod($method)->isStatic() && $refl->getMethod($method)->isPublic()) {
			return call_user_func_array($class . '::' . $method, $args);
		}
		throw new RuntimeException(sprintf('Invalid static method call for class %s and method %s', $class, $method));
	}

	public function getStaticProperty($class, $property)
	{
		$refl = new reflectionClass($class);
		// Check that property is static AND public
		if ($refl->hasProperty($property) && $refl->getProperty($property)->isStatic() && $refl->getProperty($property)->isPublic()) {
			return $refl->getProperty($property)->getValue();
		}
		throw new RuntimeException(sprintf('Invalid static property get for class %s and property %s', $class, $property));
	}

	/**
	 *
	 * {@inheritdoc}
	 */
	public function getName()
	{
		return 'customreflection';
	}
}
