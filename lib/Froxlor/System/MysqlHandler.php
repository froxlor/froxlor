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

namespace Froxlor\System;

use Froxlor\Database\Database;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;

class MysqlHandler extends AbstractProcessingHandler
{

	protected static array $froxlorLevels = [
		Logger::DEBUG => LOG_DEBUG,
		Logger::INFO => LOG_INFO,
		Logger::NOTICE => LOG_NOTICE,
		Logger::WARNING => LOG_WARNING,
		Logger::ERROR => LOG_ERR,
		Logger::CRITICAL => LOG_ERR,
		Logger::ALERT => LOG_ERR,
		Logger::EMERGENCY => LOG_ERR
	];
	protected $pdoStatement = null;

	/**
	 * Constructor
	 *
	 * @param bool|int $level Debug level which this handler should store
	 * @param bool $bubble
	 */
	public function __construct($level = Logger::DEBUG, bool $bubble = true)
	{
		parent::__construct($level, $bubble);
	}

	/**
	 * Writes the record down to the log
	 *
	 * @param array $record
	 * @return void
	 */
	protected function write(array $record)
	{
		$this->insert([
			':message' => $record['message'],
			':contextUser' => ($record['context']['user'] ?? 'unknown'),
			':contextAction' => ($record['context']['action'] ?? '0'),
			':level' => self::$froxlorLevels[$record['level']],
			':datetime' => $record['datetime']->format('U')
		]);
	}

	/**
	 * Insert the data to the logger table
	 *
	 * @param array $data
	 * @return bool
	 */
	protected function insert(array $data): bool
	{
		if ($this->pdoStatement === null) {
			$sql = "INSERT INTO `panel_syslog` SET `text` = :message, `user` = :contextUser, `action` = :contextAction, `type` = :level, `date` = :datetime";
			$this->pdoStatement = Database::prepare($sql);
		}
		return $this->pdoStatement->execute($data);
	}
}
