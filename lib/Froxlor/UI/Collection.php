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

class Collection
{
	private string $class;
	private array $has = [];
	private array $params;
	private array $userinfo;
	private ?Pagination $pagination = null;
	private bool $internal = false;

	public function __construct(string $class, array $userInfo, array $params = [])
	{
		$this->class = $class;
		$this->params = $params;
		$this->userinfo = $userInfo;
	}

	public function getList(): array
	{
		return $this->getData()['list'];
	}

	public function getData(): array
	{
		return $this->get()['data'];
	}

	public function get(): array
	{
		$result = $this->getListing($this->class, $this->params);

		// check if the api result contains any items (not the overall listingCount as we might be in a search-resultset)
		if (count($result)) {
			foreach ($this->has as $has) {
				$attributes = $this->getListing($has['class'], $has['params']);

				foreach ($result['data']['list'] as $key => $item) {
					foreach ($attributes['data']['list'] as $list) {
						if ($item[$has['parentKey']] == $list[$has['childKey']]) {
							$result['data']['list'][$key][$has['column']] = $list;
						}
					}
				}
			}
		}

		// attach pagination if available
		if ($this->pagination) {
			$result = array_merge($result, $this->pagination->getApiResponseParams());
		}

		return $result;
	}

	private function getListing($class, $params): array
	{
		return json_decode($class::getLocal($this->userinfo, $params, $this->internal)->listing(), true);
	}

	public function getJson(): string
	{
		return json_encode($this->get());
	}

	public function has(string $column, string $class, string $parentKey = 'id', string $childKey = 'id', array $params = []): Collection
	{
		$this->has[] = [
			'column' => $column,
			'class' => $class,
			'parentKey' => $parentKey,
			'childKey' => $childKey,
			'params' => $params
		];

		return $this;
	}

	public function addParam(array $keyval): Collection
	{
		$this->params = array_merge($this->params, $keyval);

		return $this;
	}

	public function withPagination(array $columns, array $default_sorting = [], array $pagination_additional_params = []): Collection
	{
		// Get only searchable columns
		$sortableColumns = [];
		foreach ($columns as $key => $column) {
			if (!isset($column['sortable']) || (isset($column['sortable']) && $column['sortable'])) {
				$sortableColumns[$key] = $column;
			}
		}

		// Prepare pagination
		$this->pagination = new Pagination($sortableColumns, $this->count(), (int)Settings::Get('panel.paging'), $default_sorting, $pagination_additional_params);
		$this->params = array_merge($this->params, $this->pagination->getApiCommandParams());
		$this->pagination->setEntries($this->count(true));
		return $this;
	}

	public function count(bool $with_pagination = false): int
	{
		if ($with_pagination) {
			$this->params = array_merge($this->params, $this->pagination->getApiCommandParams());
		}
		return json_decode($this->class::getLocal($this->userinfo, $this->params, $this->internal)->listingCount(), true)['data'];
	}

	public function getPagination(): ?Pagination
	{
		return $this->pagination;
	}

	public function setInternal(bool $internal): Collection {
		$this->internal = $internal;
		return $this;
	}
}
