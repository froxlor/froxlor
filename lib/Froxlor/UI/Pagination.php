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

/**
 * Class to manage pagination, limiting and ordering
 */
class Pagination
{
	public string $sortorder = 'ASC';
	public $sortfield = null;
	private array $data = [];
	private ?array $fields = null;
	private ?string $searchtext = null;

	private $searchfield = null;

	private bool $is_search = false;

	private int $pageno = 0;

	private int $entries = 0;

	private int $perPage;

	private string $paginationAdditional = "";

	/**
	 * Create new pagination object to search/filter, limit and sort Api-listing() calls
	 *
	 * @param array $fields
	 * @param int $total_entries
	 * @param int $perPage
	 * @param array $default_sorting array of key=sortfield,value=sortorder for default sorting
	 * @param array $pagination_additional_params
	 */
	public function __construct(
		array $fields = [],
		int   $total_entries = 0,
		int   $perPage = 20,
		array $default_sorting = [],
		array $pagination_additional_params = []
	)
	{
		$this->fields = $fields;
		$this->entries = $total_entries;
		$this->perPage = $perPage;
		$this->pageno = 1;
		// add default limitation by settings
		if (Settings::Get('panel.paging') > 0) {
			$this->addLimit(Settings::Get('panel.paging'));
		}
		// check search request
		$this->searchtext = '';
		if (count($fields) > 0) {
			$orderfields = array_keys($fields);
			$this->searchfield = $orderfields[0];
		}
		$searchtext = Request::any('searchtext');
		if (isset($searchtext) && (preg_match('/[-_@\p{L}\p{N}*.]+$/u',	$searchtext) || $searchtext === '')) {
			$this->searchtext = trim($searchtext);
		}
		$searchfield = Request::any('searchfield');
		if (isset($searchfield) && isset($fields[$searchfield])) {
			$this->searchfield = $searchfield;
		}
		if (!empty($this->searchtext) && !empty($this->searchfield)) {
			$this->addSearch($this->searchtext, $this->searchfield);
			$pagination_additional_params[] = 'searchfield=' . $this->searchfield;
			$pagination_additional_params[] = 'searchtext=' . $this->searchtext;
		}

		// check other ordering requests
		$sortorder = Request::any('sortorder');
		if (!empty($sortorder) && (strtolower($sortorder) == 'desc' || strtolower($sortorder) == 'asc')) {
			$this->sortorder = strtoupper($sortorder);
		}
		$sortfield = Request::any('sortfield');
		if (!empty($sortfield) && isset($fields[$sortfield])) {
			$this->sortfield = $sortfield;
			$this->addOrderBy($this->sortfield, $this->sortorder);
		} else {
			// add default ordering by given order
			if (!empty($default_sorting)) {
				while (!empty($default_sorting)) {
					$this->sortfield = array_key_first($default_sorting);
					$this->sortorder = array_shift($default_sorting) ?? $this->sortorder;
					$this->addOrderBy($this->sortfield, $this->sortorder);
				}
			}
			// add default ordering by given fields
			if (count($fields) > 0 && empty($this->sortfield)) {
				$orderfields = array_keys($fields);
				$this->sortfield = $orderfields[0];
				$this->addOrderBy($orderfields[0], $this->sortorder);
			}
		}

		$this->checkPageNumber();

		// pagination additional parameters for url
		if (!empty($pagination_additional_params)) {
			foreach ($pagination_additional_params as $pap) {
				$this->paginationAdditional .= "&" . $pap;
			}
		}
	}

	private function checkPageNumber(): void
	{
		// check current page / pages
		$pageno = Request::any('pageno');
		if (!empty($pageno) && intval($pageno) != 0) {
			$this->pageno = intval($pageno);
		}
		if (($this->pageno - 1) * Settings::Get('panel.paging') > $this->entries) {
			$this->pageno = 1;
		}
		$this->addOffset(($this->pageno - 1) * Settings::Get('panel.paging'));
	}

	/**
	 * add a limit
	 *
	 * @param int $limit
	 *            optional, default 0
	 *
	 * @return Pagination
	 */
	public function addLimit(int $limit = 0): Pagination
	{
		$this->data['sql_limit'] = $limit;
		return $this;
	}

	/**
	 * add a search operation
	 *
	 * @param string|null $searchtext
	 * @param string|null $field
	 * @param string|null $operator
	 *
	 * @return Pagination
	 */
	public function addSearch(?string $searchtext = null, ?string $field = null, ?string $operator = null): Pagination
	{
		if (!isset($this->data['sql_search'])) {
			$this->data['sql_search'] = [];
		}
		$this->data['sql_search'][$field] = [
			'value' => $searchtext,
			'op' => $operator
		];
		// remember this is a search (-result)
		$this->is_search = true;
		return $this;
	}

	/**
	 * add a field for ordering
	 *
	 * @param string $field
	 * @param string $order optional, default 'ASC'
	 * @return Pagination
	 */
	public function addOrderBy($field = null, $order = 'ASC'): Pagination
	{
		if (!isset($this->data['sql_orderby'])) {
			$this->data['sql_orderby'] = [];
		}
		$this->data['sql_orderby'][$field] = $order;
		return $this;
	}

	/**
	 * add an offset
	 *
	 * @param int $offset optional, default 0
	 * @return Pagination
	 */
	public function addOffset(int $offset = 0): Pagination
	{
		$this->data['sql_offset'] = $offset;
		return $this;
	}

	/**
	 * return number of total entries the user can access from the current resource
	 *
	 * @return number
	 */
	public function getEntries(): int
	{
		return $this->entries;
	}

	public function setEntries(int $entries): void
	{
		$this->entries = $entries;
		$this->checkPageNumber();
	}

	public function getApiCommandParams(): array
	{
		return $this->data;
	}

	public function getApiResponseParams(): array
	{
		return [
			'pagination' => [
				"total" => $this->entries,
				"per_page" => $this->perPage,
				"current_page" => $this->pageno,
				"last_page" => (Settings::Get('panel.paging') > 0) ? ceil($this->entries / $this->perPage) : -1,
				"from" => $this->data['sql_offset'] ?? null,
				"to" => min($this->data['sql_offset'] + $this->perPage, $this->entries),
				"sortfields" => array_keys($this->fields),
				"link_additions" => $this->paginationAdditional,
			]
		];
	}

	public function isSearchResult(): bool
	{
		return $this->is_search;
	}
}
