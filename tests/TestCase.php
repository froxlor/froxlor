<?php

namespace Tests;

use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    // Tests run against the seeded fixtures (migrate:fresh --seed); rolling back each test
    // keeps them unchanged, so the suite can run repeatedly without reseeding.
    use DatabaseTransactions;
}
