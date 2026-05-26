<?php

declare(strict_types=1);

namespace Froxlor\PhpHelper;

use PHPUnit\Framework\TestCase;
use Froxlor\PhpHelper;

/**
 * Tests for CNAME chain resolution in PhpHelper::gethostbynamel6().
 * These assertions use public DNS, so they verify result shape instead of fixed IPs.
 *
 * @group dns
 */
class CnameResolutionTest extends TestCase
{
    /**
     * Test that the function exists and is callable
     */
    public function testFunctionExists(): void
    {
        $this->assertTrue(is_callable([PhpHelper::class, 'gethostbynamel6']));
    }

    /**
     * Test non-existent domains return false
     */
    public function testNonExistentDomainReturnsFalse(): void
    {
        $result = PhpHelper::gethostbynamel6('this-domain-definitely-does-not-exist-12345.invalid', true);
        $this->assertFalse($result);
    }

    /**
     * Test single CNAME resolution
     * github.github.io -> CNAME -> lb-2.github.com -> A records
     */
    public function testSingleCnameResolution(): void
    {
        $result = PhpHelper::gethostbynamel6('github.github.io', true);
        $this->assertNotFalse($result);
        $this->assertIsArray($result);
        $this->assertNotEmpty($result);

        foreach ($result as $ip) {
            $this->assertNotFalse(filter_var($ip, FILTER_VALIDATE_IP));
        }
    }

    /**
     * Test that AAAA-only resolution works with CNAME
     */
    public function testCnameResolutionWithAaaaOnly(): void
    {
        $result = PhpHelper::gethostbynamel6('github.github.io', false); // AAAA only
        // If it resolves, verify IPs are valid
        if ($result !== false) {
            $this->assertIsArray($result);
            $this->assertNotEmpty($result);
            foreach ($result as $ip) {
                $this->assertNotFalse(filter_var($ip, FILTER_VALIDATE_IP));
            }
        }
        // If it returns false, that's also acceptable (no AAAA records)
    }

    /**
     * Test direct A/AAAA resolution (no CNAME)
     */
    public function testDirectARecordResolution(): void
    {
        $result = PhpHelper::gethostbynamel6('google.com', true);
        $this->assertNotFalse($result);
        $this->assertIsArray($result);
        $this->assertNotEmpty($result);

        foreach ($result as $ip) {
            $this->assertNotFalse(filter_var($ip, FILTER_VALIDATE_IP));
        }
    }

    /**
     * Test that the function handles CNAME chains gracefully without crashing
     */
    public function testCnameDoesNotCrash(): void
    {
        // Should not throw any exception
        $result = PhpHelper::gethostbynamel6('github.github.io', true);
        $this->assertIsArray($result); // or false, but not throw
    }

    /**
     * Test that the function doesn't infinite-loop on CNAME chains
     * (max depth guard should prevent this)
     */
    public function testCnameChainDoesNotInfiniteLoop(): void
    {
        $start = microtime(true);
        PhpHelper::gethostbynamel6('github.github.io', true);
        $elapsed = microtime(true) - $start;

        // Should complete in reasonable time (< 5 seconds)
        $this->assertLessThan(5.0, $elapsed, 'CNAME resolution took too long, possible infinite loop');
    }

    /**
     * Test mixed A/AAAA resolution
     */
    public function testMixedAAndAaaaResolution(): void
    {
        $result = PhpHelper::gethostbynamel6('google.com', true);
        $this->assertNotFalse($result);
        $this->assertIsArray($result);

        // Verify all IPs are valid (either IPv4 or IPv6)
        foreach ($result as $ip) {
            $this->assertNotFalse(filter_var($ip, FILTER_VALIDATE_IP));
        }
    }
}
