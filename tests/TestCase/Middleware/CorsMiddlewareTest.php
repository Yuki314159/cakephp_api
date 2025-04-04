<?php
declare(strict_types=1);

namespace App\Test\TestCase\Middleware;

use App\Middleware\CorsMiddleware;
use Cake\TestSuite\TestCase;

/**
 * App\Middleware\CorsMiddleware Test Case
 */
class CorsMiddlewareTest extends TestCase
{
    /**
     * Test subject
     *
     * @var \App\Middleware\CorsMiddleware
     */
    protected $Cors;

    /**
     * Test process method
     *
     * @return void
     * @uses \App\Middleware\CorsMiddleware::process()
     */
    public function testProcess(): void
    {
        $this->markTestIncomplete('Not implemented yet.');
    }
}
