<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Cors middleware
 */
class CorsMiddleware implements MiddlewareInterface
{
    /**
     * Process method.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param \Psr\Http\Server\RequestHandlerInterface $handler The request handler.
     * @return \Psr\Http\Message\ResponseInterface A response.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        // CORSヘッダを追加
        $response = $response->withHeader('Access-Control-Allow-Origin', '*')
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE')
            ->withHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        // Preflightリクエストの場合は200を返す
        if ($request->getMethod() === 'OPTIONS') {
            return $response->withStatus(200);
        }

        return $response;
    }
}
