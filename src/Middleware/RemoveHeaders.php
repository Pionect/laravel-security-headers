<?php

declare(strict_types = 1);

namespace TheRobFonz\SecurityHeaders\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RemoveHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);

        foreach ((array) config('security.remove') as $header) {
            $response->headers->remove(
                key: $header,
            );
        }

        return $response;
    }
}
