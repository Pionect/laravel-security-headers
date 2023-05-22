<?php

namespace Pionect\SecurityHeaders\Middleware;

use Closure;
use Illuminate\Http\Request;
use Pionect\SecurityHeaders\SecurityHeadersGenerator;
use Symfony\Component\HttpFoundation\Response;

class RespondWithSecurityHeaders
{
    public function __construct(
        protected SecurityHeadersGenerator $securityHeaders
    ) {
    }

    /**
     * Add security headers to the request
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        return $this->securityHeaders->attach($response);
    }
}
