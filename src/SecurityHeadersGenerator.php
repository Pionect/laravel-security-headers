<?php

declare(strict_types = 1);

namespace TheRobFonz\SecurityHeaders;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

class SecurityHeadersGenerator
{
    /**
     * The HTTP response
     */
    protected Response $response;

    public function __construct(
        protected Request $request
    ) {
    }

    /**
     * Generate a random string
     */
    public function attach(Response $response): Response
    {
        $this->response = $response;

        // don't attach the headers
        if (! $this->shouldAttachHeaders()) {
            return $response;
        }

        // add the headers to the response
        foreach (config('security.headers') as $header => $value) {
            if ($header === 'Content-Security-Policy') {
                $this->response->headers->set($header, $this->processContentSecurityPolicy($value));
            } else {
                $this->response->headers->set($header, $value);
            }
        }

        return $this->response;
    }

    /**
     * Determine if the request has a URI that should pass through CSRF verification.
     */
    private function inExceptArray(): bool
    {
        foreach (config('security.excludes') as $except) {
            if ($except !== '/') {
                $except = trim($except, '/');
            }

            if ($this->request->fullUrlIs($except) || $this->request->is($except)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Processes the content security policy
     */
    private function processContentSecurityPolicy(string|array $header): string
    {
        if (! is_array($header)) {
            return $header;
        }

        $csp = resolve('content-security-policy');

        foreach($header as $policy => $values) {
            $csp->add($policy, $values);
        }

        return $csp->generate();
    }

    /**
     * Decides if headers should be attached to the response
     */
    private function shouldAttachHeaders(): bool
    {
        $enabled = config()->has('security.enabled')
            ? config('security.enabled')
            : true;

        return property_exists($this->response, 'exception')
                    && ! $this->response->exception
                    && $enabled
                    && ! $this->inExceptArray()
                || ! property_exists($this->response, 'exception')
                    && $enabled
                    && ! $this->inExceptArray();
    }
}
