<?php

namespace Pionect\SecurityHeaders\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Pionect\SecurityHeaders\Providers\ContentSecurityPolicyServiceProvider;
use Pionect\SecurityHeaders\Providers\SecurityHeadersServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            ContentSecurityPolicyServiceProvider::class,
            SecurityHeadersServiceProvider::class,
        ];
    }
}
