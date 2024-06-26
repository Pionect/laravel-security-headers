<?php

use Pionect\SecurityHeaders\Middleware\RemoveHeaders;
use Pionect\SecurityHeaders\SecurityHeadersGenerator;

/**
 * @see SecurityHeadersGenerator
 */
return [
    /**
     * Routes to exclude from the security header response
     */
    'excludes' => [
    ],

    /**
     * Used to enable or disable adding the security headers to the response
     */
    'enabled' => env('SECURITY_HEADERS', true),

    /**
     * These headers will be removed from the response @see RemoveHeaders
     */
    'remove' => [
        'X-Powered-By',
        'x-powered-by',
        'Server',
        'server',
    ],

    /**
     * These headers will be added to the response
     */
    'headers' => [
        /*
         * Used to indicate whether a browser should be allowed to render a page
         * in a <frame>, <iframe>, <embed> or <object>.
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
         */
        'X-Frame-Options' => 'sameorigin',

        /*
         * Used by the server to indicate that the MIME types advertised in the Content-Type headers
         * should not be changed and be followed.
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
         */
        'X-Content-Type-Options' => 'nosniff',

        /*
         * A feature of Internet Explorer, Chrome and Safari that stops pages from loading when
         * they detect reflected cross-site scripting (XSS) attacks.
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
         */
        'X-XSS-Protection' => '1; mode=block',

        /*
         * Lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
         */
        'Strict-Transport-Security' => 'max-age=2592000; includeSubDomains',

        /*
         * Governs which referrer information, sent in the Referer header, should be included with requests made.
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
         */
        'Referrer-Policy' => 'no-referrer-when-downgrade',

        /*
         * Provides a mechanism to allow and deny the use of browser features in its own frame, and in content
         * within any <iframe> elements in the document.
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy
         */
        'Feature-Policy' => [
            'geolocation' => 'none',
            'midi' => 'none',
            'microphone' => 'none',
            'sync-xhr' => 'self',
            'encrypted-media' => 'self',
            'camera' => 'none',
            'magnetometer' => 'none',
            'gyroscope' => 'none',
            'fullscreen' => 'self',
            'payment' => 'none',
            'usb' => 'none',
        ],

        /*
         * Allows website administrators to control resources the user agent is allowed to load for a given page.
         *
         * NOTE: The semicolon at the end of the policy will be automatically added as well as the nonce for script-src
         *
         * Options: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
         */
        'Content-Security-Policy' => [
            'default-src' => "'self'",
            'script-src' => "'self'",
            'style-src' => "'self'",
            'img-src' => "'self'",
            'font-src' => "'self'",
            'frame-src' => "'self'",
            'object-src' => "'self'",
            'connect-src' => "'self'",
        ],
    ],
];
