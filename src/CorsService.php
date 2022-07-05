<?php

/*
 * This file was originally part of fruitcake/php-cors
 *
 * (c) Alexander <iam.asm89@gmail.com>
 * (c) Barryvdh <barryvdh@gmail.com>
 * (c) Nfaiz
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nfaiz\Cors;

use CodeIgniter\HTTP\Request;
use CodeIgniter\HTTP\Response;

class CorsService
{
    protected array $allowedOrigins;
    protected array $allowedOriginsPatterns;
    protected array $allowedMethods;
    protected array $allowedHeaders;
    protected array $exposedHeaders;
    protected bool $supportsCredentials;
    protected ?int $maxAge;

    protected bool $allowAllOrigins;
    protected bool $allowAllMethods;
    protected bool $allowAllHeaders;

    /**
     * @param CorsInputOptions $options
     */
    public function __construct(array $options = [])
    {
        if ($options) {
            $this->setOptions($options);
        }
    }

    /**
     * @param CorsInputOptions $options
     */
    public function setOptions(array $options): void
    {
        $this->allowedOrigins = $options['allowedOrigins'];
        $this->allowedOriginsPatterns = $options['allowedOriginsPatterns'];
        $this->allowedMethods = $options['allowedMethods'];
        $this->allowedHeaders = $options['allowedHeaders'];
        $this->supportsCredentials = $options['supportsCredentials'] ?? false;
        $this->maxAge = is_int($options['maxAge']) ? $options['maxAge'] : null;
        $this->exposedHeaders = $options['exposedHeaders'];

        $this->normalizeOptions();
    }

    private function normalizeOptions(): void
    {
        // Normalize case
        $this->allowedHeaders = array_map('strtolower', $this->allowedHeaders);
        $this->allowedMethods = array_map('strtoupper', $this->allowedMethods);

        // Normalize ['*'] to true
        $this->allowAllOrigins = in_array('*', $this->allowedOrigins) ? true : false;
        $this->allowAllHeaders = in_array('*', $this->allowedHeaders) ? true : false;
        $this->allowAllMethods = in_array('*', $this->allowedMethods) ? true : false;

        // Transform wildcard pattern
        if (!$this->allowAllOrigins) {
            foreach ($this->allowedOrigins as $origin) {
                if (strpos($origin ?? '', '*') !== false) {
                    $this->allowedOriginsPatterns[] = $this->convertWildcardToPattern($origin);
                }
            }
        }
    }

    /**
     * Create a pattern for a wildcard, based on Str::is() from Laravel
     *
     * @see https://github.com/laravel/framework/blob/5.5/src/Illuminate/Support/Str.php
     * @param string $pattern
     * @return string
     */
    private function convertWildcardToPattern($pattern)
    {
        $pattern = preg_quote($pattern, '#');

        // Asterisks are translated into zero-or-more regular expression wildcards
        // to make it convenient to check if the strings starts with the given
        // pattern such as "*.example.com", making any string check convenient.
        $pattern = str_replace('\*', '.*', $pattern);

        return '#^' . $pattern . '\z#u';
    }

    public function isCorsRequest(Request $request): bool
    {
        return $request->hasHeader('Origin') && ! $this->isSameHost($request);
    }

    public function isPreflightRequest(Request $request): bool
    {
        return strtoupper($request->getMethod()) === 'OPTIONS' && $request->hasheader('Access-Control-Request-Method');
    }

    public function handlePreflightRequest(Request $request): Response
    {
        $response = new Response(config('App'));

        $response->setStatusCode(204);

        return $this->handleRequest($response, $request);
    }

    public function addPreflightRequestHeaders(Response $response, Request $request): Response
    {
        $this->configureAllowedOrigin($response, $request);

        if ($response->hasheader('Access-Control-Allow-Origin')) {
            $this->configureAllowCredentials($response, $request);

            $this->configureAllowedMethods($response, $request);

            $this->configureAllowedHeaders($response, $request);

            $this->configureMaxAge($response, $request);
        }

        return $response;
    }

    public function isOriginAllowed(Request $request): bool
    {
        if ($this->allowAllOrigins === true) {
            return true;
        }

        $origin = (string) $request->getHeaderLine('Origin');

        if (in_array($origin, $this->allowedOrigins)) {
            return true;
        }

        foreach ($this->allowedOriginsPatterns as $pattern) {
            if (preg_match($pattern, $origin)) {
                return true;
            }
        }

        return false;
    }

    public function addActualRequestHeaders(Response $response, Request $request): Response
    {
        $this->configureAllowedOrigin($response, $request);

        if ($response->hasheader('Access-Control-Allow-Origin')) {
            $this->configureAllowCredentials($response, $request);

            $this->configureExposedHeaders($response, $request);
        }

        return $response;
    }

    public function varyHeader(Response $response, string $header): Response
    {
        if (!$response->hasHeader('Vary')) {
            $response->setHeader('Vary', $header);
        } elseif (!in_array($header, explode(', ', (string) $response->getHeaderLine('Vary')))) {
            $response->setHeader('Vary', ((string) $response->headers->getHeaderLine('Vary')) . ', ' . $header);
        }

        return $response;
    }

    protected function configureAllowedOrigin(Response $response, Request $request): void
    { 
        if ($this->allowAllOrigins === true && ! $this->supportsCredentials) {
            // Safe+cacheable, allow everything
            $response->setHeader('Access-Control-Allow-Origin', '*');
        } elseif ($this->isSingleOriginAllowed()) {
            // Single origins can be safely set
            $response->setHeader('Access-Control-Allow-Origin', array_values($this->allowedOrigins)[0]);
        } else {
            // For dynamic headers, set the requested Origin header when set and allowed
            if ($this->isCorsRequest($request) && $this->isOriginAllowed($request)) {
                $response->setHeader('Access-Control-Allow-Origin', (string) $request->hasHeader('Origin'));
            }

            $this->varyHeader($response, 'Origin');
        }
    }

    protected function isSingleOriginAllowed(): bool
    {
        if ($this->allowAllOrigins === true || count($this->allowedOriginsPatterns) > 0) {
            return false;
        }

        return count($this->allowedOrigins) === 1;
    }

    protected function configureAllowedMethods(Response $response, Request $request): void
    {
        if ($this->allowAllMethods === true) {
            $allowMethods = strtoupper((string) $request->getHeaderLine('Access-Control-Request-Method'));
            $this->varyHeader($response, 'Access-Control-Request-Method');
        } else {
            $allowMethods = implode(', ', $this->allowedMethods);
        }

        $response->setHeader('Access-Control-Allow-Methods', $allowMethods);
    }

    protected function configureAllowedHeaders(Response $response, Request $request): void
    {
        if ($this->allowAllHeaders === true) {
            $allowHeaders = (string) $request->getHeaderLine('Access-Control-Request-Headers');
            $this->varyHeader($response, 'Access-Control-Request-Headers');
        } else {
            $allowHeaders = implode(', ', $this->allowedHeaders);
        }

        $response->setHeader('Access-Control-Allow-Headers', $allowHeaders);
    }

    protected function configureAllowCredentials(Response $response, Request $request): void
    {
        if ($this->supportsCredentials) {
            $response->setHeader('Access-Control-Allow-Credentials', 'true');
        }
    }

    protected function configureExposedHeaders(Response $response, Request $request): void
    {
        if ($this->exposedHeaders) {
            $response->setHeader('Access-Control-Expose-Headers', implode(', ', $this->exposedHeaders));
        }
    }

    protected function configureMaxAge(Response $response, Request $request): void
    {
        if ($this->maxAge !== null) {
            $response->setHeader('Access-Control-Max-Age', (string) $this->maxAge);
        }
    }

    protected function isSameHost(Request $request): bool
    {
        return $request->getHeaderLine('Origin') === config('App')->baseURL;
    }
}