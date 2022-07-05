<?php

namespace Nfaiz\Cors\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

use Nfaiz\Cors\CorsService;

class CorsFilter implements FilterInterface
{
    protected $cors;

    public function __construct() {

        $config = config('Nfaiz\Cors\Config\Cors');

        $this->cors = new CorsService([
            'allowedHeaders'         => $config->allowedHeaders ?? ['*'],
            'allowedMethods'         => $config->allowedMethods ?? ['*'],
            'allowedOrigins'         => $config->allowedOrigins ?? ['*'],
            'allowedOriginsPatterns' => $config->allowedOriginsPatterns ?? [],
            'exposedHeaders'         => $config->exposedHeaders ?? [],
            'maxAge'                 => $config->maxAge ?? 0,
            'supportsCredentials'    => $config->supportsCredentials ?? false,
        ]);
    }

    public function before(RequestInterface $request, $arguments = null)
    {
        if ($this->cors->isPreflightRequest($request)) {
            $response = $this->cors->handlePreflightRequest($request);

            $this->cors->varyHeader($response, 'Access-Control-Request-Method');

            return $response;
        }
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        if (! $response->hasHeader('Access-Control-Allow-Origin')) {
            return $this->cors->addActualRequestHeaders($response, $request);
        }
    }
}