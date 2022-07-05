<?php

namespace Nfaiz\Cors\Config;

use CodeIgniter\Config\BaseConfig;

class Cors extends BaseConfig
{
    /*
    * Matches the request method. `['*']` allows all methods.
    */
    public $allowedMethods = ['*'];

    /*
     * Matches the request origin. `['*']` allows all origins. Wildcards can be used; eg `*.mydomain.com`
     */
    public $allowedOrigins = ['*'];

    /*
     * Patterns that can be used with `preg_match` to match the origin.
     */
    public $allowedOriginsPatterns = [];

    /*
     * Sets the Access-Control-Allow-Headers response header. `['*']` allows all headers.
     */
    public $allowedHeaders = ['*'];

    /*
     * Sets the Access-Control-Expose-Headers response header with these headers.
     */
    public $exposedHeaders = [];

    /*
     * Sets the Access-Control-Max-Age response header when > 0.
     */
    public $maxAge = 0;

    /*
     * Sets the Access-Control-Allow-Credentials header.
     */
    public $supportsCredentials = false;

}