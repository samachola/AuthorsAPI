<?php

namespace App\Http\Middleware;

use Closure;
use Auth0\SDK\JWTVerifier;

class Auth0Middleware
{
    /**
     * Run the request filter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */

     public function handle($request, Closure $next)
     {
         if(!$request->hasHeader('Authorization'))
         {
             return response()->json('Authorization header not found', 401);
         }

         $token = $request->bearerToken();

         if($request->header('Authorization') == null || $token == null )
         {
             return response('No token provided', 401);
         }

         $this->retrieveAndValidate($token);

         return $next($request);
     }

     public function retrieveAndValidate($token)
     {
         try {  
             $verifier = new JWTVerifier([
                 'supported_algs' => ['RS256'],
                 'valid_audiences' => ['https://achola.com'],
                 'authorized_iss' => ['https://achola.eu.auth0.com/']
             ]);

             $decoded = $verifier->verifyAndDecode($token);

         } 
         catch(\Auth0\SDK\Exception\CoreException $e) {
             throw $e;
         }
     }
}
