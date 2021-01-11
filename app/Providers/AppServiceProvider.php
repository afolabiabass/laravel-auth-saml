<?php

namespace App\Providers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        // https://stackoverflow.com/questions/54289010/azure-active-directory-sso-with-laravel
        Event::listen('Aacotroneo\Saml2\Events\Saml2LoginEvent', function (Saml2LoginEvent $event) {
            $messageId = $event->getSaml2Auth()->getLastMessageId();

            $user = $event->getSaml2User();
            $assertion = $user->getRawSamlAssertion();

            $inputs = [
                'sso_user_id' => $user->getUserId(),
                'username' => $user->getAttribute('http://schemas.microsoft.com/identity/claims/displayname'),
                'email' => $user->getAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'),
                'first_name' => $user->getAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'),
                'last_name' => $user->getAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'),
                'password' => Hash::make('secret'),
            ];

            $user = User::where('sso_user_id', $inputs['sso_user_id'])
                ->where('email', $inputs['email'])
                ->first();

            if (! $user) {
                $user = User::create($inputs);
                if ($user) {
                    Auth::guard('web')->login($user);
                } else {
                    Log::info('SAML USER Error');
                }
            } else {
                Auth::guard('web')->login($user);
            }
        });
    }
}
