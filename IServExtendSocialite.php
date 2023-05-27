<?php

namespace GeevooDE\IServ;

use SocialiteProviders\Manager\SocialiteWasCalled;

class IServExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('iserv', Provider::class);
    }
}
