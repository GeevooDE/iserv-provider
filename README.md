# IServ

```bash
composer require geevoode/iserv-provider
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

### Add configuration to `config/services.php`

```php
'iserv' => [
    'client_id' => env('ISERV_CLIENT_ID'),
    'client_secret' => env('ISERV_CLIENT_SECRET'),
    'redirect' => env('ISERV_REDIRECT_URI')
],
```

### Add provider event listener

Configure the package's listener to listen for `SocialiteWasCalled` events.

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        \GeevooDE\IServ\IServExtendSocialite::class.'@handle',
    ],
];
```

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('iserv')->redirect();
```

### Returned User fields

- `id`
- `name`
- `email`

More fields are available under the `user` subkey:

```php
$user = Socialite::driver('iserv')->user();

$locale = $user->user['locale'];
$email_verified = $user->user['email_verified'];
```
