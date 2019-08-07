# Auth0.js Implicit

A utility for Auth0 implicit authentication flows in a route-enabled single-page-app.

## Install 

`yarn add auth0-js-implicit`

## Examples

### [Live Demo](https://brietsparks.github.io/auth0-js-implicit-example)

### [Source](https://github.com/brietsparks/auth0-js-implicit-example)

## Use

1. create an Auth0 WebAuth client instance.
    ```js
    import auth0 from 'auth0-js';
    
    const client = new auth0.WebAuth({ 
      domain: '<auth0-domain>.auth0.com', 
      clientID: '<auth0-client-id>', 
      audience: '<auth0-api-identifier>',
      redirectUri: window.location.origin + '/<login-callback-path>'
    });
    ```

2. instantiate the helper, passing in the client and the url Auth0 redirects to upon logout.
    ```js
    const logoutReturnLocation = window.location.origin + '/logged-out';
    export const authenticator = new Authenticator(client, logoutReturnLocation);
    ```

## API

The helper instance contains the following methods to help create authentication flows.

### `authenticate`

```js
authenticate(currentLocation?: string): Promise<{ userId?, accessToken?, expiresAt?, redirectTo? }>
```
Call this at the beginning of a page that should run authentication. 


Given no arguments, it will try to authenticate the user, but if no valid credentials are found then it will
not show the Auth0 login page. Use this to initialize authentication state that allows for anonymous users.
```js
authenticate().then(result => ...)
```

Given a string of the current location, it will try to authenticate the user, and if no valid credentials
are found then it will show an Auth0 login prompt. Use this for an auth wall.

```js
authenticate('/current-route').then(result => ...)
```

### `handleLoginSuccess`

```js
handleLoginSuccess(): Promise<{ accessToken, userId, expiresAt, redirectTo }>
```
Call this at the login-callback page. It will store the access token and expiration 
in the browser and resolve to a promise containing the auth data and the route where
authentication was initiated (e.g. "/current-route" from `authenticate('/current-route')`).
Use this string to redirect to the location the user logged in from.

### `promptLogin`

```js
promptLogin(currentLocation: string, opts: auth0.AuthorizeOptions = {}): void
```
This imperatively shows the Auth0 login page. Accepts a string of the current location
and options passed to Auth0's `authorize` method.

### `logout`
This clears the auth data from the browser storage and class the Auth0 `logout` function
to clear the session from the Auth0 server.
