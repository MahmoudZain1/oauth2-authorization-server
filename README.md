# OAuth2 Authorization Server with Spring Boot

A complete implementation of an OAuth2 Authorization Server using Spring Security with JWT tokens and OpenID Connect (OIDC) support.

## Features

- JWT-based authentication using RSA key pairs
- OAuth2 Authorization Code flow
- Custom JWT claims (including user roles)
- In-memory user management
- OIDC (OpenID Connect) support
- Multiple client authentication methods
- Configurable token lifetimes
- Integrated resource server secured with JWT

## Client Configuration

- Client ID: `client`
- Client Secret: `secret`
- Redirect URI: `http://127.0.0.1:8080/login/oauth2/code/client`
- Scopes: `openid`, `profile`, `email`, `read`, `write`, `admin`

## Endpoints

- Authorization: `http://localhost:8080/oauth2/authorize`
- Token: `http://localhost:8080/oauth2/token`
- JWK Set: `http://localhost:8080/oauth2/jwks`
- OIDC Discovery: `http://localhost:8080/.well-known/openid-configuration`
- Login Page: `http://localhost:8080/login`
- Protected Resource: `http://localhost:8080/demo`

## Authorization Code Flow

### Step 1: Authorization Request
Visit the following URL in a browser:

```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/client&scope=openid%20profile%20email%20read%20write
```

### Step 2: User Authentication
- Enter valid credentials from the pre-configured in-memory users
- Approve the requested scopes

### Step 3: Authorization Code
After login, the browser will redirect to:

```
http://127.0.0.1:8080/login/oauth2/code/client?code=AUTHORIZATION_CODE
```

### Step 4: Token Exchange
Use curl or Postman to exchange the authorization code for an access token:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Authorization: Basic Y2xpZW50OnNlY3JldA==" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://127.0.0.1:8080/login/oauth2/code/client"
```

### Step 5: Access Protected Resource
Use the returned access token to call a protected endpoint:

```bash
curl -X GET http://localhost:8080/demo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Token Configuration

| Token Type | Duration |
|------------|----------|
| Access Token | 5 minutes |
| Refresh Token | 30 days |
| Authorization Code | 2 minutes |

## JWT Example Payload

```json
{
  "sub": "Mahmoud",
  "aud": ["client"],
  "iss": "http://127.0.0.1:8080",
  "Roles": ["ROLE_ADMIN", "ROLE_USER"],
  "scope": ["openid"],
  "exp": 1752329191,
  "iat": 1752328891
}
```

## Testing Instructions

1. Start the Spring Boot application
2. Visit the authorization URL to get a code
3. Use curl to exchange the code for an access token
4. Use the access token to call the protected API /demo

## Security Notes

- JWT tokens are signed using RSA 2048-bit key pair
- JWT includes user roles as custom claims
