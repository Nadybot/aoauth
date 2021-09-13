# aoauth

aoauth is a JWT-based authentication provider for Anarchy Online. A pre-hosted version is available at [https://aoauth.org](https://aoauth.org).

## Running

docker/podman:

```bash
podman pull quay.io/gelbpunkt/aoauth:latest
touch aoauth.db
cd keys
./generate.sh
cd ..
podman run --rm -it -p 4114:4114 -v $(pwd)/aoauth.db:/aoauth.db:Z -v $(pwd)/keys:/keys:Z -e BOT_USERNAME="abc" -e BOT_PASSWORD="def" -e BOT_PASSWORD="ghi" quay.io/gelbpunkt/aoauth:latest
```

## Flow

Redirect your users to [https://aoauth.org/auth?redirect_uri=http://my-server/callback&application_name=My+website](https://aoauth.org/authorize?redirect_uri=http://my-server/callback&application_name=My+website).

They will then be prompted to log in, if they haven't already, and then select a character to authenticate with.

After that, they are redirected to your specified "redirect_uri" with a "_aoauth_token" query string parameter that is a signed JWT token containing the character and expiry for this token. The public key to verify the signature can be found on the main page of the aoauth instance.
