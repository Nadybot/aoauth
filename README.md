# aoauth

aoauth is a JWT-based authentication provider for Anarchy Online. A pre-hosted version is available at <https://aoauth.org>.

## Running

You can run aoauth yourself either inside a container or outside of one, but you should be running it on a Linux-based operating system. I haven't tested running this on Windows or MacOS, it might work, but it might as well not work.

No matter how you run it, after starting it, you can access aoauth at <http://localhost:4114>.

### Using a container

When running inside a container, you should create a new directory for the database files and encryption keys like so:

```bash
cd /where/i/want/my/data/to/be
# Create the directory for the data and enter it
mkdir aoauth && cd aoauth
# Create a directory for the database and create an empty database file
mkdir db && touch db/aoauth.db
# Create a new directory for the encryption keys and enter it
mkdir keys && cd keys
# Generate a new private and public key pair
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
openssl pkcs8 -topk8 -nocrypt -in private.pem -out private_new.pem
rm private.pem
mv private_new.pem private.pem
# Go back to the data directory
cd ..
```

Then, you can start the bot with the following command (`podman` is used for demonstration, `docker` will work just fine, too):

```bash
podman run --rm -it -p 4114:4114 -v $(pwd)/db:/db:Z -v $(pwd)/keys:/keys:Z -e BOT_USERNAME="abc" -e BOT_PASSWORD="def" -e BOT_CHARACTER="ghi" -e DATABASE_FILE="db/aoauth.db" quay.io/gelbpunkt/aoauth:latest
```

Make sure to use your actual in-game bot credentials instead of the example ones here. In case you want to run this _properly_ inside e.g. a systemd unit, replace `$(pwd)` with the full path to the `aoauth` directory you created.

### Building it yourself

The alternative to using a container is building it yourself - which will require some prerequisites.

You'll need to install a nightly rust compiler, like so:

```bash
# Install nightly rust toolchain
curl -sSf https://sh.rustup.rs | sh -s -- --profile minimal --component rust-src --default-toolchain nightly -y
# Add the binaries to $PATH
source $HOME/.cargo/env
```

Then, you need to download the sources and compile them:

```bash
# Download the source code
git clone https://github.com/Nadybot/aoauth
# Enter the source directory
cd aoauth
# Tell the compiler to compile for the default installed target
export CARGO_BUILD_TARGET=$(rustup target list --installed)
cargo build --release
```

You'll have to generate encryption keys:

```bash
cd keys
# Generate a new private a public key pair using OpenSSL
./generate.sh
cd ..
```

Next, you need to copy the example config file and fill it out:

```bash
# Copy the example config to config.json
cp config.example.json config.json
# Now, open config.json in an editor and fill it out
```

Finally, you can run aoauth like so:

```bash
./target/$CARGO_BUILD_TARGET/release/aoauth
```

## How it works

aoauth itself stores two kinds of data - accounts (usernames and hashes of the passwords) and characters (character name and ID for all characters linked to an account).

When verification for a character is requested, the user is given a tell command with a validation token to use in Anarchy Online to send a messages to aoauth's ingame bot, which will, upon receiving a valid token, add the character to the user's character list.

Any website that wants to know whether someone is _actually_ a specific character in Anarchy Online or just _who_ someone is in Anarchy Online can redirect the user to aoauth, which will let the user choose a character whose information (ID and name) will be handed back to the website requesting authentication. Additionally, to prevent issues with name changes, aoauth will make sure the character ID and name pair still belongs together when a character is chosen.

The website will receive a JSON Web Token (JWT), which is base64-encoded so it can be included in a URL. The contents will look like this:

```json
{
  "header": {
    "typ": "JWT",
    "alg": "ES256"
  },
  "payload": {
    "exp": 1634230289,
    "sub": {
      "id": 817294788,
      "name": "Yakuzy"
    }
  }
}
```

Every JWT has a header, which contains information about the signing algorithm used (here, ECDSA with 256-bit AES, which is an asymmetrical algorithm, so it's _very_ secure). The payload itself contains _exp_, which is the expiry of this data, usually 30 days, which is a fairly safe default. _sub_ refers to the subject, which is the character that was selected by the user.

The JWT has another part attached to it, the signature. This is essentially a bunch of data calculated with the private key of the aoauth server. Because only the aoauth server has the private key, noone else can tamper the payload and then re-sign it. The signature can be verified with the public key of the aoauth instance.

## HowTo for developers

Redirect your users to <https://aoauth.org/auth?redirect_uri=http://my-server/callback&application_name=My+website>, replacing `application_name` with the name of your website.

They will then be prompted to log in, if they haven't already, and then select a character to authenticate with.

After that, they are redirected to your specified `redirect_uri` with an `_aoauth_token` query string parameter that is a signed JWT token containing the character and expiry for this token. The public key to verify the signature, which is ECDSA with 256-bit AES, can be downloaded at the [https://aoauth.org/key](https://aoauth.org/key) endpoint. An example JWT payload can be found in the section before this one.

Then, you can for example set a cookie with the expiry included in the JSON payload and on each request from the client, validate the signature to make sure they are indeed who they claim to be and use the character included in the payload to perform actions on your backend.
