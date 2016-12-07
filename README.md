# Ephemeral - The Secret Whisperer

Ever needed to send someone a password? You need it to be sent over a secure channel, so you rule out email, IM... Some platforms like lastpass need you to create an account, and that may be inconvenient. Also... how can you make sure the password wasn't intercepted?

Ephemeral - The Secret Whisperer tries to cover this gap. It doesn't need an account to be created, the secrets will be stored password-encrypted (yes, a password on the password), and they can be read just once, as they'll be deleted right after the first read. Also the secrets will have a TTL, they'll get deleted eventually, even if nobody reads them.

## Ephemeral v0.2 - First working version 
- Using cherrypy as a front-end and redis as store.
- Ajax for encrypting the secret with user's password, so it never leaves the browser unencrypted. Ephemeral will never be in touch with the unencrypted password
- Configurable TTL (right now is 1h for testing purposes)
- Can be tested at http://ephemeral.tomas.cat:6543 (no, there's no SSL yet, but we'll get there)

## Ephemeral v0.1 - Establishing requirements
### UI for storing a secret:
- In the homepage there's a form where you type your secret (should there be a length limitation?), and the password (optional). After submitting, it will give a URL back, the one you can send safely on an unsecure channel.

### UI for reading a secret:
- You receive a URL, you visit it, and it will ask for a password (even if the original secret didn't have one). After you type it, it will show a secret, even if the password was wrong.

### Behind the curtain
- When storing a secret, the URL and the password-encrypted secret will be stored in a key-value store (redis?)
- When reading a secret, we'll check if there's an entry for that URL in our key-value store. If there is, the site will ask for the password, it will decrypt the contents of the key-value store using that password and show them on the web. A secret will be shown even if the password was incorrect, so there's no indicator for a snooper. The value for that URL will be overwritten with a tombstone, so if anybody checks the same secret in a short period, they'll get a message "This secret was already revealed".
- The secrets will be stored with the app key, optionally adding a second layer of encryption with a user password.

### Possible architecture
- Python app using cherrypy, backed by a redis server (or cluster). No session info will be stored, that way the webservers can scale out if needed. Redis cluster can already scale out.
- REST api would need two calls. Something like: https://ephemeral.tld/store/THISISYOURSECRET/THISISTHESECRETPASSWORD for storing, and something like https://ephemeral.tld/read/URL/THISISTHESECRETPASSWORD for reading.
