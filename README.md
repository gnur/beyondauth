# BeyondAuth

BeyondAuth can be used as a forward authenticating agent to make Traefik or nginx (untested) an Identity Aware Proxy. Inspired by the BeyondCorp papers by Google.

## implementation
BeyondAuth uses OpenID Connect to authenticate users and sets a domain cookie with a JWT after a successful login to persist logins. As of v0.1 it has been tested to be compatible with Google, Auth0 and Keycloak.
Every request made to the reverse proxy sends an additional request to BeyondAuth to verify if it is allowed or not.  
BeyondAuth is stateless, so no data store is needed. This does mean however that issued JWTs cannot be revoked, unless you change the secret and ALL JWTs will be revoked.
Every incoming requests is classified into groups, a user can be a member of multiple groups and a subdomain can grant access to multiple groups. So if a user is member of a group that is allowed access, the request is allowed.


## todo

- Write comprehensive readme
- Create a better getKey function
- document example


## example config

see `example.toml`
