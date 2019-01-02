# BeyondAuth

BeyondAuth can be used as a forward authenticating agent to make Traefik or nginx (untested) an Identity Aware Proxy. Inspired by the BeyondCorp papers by Google.

## implementation
BeyondAuth uses OpenID connect to authenticate users and sets a domain cookie with a JWT after a successful login to persist logins. It currently is hard coded to use google as the provider. But it should be trivial to make this configurable as well.  
Every request made to the reverse proxy sends an additional request to BeyondAuth to verify if it is allowed or not.  
BeyondAuth is stateless, so no data store is needed. This does mean however that issued JWTs cannot be revoked, unless you change the secret and ALL JWTs will be revoked.
Every incoming requests is classified into groups, a user can be a member of multiple groups and a subdomain can grant access to multiple groups. So if a user is member of a group that is allowed access, the request is allowed.


## todo

- Write comprehensive readme
- Include example RBAC file
- document limitations
- make sure invalid TOML is ignored
- cleanup all private tokens


## example config

```
defaultPolicy = "deny" #default policy is always deny

[groups.admin]
domains = [ "gnur.nl" ]

[groups.anyone]
domains = [ "gmail.com", "example.com" ]

[groups.internal]
subnets = [ "10.0.0.0/8" ]

[groups.superadmin]
users = [ "boss@example.com" ]
domains = [ "onlyceos.com" ]


[hosts."s3.example.com"]
public = true

[hosts."traefik.example.com"]
public = false
allowedGroups = [ "admin" ]
```
