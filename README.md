# Passport authentication strategy for Melinda using jwt tokens

Melinda implementation of passport + jwt token authorization

## How to implement in server side

### Create JWT token
``` javascript
import {generateJwtToken} from '@natlibfi/passport-melinda-jwt';
const token: generateJwtToken(payload, {
  secretOrPrivateKey,
  issuer,
  audience,
  algorithm
});
```
* secretOrPrivateKey: secret
* issuer: String value of issuer
* audience: String value of audience
* algorithm: encryption method default: 'HS512'


### Check JWT token
``` javascript
import MelindaJwtStrategy, {verify, jwtFromRequest} from '@natlibfi/passport-melinda-jwt';

passport.use(new MelindaJwtStrategy({
  secretOrKey
  issuer,
  audience,
  algorithms,
  jwtFromRequest
}, verify));
```
* secretOrKey: secret
* issuer: String value of issuer
* audience: String value of audience
* algorithms: String array, e.g. ['HS512']
* jwtFromRequest: Function that gets token from request (Default contained in this repository)
* verify: Function to verify token content (Default contained in this repository)


## How to implement in client side
``` javascript
headers: {
  Authorization: token,
}
```
* Send token as authorization header in requests

## License and copyright

Copyright (c) 2021-2024 **University Of Helsinki (The National Library Of Finland)**

This project's source code is licensed under the terms of **MIT** or any later version.