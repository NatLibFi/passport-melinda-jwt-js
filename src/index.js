/**
*
* @licstart  The following is the entire license notice for the JavaScript code in this file.
*
* Passport authentication strategy for Melinda using JWT tokens
*
* Copyright (C) 2018-2020 University Of Helsinki (The National Library Of Finland)
*
* This file is part of passport-melinda-jwt-js
*
* passport-melinda-jwt-js program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* passport-melinda-jwt-js is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* @licend  The above is the entire license notice
* for the JavaScript code in this file.
*
*/

import {Strategy as JwtStrategy, ExtractJwt} from 'passport-jwt';
import jwt from 'jsonwebtoken';

export default class extends JwtStrategy { }
export const jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('melinda');

export function generateJwtToken(payload, {secretOrPrivateKey = '', issuer = '', audience = '', algorithm = 'HS512'}) {
  // eslint-disable-next-line functional/immutable-data
  payload.name = undefined;
  // eslint-disable-next-line functional/immutable-data
  payload.organization = undefined;
  // eslint-disable-next-line functional/immutable-data
  payload.emails = undefined;
  // eslint-disable-next-line functional/immutable-data
  payload.exp = makeExpDate();
  return `melinda ${jwt.sign(payload, secretOrPrivateKey, {issuer, audience, algorithm})}`;

  function makeExpDate() {
    // eslint-disable-next-line no-var
    var date = new Date();
    const monday = (1 + 7 - date.getDay()) % 7;
    // eslint-disable-next-line functional/immutable-data
    date.setDate(date.getDate() + monday + 7);
    // eslint-disable-next-line functional/immutable-data
    date.setHours(0, 0, 0, 0);
    return date.getTime() / 1000;
  }
}

export function verify(decoded, done) {
  if (decoded.id === undefined) {
    return done(new Error('Invalid jwt token!'), false);
  }

  if (decoded.id) {
    // eslint-disable-next-line functional/immutable-data
    decoded.aud = undefined;
    // eslint-disable-next-line functional/immutable-data
    decoded.iss = undefined;
    return done(null, decoded);
  }

  return done(new Error('Jwt auth error'), false);
}
