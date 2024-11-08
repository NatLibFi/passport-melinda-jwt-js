import {Strategy as JwtStrategy, ExtractJwt} from 'passport-jwt';
import {sign as jwtSign} from 'jsonwebtoken';

export class MelindaJwtStrategy extends JwtStrategy { }
export const jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('melinda');

export const cookieExtractor = (req) => {
  if (req && req.cookies) {
    return req.cookies.melinda || null;
  }

  return null;
};

export function generateJwtToken(payload, {secretOrPrivateKey = false, issuer = '', audience = '', algorithm = 'HS512'}) {
  if (secretOrPrivateKey === false) {
    throw new Error('Set secret or private key to passport!');
  }

  return jwtSign(payload, secretOrPrivateKey, {issuer, audience, algorithm, expiresIn: '120h'});
}

export function verify(decoded, done) {
  if (decoded.id === undefined) {
    return done(new Error('Invalid jwt token!'), false);
  }

  if (decoded.id) {
    return done(null, decoded);
  }

  return done(new Error('Jwt auth error'), false);
}
