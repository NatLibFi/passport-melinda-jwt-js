import {sign as jwtSign, type Algorithm, type JwtPayload, type Secret} from 'jsonwebtoken';
import {ExtractJwt, Strategy as JwtStrategy, type VerifiedCallback} from 'passport-jwt';

export class MelindaJwtStrategy extends JwtStrategy { }

export const jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('melinda');

interface CookieRequest {
	readonly cookies: Readonly<Record<string, unknown>>;
}

function isCookieRequest(value: unknown): value is CookieRequest {
	return (
		typeof value === 'object'
		&& value !== null
		&& 'cookies' in value
		&& typeof value.cookies === 'object'
		&& value.cookies !== null
	);
}

export const cookieExtractor = (req: unknown): string | null => {
	if (!isCookieRequest(req)) {
		return null;
	}

	const {melinda} = req.cookies;

	return typeof melinda === 'string' ? melinda : null;
};

export interface GenerateJwtTokenOptions {
	readonly secretOrPrivateKey?: Secret | false;
	readonly issuer?: string;
	readonly audience?: string;
	readonly algorithm?: Algorithm;
}

export function generateJwtToken(
	payload: JwtPayload | string,
	{secretOrPrivateKey = false, issuer = '', audience = '', algorithm = 'HS512'}: GenerateJwtTokenOptions
): string {
	if (secretOrPrivateKey === false) {
		throw new Error('Set secret or private key to passport!');
	}

	return jwtSign(payload, secretOrPrivateKey, {issuer, audience, algorithm, expiresIn: '120h'});
}

export function verify(decoded: unknown, done: VerifiedCallback): void {
	if (typeof decoded !== 'object' || decoded === null || !('id' in decoded)) {
		return done(new Error('Invalid jwt token!'), false);
	}

	const {id} = decoded;

	if (id === undefined) {
		return done(new Error('Invalid jwt token!'), false);
	}

	if (id) {
		return done(null, decoded);
	}

	return done(new Error('Jwt auth error'), false);
}
