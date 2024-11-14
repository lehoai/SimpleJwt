# SimpleJwt - A Lightweight Alternative to JJWT for Simple JWT Needs

`SimpleJwt` is a minimalistic library for creating, verifying, and decoding JSON Web Tokens (JWT) in Java, specifically using the HS256 (HMAC-SHA256) algorithm. If you find JJWT or other JWT libraries overly complex for your needs, `SimpleJwt` provides a straightforward solution for essential JWT functionality.
This project is ideal for developers who need a simple way to manage JWTs in Java without any extra dependencies.

## Features

- **Lightweight**: Avoids the complexity of larger libraries like JJWT.
- **Essential Functionality**: Supports token creation, verification, and payload decoding with HS256, a widely-used symmetric signing algorithm.
- **Ease of Use**: Simple, easy-to-use methods for handling JWTs.

## Usage
**Generate JWT**
```java
SimpleJwt.JwtBuilder jwtBuilder = new SimpleJwt.JwtBuilder();
String jwt = jwtBuilder.generateJwt("myemail@gmail.com", "thisismyverylongkey");
```
**Verify and get payload**
```java
SimpleJwt.JwtParser jwtParser = new SimpleJwt.JwtParser();
jwtParser.verifyToken(jwt, "thisismyverylongkey")
jwtParser.getPayload(jwt)
```

## License
MIT
