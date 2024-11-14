import io.jsonwebtoken.SimpleJwt;

public class SimpleJwtTest {

    public static void main(String[] args) throws Exception {
        SimpleJwt.JwtBuilder jwtBuilder = new SimpleJwt.JwtBuilder();
        String jwt = jwtBuilder.generateJwt("myemail@gmail.com", "thisismyverylongkey");
        System.out.println(jwt);

        SimpleJwt.JwtParser jwtParser = new SimpleJwt.JwtParser();
        System.out.println(jwtParser.verifyToken(jwt, "thisismyverylongkey"));
        System.out.println(jwtParser.getPayload(jwt));
    }
}
