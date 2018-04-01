package com.aws.jwt.token;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.http.HttpStatus;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

/**
 * @implNote AWS JWT Validator class.
 * @author rkumar2
 */
public class AwsCognitoJwtValidatorUtil {


    private AwsCognitoJwtValidatorUtil() {
    }

    /**
     * This validates the Aws Jwt Token using Nimbus Jose Jwt Library. For reference please see.
     * @see <a href= "https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-identity-user-pools-using-id-and-access-tokens-in-web-api"> AWS JWT Token</>
     * @param token
     * @return JWTClaimsSet
     */
    public static JWTClaimsSet validateAWSJwtToken(String token) throws ParseException, JOSEException, BadJOSEException, MalformedURLException, CustomException {

        /**
         * AwsCognitoJwtParserUtil class parse the jwt token and gives back the payload.
         */
        String jsonWebKeyFileURL = AwsCognitoJwtParserUtil.getJsonWebKeyURL(token);

        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWKSource jwkSource = null;
        jwkSource = new RemoteJWKSet(new URL(jsonWebKeyFileURL));
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
        JWSKeySelector keySelector = new JWSVerificationKeySelector(jwsAlgorithm, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);
        try {
            JWTClaimsSet claimsSet = jwtProcessor.process(token, null);
            return claimsSet;

        }catch (BadJWTException e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.TOKEN_EXPIRED, e.getLocalizedMessage());
        }

    }

    public static void main(String[] args) throws MalformedURLException, BadJOSEException, CustomException, ParseException, JOSEException {

        String token = "eyJraWQiOiIrdFFsSFYXC9lMnFmYzdoeFwvemhJanNHTzZ2VkE9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIlLTQ3MmYtODRhYi1iNGQwZTU0OGE1MGQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWRkcmVzcyI6eyJmb3JtYXR0ZWQiOiJFQzRNIDdMUyJ9LCJwcm9maWxlIjoiTUVNQkVSIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMi5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTJfcWhvbVdjNlJYIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoiNDI4Y2YwMDEtNTQ2ZS00NzJmLTg0YWItYjRkMGU1NDhhNTBkIiwiYXVkIjoiM2J2b25nb2hiY2ZpMTZmNW8zNHE3MnVkMXYiLCJldmVudF9pZCI6IjhkMDBjNmVkLTJkMWQtMTFlOC05ZDgxLTI3MDZlZTM1NjVlYyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTIxNjQ2NTU4LCJuYW1lIjoiVFFDRkQgVXNlcijE1MjE2NTAxNTgsImlhdCI6MTUyMTY0NjU1OCwiZW1haWwiOiJhYmNAeHl6LmNvbSJ9.JqCsBAO03PTgDx68GErueS9syYcBTbVyIgZ8x0Nsb7VgMdW6tE67H6Ma2eoaIK2FLQ3DOI3AECtJHSfi_dgWwXPdUn4xlR3HEKhSosIyZpRLNchPTgRSjI-vEY4DQJj4-JgyU2SdQXuAEaG8r-qEXy7Iy5pPVCIFt0Vi8YrMO2IzAbaReGqWu6bSjSfTt_VE-ZfPT5RTuWPuvG2mbeltHOirrreuZ652T-RbW6g7o-3QnJx0U887T_XLlqELdu8dNo5Cgmsbreu4KOnUCf6FG6LVOgI-mnewDqESYa07hn4NrnDG7LHtlmmFvonLn9Xq1p9xcw";

       /* JsonObject payload = getPayload(token);
        JsonObject header = getHeader(token);
        String  signature = getSignature(token);*/

        JWTClaimsSet jwtClaimsSet = AwsCognitoJwtValidatorUtil.validateAWSJwtToken(token);
        System.out.println(jwtClaimsSet.toJSONObject());
    }




}

