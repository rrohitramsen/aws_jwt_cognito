AWS Cognito Json Web Token Parser and Validator.
===============================================

`Parse and Validate ID Tokens and Access Tokens in your Web APIs`
----------------------------------------------------------------
###### `Since both the ID token and the access token are JSON Web Tokens (JWT), you may use any of the available JWT libraries to decode the JWT and verify the signature. For example, if your platform is Java, you could use the Nimbus JOSE and JWT library. The following procedure describes the high level steps you must implement to process the ID token and the access token on the server side.

###### To verify a signature for ID and access tokens

1. Download and store the JSON Web Key (JWK) for your user pool. You can locate it at https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json.

   Each JWK should be stored against its kid.

   Note

   - This is a one time step before your web APIs can process the tokens. Now you can perform the following steps each time the ID token or the access token are used against your web APIs.

2. Decode the token string into JWT format.

3. Check the iss claim. It should match your user pool. For example, a user pool created in the us-east-1 region will have an iss value of https://cognito-idp.us-east-1.amazonaws.com/{userPoolId}.

4. Check the token_use claim.

   - If you are only accepting the access token in your web APIs, its value must be access.

   - If you are only using the ID token, its value must be id.

   - If you are using both tokens, the value is either id or access.

5. Get the kid from the JWT token header and retrieve the corresponding JSON Web Key that was stored in step 1.

6. Verify the signature of the decoded JWT token.

7. Check the exp claim and make sure the token is not expired.


### Aws Token Parser, Use this class to parse Aws Cognito Jwt token.

```java
public class AwsCognitoJwtParserUtil {

    public static final String ISS = "iss";
    public static final String JWK_URl_SUFFIX = "/.well-known/jwks.json";
    public static final String JWK_FILE_PREFIX = "/jwk_";
    public static final String JWK_FILE_SUFFIX = ".json";


    private static final int HEADER = 0;
    private static final int PAYLOAD = 1;
    private static final int SIGNATURE = 2;
    private static final int JWT_PARTS = 3;

    /**
     * Returns header for a JWT as a JSON object.
     *
     * @param jwt  Required valid JSON Web Token as String.
     * @return AWS jwt header as a JsonObject.
     */
    public static JsonObject getHeader(String jwt) throws CustomException {
        try {
            validateJWT(jwt);
            String header = jwt.split("\\.")[HEADER];
            final byte [] headerBytes = Base64.getUrlDecoder().decode(header);
            final String headerString = new String(headerBytes, "UTF-8");
            JsonParser jsonParser = new JsonParser();
            JsonObject jsonObject = (JsonObject) jsonParser.parse(headerString);
            return jsonObject;
        }catch (UnsupportedEncodingException e){
            throw new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, jwt);
        }


    }

    /**
     * Returns payload of a JWT as a JSON object.
     *
     * @param jwt   Required valid JSON Web Token as String.
     * @return AWS jwt payload as a JsonObject.
     */
    public static JsonObject getPayload(String jwt) throws CustomException {
        try {
            validateJWT(jwt);
            final String payload = jwt.split("\\.")[PAYLOAD];
            final byte[] payloadBytes =  Base64.getUrlDecoder().decode(payload);
            final String payloadString = new String(payloadBytes, "UTF-8");
            JsonParser jsonParser = new JsonParser();
            JsonObject jsonObject = (JsonObject) jsonParser.parse(payloadString);
            return jsonObject;
        } catch ( UnsupportedEncodingException e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, jwt);
        }
    }

    /**
     * Returns signature of a JWT as a String.
     *
     * @param jwt  Required valid JSON Web Token as String.
     * @return AWS JWT signature as a String.
     */
    public static String getSignature(String jwt) throws CustomException {
        try {
            validateJWT(jwt);
            final String signature = jwt.split("\\.")[SIGNATURE];
            final byte[] signatureBytes = Base64.getUrlDecoder().decode(signature);
            return new String(signatureBytes, "UTF-8");
        } catch (final Exception e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, jwt);
        }
    }

    /**
     * Returns a claim, from the {@code JWT}s' payload, as a String.
     *
     * @param jwt Required valid JSON Web Token as String.
     * @param claim  Required claim name as String.
     * @return  claim from the JWT as a String.
     */
    public static String getClaim(String jwt, String claim) throws CustomException {
        try {
            final JsonObject payload = getPayload(jwt);
            final Object claimValue = payload.get(claim);

            if (claimValue != null) {
                return claimValue.toString();
            }

        } catch (final Exception e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, jwt);
        }
        return null;
    }

    /**
     * Checks if {@code JWT} is a valid JSON Web Token.
     *
     * @param jwt
     */
    public static void validateJWT(String jwt) throws CustomException {
        // Check if the the JWT has the three parts
        final String[] jwtParts = jwt.split("\\.");
        if (jwtParts.length != JWT_PARTS) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, jwt);
        }
    }


    /**
     * Parse the Jwt token and get the token issuer URL including user pool id.
     * @param token
     * @return Json Web Key URL
     * @throws CustomException
     */
    public static String getJsonWebKeyURL(String token) throws CustomException {

        JsonObject payload = AwsCognitoJwtParserUtil.getPayload(token);
        JsonElement issJsonElement = payload.get(ISS);
        if (Objects.isNull(issJsonElement)) {
            throw  new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, payload.toString());
        }

        String issString = issJsonElement.getAsString();
        String jwkURl = issString + JWK_URl_SUFFIX;

        return jwkURl;
    }

    /**
     * This method gets the JWK from AWS using token ISS.
     *
     * @param token
     * @return jwk.json Json Web Key file.
     */
    public static File getJsonWebKeyFile(String token) throws CustomException, IOException{

        JsonObject payload = AwsCognitoJwtParserUtil.getPayload(token);
        JsonElement issJsonElement = payload.get(ISS);
        if (Objects.isNull(issJsonElement)) {
            throw  new CustomException(HttpStatus.UNAUTHORIZED, AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, payload.toString());
        }

        String issString = issJsonElement.getAsString();
        String userPoolName = getUserPoolFromPayload(issString);
        String jwkURl = issString + JWK_URl_SUFFIX;

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> responseEntity = restTemplate.getForEntity(jwkURl, String.class);

        if (APIRestUtil.isHTTPError(responseEntity.getStatusCode())) {
            throw new CustomException(responseEntity.getStatusCode(), AuthenticationError.NOT_VALID_JSON_WEB_TOKEN, responseEntity.getBody());

        } else {

            Path resourceDirectory = Paths.get("src","main","resources");
            File file = new File(resourceDirectory + JWK_FILE_PREFIX + userPoolName + JWK_FILE_SUFFIX);

            if (file.exists()) {
                return file;
            }
            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                try {
                    file.createNewFile();
                    try (Writer writer = new FileWriter(file); BufferedWriter bufferedWriter = new BufferedWriter(writer)) {
                        bufferedWriter.write(responseEntity.getBody());
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }

            }

            return file;
        }

    }

    /**
     * Get the user pool from the iss url.
     * @param issUrl
     * @return ISS - token issuer URL.
     */
    private static String getUserPoolFromPayload(String issUrl) {

        String [] issArray = issUrl.split("amazonaws.com/");
        return issArray[1];
    }

}

```


### Aws Cognito Jwt validator, use this class to validate the token.

```java

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

        String token = "eyJraWQiOiIrdFFsSkJ2cnR1SndsTXhIUUVReEFYXC9lMnFmYzdoeFwvemhJanNHTzZ2VkE9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI0MjhjZjAwMS01NDZlLTQ3MmYtODRhYi1iNGQwZTU0OGE1MGQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWRkcmVzcyI6eyJmb3JtYXR0ZWQiOiJFQzRNIDdMUyJ9LCJwcm9maWxlIjoiTUVNQkVSIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMi5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTJfcWhvbVdjNlJYIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoiNDI4Y2YwMDEtNTQ2ZS00NzJmLTg0YWItYjRkMGU1NDhhNTBkIiwiYXVkIjoiM2J2b25nb2hiY2ZpMTZmNW8zNHE3MnVkMXYiLCJldmVudF9pZCI6IjhkMDBjNmVkLTJkMWQtMTFlOC05ZDgxLTI3MDZlZTM1NjVlYyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTIxNjQ2NTU4LCJuYW1lIjoiVFFDRkQgVXNlciIsInBob25lX251bWJlciI6Iis5MTk4OTAxMDUyNjIiLCJleHAiOjE1MjE2NTAxNTgsImlhdCI6MTUyMTY0NjU1OCwiZW1haWwiOiJhYmNAeHl6LmNvbSJ9.JqCsBAO03PTgDx68GErueS9syYcBTbVyIgZ8x0Nsb7VgMdW6tE67H6Ma2eoaIK2FLQ3DOI3AECtJHSfi_dgWwXPdUn4xlR3HEKhSosIyZpRLNchPTgRSjI-vEY4DQJj4-JgyU2SdQXuAEaG8yQPMh4jTQX3iaf2vr-qEXy7Iy5pPVCIFt0Vi8YrMO2IzAbaReGqWu6bSjSfTt_VE-ZfPT5RTuWPuvG2mbeltHOirrreuZ652T-RbW6g7o-3QnJx0U887T_XLlqELdu8dNo5Cgmsbreu4KOnUCf6FG6LVOgI-mnewDqESYa07hn4NrnDG7LHtlmmFvonLn9Xq1p9xcw";

       /* JsonObject payload = getPayload(token);
        JsonObject header = getHeader(token);
        String  signature = getSignature(token);*/

        JWTClaimsSet jwtClaimsSet = AwsCognitoJwtValidatorUtil.validateAWSJwtToken(token);
        System.out.println(jwtClaimsSet.toJSONObject());
    }

}


```





