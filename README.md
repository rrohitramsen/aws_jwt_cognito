AWS Cognito Json Web Token Parser and Validator.
==========================

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




