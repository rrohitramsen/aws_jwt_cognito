package com.aws.jwt.token;


import org.springframework.http.HttpStatus;

/**
 * Created by rohitkumar on 24/03/18.
 */
public class APIRestUtil {

    public static boolean isHTTPError(HttpStatus statusCode) {
        return statusCode.is4xxClientError() || statusCode.is5xxServerError();
    }
}
