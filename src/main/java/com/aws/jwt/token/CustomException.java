package com.aws.jwt.token;

import org.springframework.http.HttpStatus;

/**
 * Created by rohitkumar on 24/03/18.
 */
public class CustomException extends Exception {

    private HttpStatus httpStatus;

    public CustomException(HttpStatus httpStatus, String errorReason, String message) {
        super(errorReason + message);
    }
}
