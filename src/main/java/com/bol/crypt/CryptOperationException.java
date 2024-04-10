package com.bol.crypt;

/**
 * Wraps different JCA exceptions under a single umbrella.
 */
public class CryptOperationException extends RuntimeException {
    public CryptOperationException(String s, Throwable e) {
        super(s, e);
    }

    public CryptOperationException(String s) {
        super(s);
    }
}
