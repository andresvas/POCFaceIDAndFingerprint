package com.todo.bc.pocfaceid;

public class CredentialResponse {

    private boolean error;
    private String message;
    private int code;

    public CredentialResponse(boolean error, String message, int code) {
        this.error = error;
        this.message = message;
        this.code = code;
    }

    public boolean isError() {
        return error;
    }

    public String getMessage() {
        return message;
    }

    public int getCode() {
        return code;
    }

}
