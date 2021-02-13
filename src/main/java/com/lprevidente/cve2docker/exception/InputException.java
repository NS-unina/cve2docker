package com.lprevidente.cve2docker.exception;

public class InputException extends Exception {
  public InputException() {}

  public InputException(String message) {
    super(message);
  }

  public InputException(String message, Throwable cause) {
    super(message, cause);
  }

  public InputException(Throwable cause) {
    super(cause);
  }

  public InputException(
      String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
