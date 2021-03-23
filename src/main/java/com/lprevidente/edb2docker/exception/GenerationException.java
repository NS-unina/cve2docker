package com.lprevidente.edb2docker.exception;

public class GenerationException extends Exception {

  public GenerationException(String message) {
    super(message);
  }

  public GenerationException(String message, Throwable cause) {
    super(cause);
  }

  public GenerationException(Throwable cause) {
    super(cause);
  }
}
