package com.lprevidente.cve2docker.exception;

public class ConfigurationNotSupported extends Exception {
  public ConfigurationNotSupported() {}

  public ConfigurationNotSupported(String message) {
    super(message);
  }

  public ConfigurationNotSupported(String message, Throwable cause) {
    super(message, cause);
  }

  public ConfigurationNotSupported(Throwable cause) {
    super(cause);
  }

  public ConfigurationNotSupported(
      String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
