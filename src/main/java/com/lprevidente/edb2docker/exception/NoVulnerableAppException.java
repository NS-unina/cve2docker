package com.lprevidente.edb2docker.exception;

public class NoVulnerableAppException extends GenerationException {

  public NoVulnerableAppException() {
    super("No vulnerable App found");
  }
}
