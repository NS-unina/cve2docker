package com.lprevidente.cve2docker.exception;

public class NoVulnerableAppException extends GenerationException {

  public NoVulnerableAppException() {
    super("No vulnerable App found");
  }
}
