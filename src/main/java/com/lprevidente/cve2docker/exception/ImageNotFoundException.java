package com.lprevidente.cve2docker.exception;

public class ImageNotFoundException extends GenerationException {
  public ImageNotFoundException(String message) {
    super("Docker image not found for " + message);
  }
}
