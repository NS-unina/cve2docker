package com.lprevidente.cve2docker.api.interceptor;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;

public class BearerAuthInterceptor implements Interceptor {

  private final String token;

  public BearerAuthInterceptor(String token) {
    this.token = token;
  }

  @Override
  public Response intercept(Chain chain) throws IOException {
    Request authRequest =
        chain.request().newBuilder().addHeader("Authorization", "Bearer " + token).build();
    return chain.proceed(authRequest);
  }
}
