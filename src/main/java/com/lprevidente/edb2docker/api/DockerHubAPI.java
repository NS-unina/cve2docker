package com.lprevidente.edb2docker.api;

import com.lprevidente.edb2docker.entity.vo.dockerhub.*;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;

public interface DockerHubAPI {

  @GET("v2/repositories/{owner}/{repository}/tags")
  Call<SearchTagVO> searchTags(
      @Path("owner") String owner,
      @Path("repository") String repository,
      @Query("name") String name,
      @Query("page") Integer page,
      @Query("page_size") Integer pageSize,
      @Query("ordering") String ordering);
}
