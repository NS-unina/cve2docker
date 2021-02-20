package com.lprevidente.cve2docker.api;

import com.lprevidente.cve2docker.entity.vo.dockerhub.*;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;

public interface DockerHubAPI {

  @GET("v2/search/repositories")
  Call<SearchRepoVO> searchRepos(
      @Query("query") String text,
      @Query("page") Integer page,
      @Query("page_size") Integer pageSize);

  @GET("v2/repositories/{owner}/{repository}/tags")
  Call<SearchTagVO> searchTags(
      @Path("owner") String owner,
      @Path("repository") String repository,
      @Query("name") String name,
      @Query("page") Integer page,
      @Query("page_size") Integer pageSize,
      @Query("ordering") String ordering);

  @GET("api/build/v1/source")
  Call<SourceRepositoryVO> getSourceRepository(@Query("image") String repoFullName);

  @GET("v2/repositories/{owner}/{repository}")
  Call<RepoVO> getRepo(@Path("owner") String owner, @Path("repository") String repository);

  @GET("v2/repositories/{owner}/{repository}/dockerfile")
  Call<FileVO> getDockerfile(@Path("owner") String owner, @Path("repository") String repository);
}
