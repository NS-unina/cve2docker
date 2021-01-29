package com.lprevidente.cve2docker.api;

import com.lprevidente.cve2docker.entity.vo.github.FileVO;
import com.lprevidente.cve2docker.entity.vo.github.RepoVO;
import com.lprevidente.cve2docker.entity.vo.github.SearchCodeVO;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;
import retrofit2.http.Url;

import java.util.List;

public interface GitHubAPI {
  @GET("repos/{owner}/{repository}")
  Call<RepoVO> getRepositoryInformation(
      @Path(value = "owner", encoded = true) String owner,
      @Path(value = "repository", encoded = true) String repository);

  @GET("search/code")
  Call<SearchCodeVO> searcCode(
      @Query(value = "q", encoded = true) String query,
      @Query(value = "page") Integer page,
      @Query(value = "per_page") Integer per_page);

  @GET("repositories/{repositoryID}/contents/{path}")
  Call<FileVO> getContent(
      @Path(value = "repositoryID") Long repositoryId, @Path(value = "path") String path);

  @GET("repositories/{repositoryID}/contents/{path}")
  Call<List<FileVO>> getContents(
      @Path(value = "repositoryID") Long repositoryId, @Path(value = "path") String path);
}
