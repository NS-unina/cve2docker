package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.api.DockerHubAPI;
import com.lprevidente.cve2docker.entity.vo.dockerhub.*;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class DockerHubService {

  @Value("${spring.config.dockerhub.base-url}")
  private String BASE_PATH;

  @Value("${spring.config.dockerhub.max-page-size}")
  private Integer MAX_PAGE_SIZE;

  private DockerHubAPI dockerHubAPI;

  @PostConstruct
  public void initRetrofit() {
    var okHttpClient =
        new OkHttpClient()
            .newBuilder()
            .connectTimeout(120, TimeUnit.SECONDS)
            .readTimeout(120, TimeUnit.SECONDS)
            .build();

    Retrofit retrofit =
        new Retrofit.Builder()
            .baseUrl(BASE_PATH)
            .client(okHttpClient)
            .addConverterFactory(JacksonConverterFactory.create())
            .build();
    dockerHubAPI = retrofit.create(DockerHubAPI.class);
  }

  /**
   * Return the most popular repo for the text provided. The popularity is based on star and pull
   * count.
   *
   * @param text what to search
   * @return <b>null</b> if the repo doesn't exist
   * @throws IOException throw when there is a problem performing the request or the
   *     deserialization.
   */
  public SearchRepoVO.ResultVO getMostPopularRepo(@NonNull String text) throws IOException {
    SearchRepoVO searchRepoVO =
        this.searchRepos(text, 1, MAX_PAGE_SIZE); // TODO: manage other pages?
    if (searchRepoVO == null || searchRepoVO.getCount() == 0) return null;

    if (searchRepoVO.getCount() > 1)
      searchRepoVO
          .getResults()
          .sort(
              Comparator.comparingLong(SearchRepoVO.ResultVO::getStar_count)
                  .thenComparingLong(SearchRepoVO.ResultVO::getPull_count)
                  .reversed());
    return searchRepoVO.getResults().get(0);
  }

  /**
   * Get the list of repositories for the text provided.
   *
   * @param text what to search
   * @param pageSize how many repos in the response. The maximum is 100 if not specified.
   * @param page the page number
   * @return <b>null</b> if the response is not ok
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public SearchRepoVO searchRepos(@NonNull String text, int page, Integer pageSize)
      throws IOException {
    log.info(
        "[searchRepos] Request to DockerHub - Params: text = {} pageSize = {} page = {}",
        text,
        pageSize,
        page);
    Response<SearchRepoVO> response = dockerHubAPI.searchRepos(text, page, pageSize).execute();
    log.info("[searchRepos] Response from DockerHub {}", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Get the list of all repositories for the text provided.
   *
   * @param text what to search
   * @return an <b>empty</b> list if case of error.
   */
  public List<SearchRepoVO.ResultVO> searchRepos(@NonNull String text) {
    int page = 1;
    SearchRepoVO searchRepo;
    var repos = new ArrayList<SearchRepoVO.ResultVO>();
    try {
      do {
        searchRepo = searchRepos(text, page, MAX_PAGE_SIZE);
        if (searchRepo != null) {
          repos.addAll(searchRepo.getResults());
          page++;
        }
      } while (searchRepo != null && repos.size() < searchRepo.getCount());
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return repos;
  }

  /**
   * Get the list of tags for the repo provided.
   *
   * @param text what to search. In case of all tags text should be empty or null.
   * @param pageSize how many repos in the response. The maximum is 100 if not specified.
   * @param page the page number
   * @return <b>null</b> if the response is not Successful
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public SearchTagVO searchTags(
      String owner,
      @NonNull String repository,
      String text,
      int page,
      Integer pageSize,
      String ordering)
      throws IOException {
    if (StringUtils.isBlank(owner)) owner = "library";
    log.debug(
        "[searchTags] Request to DockerHub - Params: owner = {}  repository = {}  text = {} page = {}  pageSize = {}",
        owner,
        repository,
        text,
        pageSize,
        page);
    Response<SearchTagVO> response =
        dockerHubAPI.searchTags(owner, repository, text, page, pageSize, ordering).execute();
    log.debug("[searchTags] Response from DockerHub {}", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Get the Tags correspondent to the repo provided where the text is contained in its name.
   *
   * @param owner The name of owner of repository. Can be null
   * @param repository The name of repository
   * @param text what should be contained in the name of the tag. In case of null or empty all tags
   *     are compared.
   * @return <b>empty</b> list if not the tag exist
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public List<SearchTagVO.TagVO> searchTags(
      String owner, @NonNull String repository, String text) throws IOException {
    int page = 1;
    SearchTagVO searchRepo;
    var tags = new ArrayList<SearchTagVO.TagVO>();
    try {
      do {
        searchRepo = searchTags(owner, repository, text, page, MAX_PAGE_SIZE, null);
        if (searchRepo != null) {
          tags.addAll(searchRepo.getResults());
          page++;
        }
      } while (searchRepo != null && tags.size() < searchRepo.getCount());
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return tags;
  }

  /**
   * Get the Tags correspondent to the repo provided where the text is contained in its name.
   *
   * @param repoFullName The complete name of the repo owner/repository
   * @param text what should be contained in the name of the tag. In case of null or empty all tags
   *     are compared.
   * @return <b>empty</b> list if not the tag exist
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   * @throws IllegalArgumentException throws when the repoFullName is not correct
   */
  public List<SearchTagVO.TagVO> searchTags(@NonNull String repoFullName, String text)
      throws IOException, IllegalArgumentException {
    var split = repoFullName.split("/");
    String owner;
    String repoName;
    if (split.length == 1) {
      owner = null;
      repoName = repoFullName;
    } else if (split.length == 2) {
      owner = split[0];
      repoName = split[1];
    } else
      throw new IllegalArgumentException("Cannot getRepo: repoFullName not in the right format");
    return searchTags(owner, repoName, text);
  }

  /**
   * Return {@link RepoVO} with more information about the repo
   *
   * @param owner The owner of the repo
   * @param repository The name of the repo
   * @return <b>null</b> if the response is not Successful
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public RepoVO getRepo(@NonNull String owner, @NonNull String repository) throws IOException {
    log.debug(
        "[getRepo] Request to DockerHub - Params: owner = {}  repository = {}", owner, repository);
    Response<RepoVO> response = dockerHubAPI.getRepo(owner, repository).execute();
    log.debug("[getRepo] Response from DockerHub {}", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Return {@link RepoVO} with more information about the repo
   *
   * @param repoFullName The complete name of the repo owner/repository
   * @return <b>null</b> if the response is not Successful
   * @throws IOException throws when there is a problem performing the request or the *
   *     deserialization.
   * @throws IllegalArgumentException throws when the repoFullName is not correct
   */
  public RepoVO getRepo(@NonNull String repoFullName) throws IOException, IllegalArgumentException {
    log.debug("[getRepo] Request to DockerHub - Params: repoFullName = {}", repoFullName);
    var split = repoFullName.split("/");
    if (split.length != 2)
      throw new IllegalArgumentException("Cannot getRepo: repoFullName not in the right format");
    var owner = split[0];
    var repoName = split[1];
    Response<RepoVO> response = dockerHubAPI.getRepo(owner, repoName).execute();
    log.debug("[getRepo] Response from DockerHub {}", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Return {@link SourceRepositoryVO} with information about the various sources of the repository
   *
   * @param repoFullName The complete name of the repo
   * @return <b>null</b> If the response is not Successful
   * @throws IOException When there is a problem performing the request or the * deserialization.
   */
  public SourceRepositoryVO getSourceRepository(@NonNull String repoFullName) throws IOException {
    log.debug(
        "[getSourceRepository] Request to DockerHub - Params: repoFullName = {}", repoFullName);
    Response<SourceRepositoryVO> response =
        dockerHubAPI.getSourceRepository(repoFullName).execute();
    log.debug("[getSourceRepository] Response from DockerHub {} ", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Return {@link SourceRepositoryVO.ObjectVO} related to Github, in case doesn't exist return
   * null.
   *
   * @param repoFullName The complete name of the repo
   * @return <b>null</b> If the source doesn't exist;
   */
  public SourceRepositoryVO.ObjectVO getGitHubSourceRepository(@NonNull String repoFullName) {
    SourceRepositoryVO.ObjectVO githubSource = null;
    try {
      final var sources = getSourceRepository(repoFullName);
      if (sources != null)
        githubSource =
            sources.getObjects().stream()
                .filter((source) -> source.getProvider().equals("Github"))
                .findFirst()
                .orElse(null);
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return githubSource;
  }

  /**
   * Return the url used to download the docker file
   *
   * @param owner The name owner of repository
   * @param repository The name of repository
   * @return The url of dockerfile which is based on the DockerHub API.
   */
  public String getURLDockerfile(@NonNull String owner, @NonNull String repository) {
    return dockerHubAPI.getDockerfile(owner, repository).request().url().url().toString();
  }

  /**
   * Return {@link FileVO} with the content of dockerfile associated with the repo
   *
   * @param owner The name owner of repository
   * @param repository The name of repository
   * @return <b>null</b> if the response is not Successful
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public FileVO getDockerfile(@NonNull String owner, @NonNull String repository)
      throws IOException {
    log.debug("[getDockerfile] Request to DockerHub - Params: repoName = {}", repository);
    Response<FileVO> response = dockerHubAPI.getDockerfile(owner, repository).execute();
    log.debug("[getDockerfile] Response from DockerHub {}", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

}
