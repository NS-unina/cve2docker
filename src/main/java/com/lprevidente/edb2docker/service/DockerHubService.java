package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.api.DockerHubAPI;
import com.lprevidente.edb2docker.entity.vo.dockerhub.SearchTagVO;
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
   * Get the Tags correspondent to the repo provided where the tagToSearch is contained in its name.
   *
   * @param owner The name of owner of repository. Can be null
   * @param repository The name of repository
   * @param tagToSearch what should be contained in the name of the tag. In case of null or empty all tags
   *     are compared.
   * @return <b>empty</b> list if not the tag exist
   */
  public List<SearchTagVO.TagVO> searchTags(String owner, @NonNull String repository, String tagToSearch) {
    int page = 1;
    SearchTagVO searchRepo;
    var tags = new ArrayList<SearchTagVO.TagVO>();
    try {
      do {
        searchRepo = searchTags(owner, repository, tagToSearch, page, MAX_PAGE_SIZE, null);
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
   * Get the Tags correspondent to the repo provided where the tagToSearch is contained in its name.
   *
   * @param repoFullName The complete name of the repo owner/repository
   * @param tagToSearch what should be contained in the name of the tag. In case of null or empty all tags
   *     are compared.
   * @return <b>empty</b> list if not the tag exist
   * @throws IllegalArgumentException throws when the repoFullName is not correct
   */
  public List<SearchTagVO.TagVO> searchTags(@NonNull String repoFullName, String tagToSearch)
      throws IllegalArgumentException {
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
    return searchTags(owner, repoName, tagToSearch);
  }
}
