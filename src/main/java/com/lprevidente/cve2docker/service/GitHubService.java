package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.api.GitHubAPI;
import com.lprevidente.cve2docker.api.interceptor.BearerAuthInterceptor;
import com.lprevidente.cve2docker.entity.model.GitHubConfig;
import com.lprevidente.cve2docker.entity.pojo.FilePojo;
import com.lprevidente.cve2docker.entity.vo.github.FileVO;
import com.lprevidente.cve2docker.entity.vo.github.RepoVO;
import com.lprevidente.cve2docker.entity.vo.github.SearchCodeVO;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.*;

@Slf4j
@Service
public class GitHubService {

  private GitHubAPI gitHubAPI;

  @Value("${spring.config.github.base-url}")
  private String BASE_PATH;

  @Value("${spring.config.github.token}")
  private String TOKEN;

  @Value("${spring.config.github.max-page-size}")
  private Integer MAX_PAGE_SIZE;

  @Autowired private CVEService cveService;

  @PostConstruct
  public void initRetrofit() {
    OkHttpClient okHttpClient =
        new OkHttpClient.Builder().addInterceptor(new BearerAuthInterceptor(TOKEN)).build();
    Retrofit retrofit =
        new Retrofit.Builder()
            .client(okHttpClient)
            .baseUrl(BASE_PATH)
            .addConverterFactory(JacksonConverterFactory.create())
            .build();
    gitHubAPI = retrofit.create(GitHubAPI.class);
  }

  /**
   * Find the all configurations (docker-compose <i>or</i> dockerfile) there are in the repository.
   * The method explore the entire repository looking for one or more files where in the path there
   * is specified the CVE related. Each ExploitConfiguration has:
   *
   * <ul>
   *   <li>CVE
   *   <li>Author: the owner of the repository
   *   <li>Repo: the name of the repository
   *   <li>Source: Github
   *   <li>Type: Dockerfile or Docker-compose
   *   <li>Url: the url to api to download it
   * </ul>
   *
   * @param queryMap The query terms
   * @return an empty list if nothing has been found
   */
  public List<GitHubConfig> findConfigurations(@NonNull Map<String, String> queryMap) {
    List<GitHubConfig> configurations = new ArrayList<>();
    try {
      var file = searchInCode(generateQuery(queryMap));
      file.forEach(
          fileVO -> {
            try {
              var cveID = cveService.getCveIDFromString(fileVO.getPath());
              if (StringUtils.isBlank(cveID))
                cveID = cveService.getCveIDFromString(fileVO.getRepository().getFull_name());
              if (StringUtils.isNotBlank(cveID)) {
                GitHubConfig configuration = new GitHubConfig();

                var cve = cveService.getCVE(cveID);

                configuration.setCve(cve);
                configuration.setAuthor(fileVO.getRepository().getOwner().getLogin());
                configuration.setRepository(fileVO.getRepository().getName());
                configuration.setType(GitHubConfig.Type.parse(queryMap.get("filename")));
                configuration.setRepositoryID(fileVO.getRepository().getId());
                configuration.setPath(fileVO.getPath());

                configurations.add(configuration);
              }
            } catch (Exception e) {
              log.error("An exception occurred during analysis: {}", e.getMessage());
            }
          });
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getMessage());
    }
    return configurations;
  }

  /**
   * Find the all configurations (docker-compose and dockerfile) there are in the repository. The
   * method explore the entire repository looking for one or more files where in the path there is
   * specified the CVE related. Each GithubConfig has:
   *
   * <ul>
   *   <li>CVE
   *   <li>Author: the owner of the repository
   *   <li>Repo: the name of the repository
   *   <li>Source: Github
   *   <li>Type: Dockerfile or Docker-compose
   *   <li>Url: the url to api to download it
   * </ul>
   *
   * @param owner The name owner of repository
   * @param repository The name of repository
   * @return an empty list if nothing has been found
   */
  public ArrayList<GitHubConfig> findConfigurations(
      @NonNull String owner, @NonNull String repository) {
    var exploitList = new ArrayList<GitHubConfig>();
    try {
      // Searching for configurations in all repositories of user
      var map = new HashMap<String, String>();
      map.put("user", owner);
      map.put("filename", "docker-compose");
      exploitList.addAll(findConfigurations(map));

      map.replace("filename", "dockerfile");
      exploitList.addAll(findConfigurations(map));

      if (exploitList.stream().noneMatch(_c -> _c.getRepository().equals(repository))) {
        map.remove("user");
        RepoVO repoVO = getRepositoryInformation(owner, repository);
        if (repoVO != null) {
          map.put("repo", repoVO.getFull_name());
          exploitList.addAll(findConfigurations(map));

          map.put("filename", "docker-compose");
          exploitList.addAll(findConfigurations(map));
        } else log.warn("Repo Github doesn't exist");
      }
    } catch (Exception e) {
      log.error("An exception occurred during analysis: {}", e.getMessage());
      e.printStackTrace();
    }
    return exploitList;
  }

  /**
   * Retrieves more information about the repository
   *
   * @param owner The name owner of repository
   * @param repository The name of repository
   * @return <b>null</b> in case the response is not successful
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public RepoVO getRepositoryInformation(@NonNull String owner, @NonNull String repository)
      throws IOException {
    log.debug(
        "[getRepositoryInformation] Request to GitHub - Params: owner = {} repository = {}",
        owner,
        repository);
    Response<RepoVO> response = gitHubAPI.getRepositoryInformation(owner, repository).execute();
    log.debug("[getRepositoryInformation] Response from GitHub {} ", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Searches for query terms inside of a file. This method returns up to 100 results per page.
   *
   * @param query The query contains one or more search keywords and qualifiers. To learn more about
   *     the format of the query, see <a
   *     href="https://docs.github.com/en/free-pro-team@latest/github/searching-for-information-on-github/searching-code">Search
   *     Code</a>
   * @param page Page number of the results to fetch.
   * @param per_page Results per page.
   * @return <b>null</b> in case the response is not successful
   * @throws IOException throw when there is a problem performing the request or the *
   *     deserialization.
   */
  public SearchCodeVO searchInCode(String query, Integer page, Integer per_page)
      throws IOException {
    log.debug(
        "[searchCode] Request to GitHub - Params: query = {}  page = {}  per_page = {}",
        query,
        page,
        per_page);
    Response<SearchCodeVO> response = gitHubAPI.searcCode(query, page, per_page).execute();
    log.debug("[searchCode] Response from GitHub {} ", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  /**
   * Searches for query terms inside of a file. This method returns ALL results.
   *
   * @param query The query contains one or more search keywords and qualifiers. To learn more about
   *     * the format of the query, see <a *
   *     href="https://docs.github.com/en/free-pro-team@latest/github/searching-for-information-on-github/searching-code">Search
   *     * Code</a>
   * @return an <b>empty</b> list if case of error.
   */
  public List<FileVO> searchInCode(@NonNull String query) {
    int page = 1;
    SearchCodeVO searchInCode;
    var files = new ArrayList<FileVO>();
    try {
      do {
        searchInCode = searchInCode(query, page, MAX_PAGE_SIZE);
        if (searchInCode != null && !searchInCode.getItems().isEmpty()) {
          files.addAll(searchInCode.getItems());
          page++;
        }
      } while (searchInCode != null && files.size() < searchInCode.getTotal_count());
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return files;
  }

  public FileVO getContent(@NonNull Long repositoryId, @NonNull String path) throws IOException {
    log.debug(
        "[getContent] Request to GitHub - Params: repositoryID = {}  path = {}",
        repositoryId,
        path);
    Response<FileVO> response = gitHubAPI.getContent(repositoryId, path).execute();
    log.debug("[getContent] Response from GitHub {} ", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  public List<FileVO> getContents(@NonNull Long repositoryId, @NonNull String path)
      throws IOException {
    log.debug(
        "[getContent] Request to GitHub - Params: repositoryID = {}  path = {}",
        repositoryId,
        path);
    Response<List<FileVO>> response = gitHubAPI.getContents(repositoryId, path).execute();
    log.debug("[getContent] Response from GitHub {} ", response.code());
    return response.isSuccessful() ? response.body() : null;
  }

  public List<FilePojo> getContentsRecursively(@NonNull Long repositoryId, @NonNull String path)
      throws IOException {
    List<FilePojo> filePojos = new ArrayList<>();
    final var filesVO = getContents(repositoryId, path);
    filesVO.forEach(
        fileVO -> {
          try {
            if (fileVO.getType().equals("file")) {
              var _f = getContent(repositoryId, fileVO.getPath());
              filePojos.add(new FilePojo(_f.getName(), _f.getContent(), FilePojo.Type.FILE));
            } else if (fileVO.getType().equals("dir")) {
              var file = new FilePojo(fileVO.getName(), null, FilePojo.Type.FILE);
              file.setChildren(getContentsRecursively(repositoryId, fileVO.getPath()));
              filePojos.add(file);
            }
          } catch (Exception e) {
            log.error("An exception occurred: {}", e.getLocalizedMessage());
            e.printStackTrace();
          }
        });
    return filePojos;
  }

  /**
   * Generate the query string.
   *
   * @param values the key is the keyword and value the qualifier.
   * @return query string
   */
  private String generateQuery(@NonNull Map<String, String> values) {
    StringBuilder query = new StringBuilder();
    Iterator<String> iterator = values.keySet().iterator();
    while (iterator.hasNext()) {
      String key = iterator.next();
      query.append(key).append(":").append(values.get(key));
      if (iterator.hasNext()) query.append("+");
    }
    return query.toString();
  }
}
