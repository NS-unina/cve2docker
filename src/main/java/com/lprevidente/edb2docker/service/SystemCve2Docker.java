package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.entity.pojo.CPE;
import com.lprevidente.edb2docker.entity.pojo.ExploitDB;
import com.lprevidente.edb2docker.entity.pojo.ExploitType;
import com.lprevidente.edb2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.edb2docker.entity.vo.nist.CpeMatchVO;
import com.lprevidente.edb2docker.exception.ExploitUnsupported;
import com.lprevidente.edb2docker.exception.GenerationException;
import com.lprevidente.edb2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;

import static org.apache.commons.lang3.StringUtils.containsIgnoreCase;

@Slf4j
@Service
public class SystemCve2Docker {

  private final NistService nistService;

  private final ExploitDBService exploitDBService;

  private final DockerHubService dockerHubService;

  @Value("${spring.config.exploits-url-github}")
  private String EXPLOITS_URL_GITHUB;

  private final IGenerateService[] services;

  @Autowired
  public SystemCve2Docker(
      NistService nistService,
      ExploitDBService exploitDBService,
      DockerHubService dockerHubService,
      WordpressService wordpressService,
      JoomlaService joomlaService,
      PhpWebAppService phpWebAppService) {

    services = new IGenerateService[] {wordpressService, joomlaService, phpWebAppService};
    this.nistService = nistService;
    this.exploitDBService = exploitDBService;
    this.dockerHubService = dockerHubService;
  }

  /**
   * Method to generate configuration for the exploit provided. The configuration consist in
   * docker-compose, env file e other files depending on the exploit type.
   *
   * <p>The configuration is saved in ./content/generated/{edbID} folder.
   *
   * @param edbID not null
   * @param removeConfig if true the configuration will be removed after it has been setup.
   */
  public void genConfiguration(@NonNull Long edbID, boolean removeConfig)
      throws GenerationException {
    log.info(" --- START Generation Request for edbID = {} ---", edbID);
    ExploitDB exploitDB = null;
    try {
      exploitDB = exploitDBService.getExploitDBFromSite(edbID);
    } catch (Exception e) {
      log.warn("Retrying...");
      try {
        TimeUnit.MINUTES.sleep(1);
        exploitDB = exploitDBService.getExploitDBFromSite(edbID);
      } catch (Exception ignored) {
      }
    }

    if (Objects.isNull(exploitDB)) throw new ExploitUnsupported("Exploit doesn't exist");

    final var finalExploitDB = exploitDB;
    final var opt =
        Arrays.stream(services).filter(services -> services.canHandle(finalExploitDB)).findFirst();

    if (opt.isPresent()) opt.get().genConfiguration(exploitDB, removeConfig);
    else throw new ExploitUnsupported("Exploit type Unknown");
  }

  /**
   * Method to generate various configurations specifying a list of exploit types. The list of
   * exploit is taken from exploitdb GitHub <i>every time the method is executed</i> so as to have
   * the most updated list.
   *
   * <p>in addition to configurations, the method saves the result of the generation process in a
   * csv file, named result.csv.
   *
   * @param startDate The date <b>included</b> <i>after</i> which the exploit has been published
   * @param endDate The date <b>included</b> <i>before</i> which the exploit has been published
   * @param removeConfig If true remove the container after it has been tested, with the volumes
   *     associated to it
   * @param types the list of all types of exploits for which a configuration must be generated
   */
  public void genConfigurations(
      Date startDate, Date endDate, boolean removeConfig, @NonNull List<ExploitType> types) {

    CSVParser exploits;
    try {
      exploits =
          CSVParser.parse(
              new URL(EXPLOITS_URL_GITHUB),
              StandardCharsets.UTF_8,
              CSVFormat.RFC4180
                  .withHeader(
                      "id", "file", "description", "date", "author", "type", "platform", "port")
                  .withDelimiter(','));

      // Open a File write to save the results
      FileWriter writer = new FileWriter("result_" + Utils.fromDateToString(new Date()) + ".csv");

      var printer =
          new CSVPrinter(
              writer,
              CSVFormat.DEFAULT.withHeader(
                  "id", "description", "date", "result", "error description"));

      final var iterator = exploits.iterator();
      iterator.next();

      while (iterator.hasNext()) {
        var record = iterator.next();

        // Check if the description or platform contains the content of exploit type
        var matchType =
            types.stream()
                .anyMatch(
                    type ->
                        containsIgnoreCase(record.get("description"), type.name())
                            || containsIgnoreCase(record.get("platform"), type.name()));
        if (!types.isEmpty() && !matchType) continue;

        var date = Utils.fromStringToDate(record.get("date"));

        // IF startDate is set and the date of exploit is before, jump to next one
        if (Objects.nonNull(startDate) && date.before(startDate)) continue;

        // IF endDate is set and the date of exploit is after, jump to next one
        if (Objects.nonNull(endDate) && date.after(endDate)) continue;

        try {
          genConfiguration(Long.parseLong(record.get("id")), removeConfig);
          printer.printRecord(
              record.get("id"), record.get("description"), record.get("date"), "SUCCESS", "");
        } catch (GenerationException e) {
          log.error("[{}] {}", e.getClass().getSimpleName(), e.getMessage());
          printer.printRecord(
              record.get("id"),
              record.get("description"),
              record.get("date"),
              "ERROR",
              "[" + e.getClass().getSimpleName() + "] " + e.getMessage());
        }
      }

      exploits.close();
      printer.flush();
      printer.close();
    } catch (IOException e) {
      log.error("Error reading exploit csv file from GitHub: {}", e.getMessage());
    } catch (ParseException e) {
      log.error("Error parsing date {}", e.getMessage());
    }
  }

  /**
   * Find a Docker Tag that is compatible with the cpe provided.
   *
   * @param cpe the cpe for with the tag should be found
   * @param match function to find a tag with the exact name of the version
   * @param contains function to find a tag that contains the string version
   * @return null if no tag has been found.
   * @throws IOException exception occurred during the request to dockerhub
   */
  public SearchTagVO.TagVO findTag(
      @NonNull CPE cpe,
      @NonNull BiPredicate<SearchTagVO.TagVO, CpeMatchVO> match,
      @NonNull BiPredicate<SearchTagVO.TagVO, CpeMatchVO> contains)
      throws IOException {

    // Return all CPE that match the previous
    final var cpes = nistService.getCpes(cpe);
    if (cpes == null || cpes.getResult().getCpes().isEmpty()) return null;

    SearchTagVO.TagVO tag = null;

    //  Cycle through all CPE until find a tag on dockerhub corresponding to the version
    final var iterator = cpes.getResult().getCpes().iterator();

    while (iterator.hasNext() && tag == null) {
      var cpeMatchVO = iterator.next();

      final var tags =
          dockerHubService.searchTags(cpe.getVendor(), cpeMatchVO.getCpe().getVersion().toString());

      // Search for a tag with the exact name of the version
      tag = tags.stream().filter(_t -> match.test(_t, cpeMatchVO)).findFirst().orElse(null);

      // If not found, finding the FIRST repo with the containing name
      if (tag == null)
        tag = tags.stream().filter(_t -> contains.test(_t, cpeMatchVO)).findFirst().orElse(null);
    }
    return tag;
  }

  /** Wrapper of {@link ExploitDBService#downloadVulnApp(String, File)} */
  public void downloadVulnApp(String filenameVulnApp, File destDir) throws IOException {
    exploitDBService.downloadVulnApp(filenameVulnApp, destDir);
  }
}
