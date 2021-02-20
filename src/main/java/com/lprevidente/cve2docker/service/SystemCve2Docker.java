package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.ExploitType;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.entity.vo.nist.SearchCpeVO;
import com.lprevidente.cve2docker.exception.ConfigurationException;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

@Slf4j
@Service
public class SystemCve2Docker {

  @Autowired private NistService nistService;

  @Autowired private ExploitDBService exploitDBService;

  @Autowired private DockerHubService dockerHubService;

  @Autowired private WordpressService wordpressService;

  @Autowired private JoomlaService joomlaService;

  @Autowired private PhpWebAppService phpWebAppService;

  @Value("${spring.config.exploits-url-github}")
  private String EXPLOITS_URL_GITHUB;

  /**
   * Method to generate configuration for the exploit provided. The configuration consist in
   * docker-compose, env file e other files depending on the exploit type.
   *
   * <p>The configuration is saved in ./content/generated/{edbID} folder.
   *
   * @param edbID not null
   * @param removeConfig if true the configuration will be removed after it has been setup.
   * @throws ExploitUnsupported throws when there is no possibility to generate the configuration.
   * @throws IOException throw when there is a problem with I/O operation
   * @throws ConfigurationException throws when there is a problem during the setup or test of the
   *     configuration.
   */
  public void genConfigurationFromExploit(@NonNull Long edbID, boolean removeConfig)
      throws ExploitUnsupported, IOException, ConfigurationException {
    ExploitDB exploitDB = null;
    try {
      exploitDB = exploitDBService.getExploitDBFromSite(edbID);
    } catch (Exception ignored) {
    }

    if (Objects.isNull(exploitDB)) throw new ExploitUnsupported("Exploit doesn't exist");

    log.info("Exploit Found in ExploitDB");

    if (StringUtils.containsIgnoreCase(exploitDB.getTitle(), ExploitType.WORDPRESS.name()))
      wordpressService.genConfiguration(exploitDB, removeConfig);
    else if (StringUtils.containsIgnoreCase(exploitDB.getTitle(), ExploitType.JOOMLA.name()))
      joomlaService.genConfiguration(exploitDB, removeConfig);
    else if (StringUtils.equalsIgnoreCase(exploitDB.getPlatform(), ExploitType.PHP.name()))
      phpWebAppService.genConfiguration(exploitDB, removeConfig);
  }

  /**
   * Method to generate various configurations specifying a list of exploit types. The list of
   * exploit is taken from exploitdb GitHub <i>every time the method is executed</i> so as to have
   * the most updated list.
   *
   * <p>in addition to configurations, the method saves the result of the generation process in a
   * csv file, named result.csv.
   *
   * @param startDate the date <i>after</i> which the exploit has been published
   * @param endDate the date <i>before</i> which the exploit has been published
   * @param removeConfig if true the configuration will be removed after it has been setup.
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
              CSVFormat.DEFAULT.withHeader(
                  "id", "file", "description", "date", "author", "type", "platform", "port"));

      // Open a File write to save the results
      FileWriter writer = new FileWriter("result_" + new Date() + ".csv");

      var printer =
          new CSVPrinter(
              writer,
              CSVFormat.DEFAULT.withHeader(
                  "id", "description", "date", "result", "error description"));

      var nTested = 0;
      final var iterator = exploits.iterator();
      iterator.next();

      while (iterator.hasNext()) {
        var record = iterator.next();
        var matchType =
            types.stream()
                .anyMatch(
                    type -> StringUtils.containsIgnoreCase(record.get("description"), type.name()));
        if (!types.isEmpty() && !matchType) continue;

        var date = Utils.fromStringToDate(record.get("date"));

        // IF startDate is set and the date of exploit is before, jump to next one
        if (Objects.nonNull(startDate) && date.before(startDate)) continue;

        // IF endDate is set and the date of exploit is after, jump to next one
        if (Objects.nonNull(endDate) && date.after(endDate)) continue;

        try {
          genConfigurationFromExploit(Long.parseLong(record.get("id")), removeConfig);
          printer.printRecord(
              record.get("id"), record.get("description"), record.get("date"), "SUCCESS", "");
        } catch (Exception e) {
          log.warn(e.getMessage());
          printer.printRecord(
              record.get("id"),
              record.get("description"),
              record.get("date"),
              "ERROR",
              e.getMessage());
        }
        nTested++;
        if (nTested % 10 == 0) {
          log.debug("Cleaning docker networks");
          Utils.executeShellCmd("docker network prune -f");
        }
      }

      exploits.close();
      printer.close();
    } catch (IOException e) {
      log.error("Error reading exploit csv file from GitHub: {}", e.getMessage());
    } catch (InterruptedException e) {
      log.error("Error during the network prune of docker {}", e.getMessage());
    } catch (ParseException e) {
      log.error("Error parsing date {}", e.getMessage());
    }
  }

  /** Wrapper of {@link NistService#getCpes(CPE)} */
  public SearchCpeVO getCpes(CPE cpe) throws IOException {
    return nistService.getCpes(cpe);
  }

  /** Wrapper of {@link DockerHubService#searchTags(String, String)} */
  public List<SearchTagVO.TagVO> searchTags(String repoFullName, String text)
      throws IllegalArgumentException {
    return dockerHubService.searchTags(repoFullName, text);
  }

  /** Wrapper of {@link ExploitDBService#downloadVulnApp(String, File)} */
  public void downloadVulnApp(String filenameVulnApp, File destDir) throws IOException {
    exploitDBService.downloadVulnApp(filenameVulnApp, destDir);
  }
}
