package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.ExploitType;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.entity.vo.nist.SearchCpeVO;
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

import javax.naming.ConfigurationException;
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

  @Value("${spring.config.exploits-url-github}")
  private String EXPLOITS_URL_GITHUB;

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
  }

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
      FileWriter writer = new FileWriter("result.csv");

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
        if (Objects.nonNull(startDate) && date.before(startDate)) continue;

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
        if (nTested % 10 == 0){
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

  public SearchCpeVO getCpes(CPE cpe) throws IOException {
    return nistService.getCpes(cpe);
  }

  public List<SearchTagVO.TagVO> searchTags(String repoFullName, String text)
      throws IllegalArgumentException {
    return dockerHubService.searchTags(repoFullName, text);
  }

  public void downloadVulnApp(String filenameVulnApp, File destDir) throws IOException {
    exploitDBService.downloadVulnApp(filenameVulnApp, destDir);
  }
}
