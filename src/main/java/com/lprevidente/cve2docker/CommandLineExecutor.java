package com.lprevidente.cve2docker;

import com.lprevidente.cve2docker.entity.pojo.ExploitType;
import com.lprevidente.cve2docker.service.SystemCve2Docker;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;

@ConditionalOnProperty(
    prefix = "command.line.runner",
    value = "enabled",
    havingValue = "true",
    matchIfMissing = true)
@Component
@Slf4j
public class CommandLineExecutor implements CommandLineRunner {

  @Autowired private SystemCve2Docker system;

  @Override
  public void run(String... args) {
    if (args.length > 0) {

      switch (args[0]) {
        case "--edb-id":
          if (args.length > 1) {
            for (int i = 1; i < args.length; i++) {
              try {
                system.genConfigurationFromExploit(Long.parseLong(args[i]), false);
              } catch (Exception e) {
                log.error(e.getMessage());
              }
            }
          } else log.error("No edbID provided");
          break;
        case "--gen-all":
          Date startDate = null;
          Date endDate = null;
          var types = new ArrayList<ExploitType>();
          boolean removeConfig = false;
          boolean ok = true;
          try {
            for (int i = 1; i < args.length; i++) {
              switch (args[i]) {
                case "--start-date":
                  i++;
                  if (i <= args.length - 1) startDate = Utils.fromStringToDate(args[i]);
                  else {
                    ok = false;
                    log.error("No start date provided");
                  }
                  break;
                case "--end-date":
                  i++;
                  if (i <= args.length - 1) endDate = Utils.fromStringToDate(args[i]);
                  else {
                    ok = false;
                    log.error("No end date provided");
                  }
                  break;
                case "--remove-config":
                  removeConfig = true;
                  break;
                default:
                  if (args[i].contains("-")) {
                    ok = false;
                    log.error("Unknow command: {}", args[i]);
                  } else {
                    try {
                      types.add(ExploitType.valueOf(args[i].toUpperCase()));
                    } catch (Exception e) {
                      ok = false;
                      log.error("Exploit Type Unknown: {}", args[i]);
                    }
                  }
                  break;
              }
            }
            if (Objects.nonNull(startDate)
                && Objects.nonNull(endDate)
                && !startDate.before(endDate)) {
              ok = false;
              log.error("Start Date is after the End Date");
            }
            if (ok) system.genConfigurations(startDate, endDate, removeConfig, types);
          } catch (Exception e) {
            e.printStackTrace();
            log.error("Error: {}", e.getMessage());
          }
          break;
        default:
          log.error("No such command: " + args[0]);
      }
    } else log.error("No Input Provided");
    log.info("--- End ---");

    System.exit(0);
  }
}
