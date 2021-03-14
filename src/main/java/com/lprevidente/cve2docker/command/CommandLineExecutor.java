package com.lprevidente.cve2docker.command;

import com.lprevidente.cve2docker.command.EdbIDOption;
import com.lprevidente.cve2docker.command.GenAllOption;
import com.lprevidente.cve2docker.entity.pojo.ExploitType;
import com.lprevidente.cve2docker.exception.GenerationException;
import com.lprevidente.cve2docker.service.SystemCve2Docker;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.cli.*;
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
  public void run(String... args) throws java.text.ParseException {
    // Create Options object
    var opts = new Options();

    var optGroup = new OptionGroup();

    optGroup.addOption(EdbIDOption.EDB_ID);
    optGroup.addOption(GenAllOption.GEN_ALL);

    opts.addOptionGroup(optGroup);

    opts.addOption(
        Option.builder("h")
            .longOpt("help")
            .hasArg(false)
            .desc("Run --help for more information about the commands")
            .required(false)
            .build());

    // add -edb-id option
    var genAllOpts = new Options();
    genAllOpts.addOption(GenAllOption.TYPE);
    genAllOpts.addOption(GenAllOption.START_DATE);
    genAllOpts.addOption(GenAllOption.END_DATE);
    genAllOpts.addOption(GenAllOption.REMOVE_CONFIG);

    HelpFormatter formatter = new HelpFormatter();
    CommandLineParser parser = new DefaultParser();
    CommandLine cmd;
    try {
      // Starting with edbid options
      cmd = parser.parse(opts, args);
      if (cmd.hasOption("id")) {
        for (String id : cmd.getOptionValues("id")) {
          try {
            system.genConfigurationFromExploit(Long.parseLong(id), false);
          } catch (NumberFormatException e) {
            log.error("The id provided is not a number. Skipping it!");
          } catch (GenerationException e) {
            log.error("[{}] {}", e.getClass().getSimpleName(), e.getMessage());
          }
        }
      } else if (cmd.hasOption("a")) {
        Date startDate = null;
        Date endDate = null;
        var types = new ArrayList<ExploitType>();
        boolean removeConfig = false;
        try {
          cmd = parser.parse(genAllOpts, cmd.getOptionValues("a"));
          if (cmd.hasOption("s")) startDate = Utils.fromStringToDate(cmd.getOptionValue("s"));
          if (cmd.hasOption("e")) endDate = Utils.fromStringToDate(cmd.getOptionValue("e"));
          if (cmd.hasOption("r")) removeConfig = true;

          for (String type : cmd.getOptionValues("t")) {
            try {
              types.add(ExploitType.valueOf(type.toUpperCase().trim()));
            } catch (Exception e) {
              log.error("Exploit Type Unknown: {} - Ignoring it", type);
            }
          }

          // Check the dates
          if (Objects.nonNull(startDate)
              && Objects.nonNull(endDate)
              && !startDate.before(endDate)) {
            log.error("Start Date is after the End Date");
            System.exit(1);
          } else system.genConfigurations(startDate, endDate, removeConfig, types);

        } catch (MissingArgumentException e) {
          log.error(e.getMessage());
        } catch (ParseException e) {
          log.error("Error parsing command-line arguments! {} ", e.getMessage());
          formatter.printHelp("Commands", genAllOpts);
          System.exit(1);
        }
      } else {
        formatter.printHelp("Commands", opts);
      }
    } catch (MissingArgumentException e) {
      log.error(e.getMessage());
    } catch (ParseException e) {
      log.error("Error parsing command-line arguments! {}", e.getMessage());
      formatter.printHelp("Commands", opts);
      System.exit(1);
    }
    System.exit(0);
  }
}
