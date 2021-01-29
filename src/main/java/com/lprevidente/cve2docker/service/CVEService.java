package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.model.CVE;
import com.lprevidente.cve2docker.repository.CVERepository;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.map.LRUMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class CVEService {

  private static final Pattern PATTERN_CVE =
      Pattern.compile("\\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_FULL_CVE =
      Pattern.compile("cve-(\\d{4}-\\d{4,7})", Pattern.CASE_INSENSITIVE);

  private final LRUMap<String, CVE> cveLRUMap = new LRUMap<>(1000);

  @Autowired private CVERepository cveRepository;

  /**
   * Get CVE from repository, if not exist creates new one.
   *
   * <p>This method use a cache
   *
   * @param cveID the id in the format \d{4}-\d{4,7}
   * @return null if the cve is not the right format
   */
  public CVE getCVE(@NonNull String cveID) {
    var cve = cveLRUMap.get(cveID);
    if (cve == null) {
      cve = cveRepository.findById(cveID).orElse(null);
      if (cve == null) cve = parse(cveID);
      cveLRUMap.put(cveID, cve);
    }
    return cve;
  }

  /**
   * Get CVE from repository.
   * @param cveID the id in the format \d{4}-\d{4,7}
   * @return null if the cve doesn't exist
   */
  public CVE getCVENoCache(@NonNull String cveID) {
    return cveRepository.findById(cveID).orElse(null);
  }

  /**
   * Extract the cve id from the text provided.
   *
   * @param text Not Null
   * @return if no cve found, the result is null
   */
  public String getCveIDFromString(@NonNull String text) {
    Matcher cveMatcher = PATTERN_FULL_CVE.matcher(text);
    if (cveMatcher.find()) return cveMatcher.group(1);
    return null;
  }

  /**
   * Parse the cve ID returning a CVE object
   *
   * @param cveID the id in the format \d{4}-\d{4,7}
   * @return
   */
  private CVE parse(String cveID) {
    if (!PATTERN_CVE.matcher(cveID).matches()) return null;
    CVE cve = new CVE();
    cve.setId(cveID);
    return cve;
  }
}
