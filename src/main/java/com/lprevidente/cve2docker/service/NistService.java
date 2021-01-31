package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.api.NistAPI;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.vo.nist.SearchCpeVO;
import com.lprevidente.cve2docker.entity.vo.nist.VulnerabilityVO;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import javax.annotation.PostConstruct;
import java.io.IOException;

@Slf4j
@Service
public class NistService {

  @Value("${spring.config.nist.base-url}")
  private String BASE_PATH;

  @Value("${spring.config.dockerhub.max-page-size}")
  private Integer MAX_PAGE_SIZE;

  private NistAPI nistAPI;

  @PostConstruct
  public void initRetrofit() {
    Retrofit retrofit =
        new Retrofit.Builder()
            .baseUrl(BASE_PATH)
            .addConverterFactory(JacksonConverterFactory.create())
            .build();
    nistAPI = retrofit.create(NistAPI.class);
  }

  /**
   * Return {@link VulnerabilityVO} containing all information provided by NIST about the cve.
   *
   * @param cveID must be in the following format: YYYY-XXXX
   * @return <b>null</b> if the vulnerability doesn't exist
   * @throws IOException throw when there is a problem performing the request or the
   *     deserialization.
   */
  public VulnerabilityVO getVulnerability(@NonNull String cveID) throws IOException {
    log.debug("[getVulnerability] Request to NIST cveID = {}", cveID);
    var response = nistAPI.getCVEInformation("cve-" + cveID).execute();
    log.debug("[getVulnerability] Response from NIST {}", response.code());
    return response.isSuccessful() && response.body() != null
        ? response.body().getResult().getCVE_Items().get(0)
        : null;
  }

  public SearchCpeVO getCpes(@NonNull CPE cpe) throws IOException {
    log.debug("[getCpes] Request to NIST cpe = {}", cpe.toCpeString());
    log.debug("url {}", nistAPI.getCPEs(cpe.toCpeString()).request().url().url().toString());
    var response = nistAPI.getCPEs(cpe.toCpeString()).execute();
    log.debug("[getCpes] Response from NIST {}", response.code());
    return response.isSuccessful() && response.body() != null ? response.body() : null;
  }
}
