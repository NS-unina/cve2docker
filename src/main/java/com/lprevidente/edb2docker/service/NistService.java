package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.api.NistAPI;
import com.lprevidente.edb2docker.entity.pojo.CPE;
import com.lprevidente.edb2docker.entity.vo.nist.SearchCpeVO;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class NistService {

  @Value("${spring.config.nist.base-url}")
  private String BASE_PATH;

  private NistAPI nistAPI;

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
    nistAPI = retrofit.create(NistAPI.class);
  }

  /**
   * Return {@link SearchCpeVO} containing a list of all cpes that match the cpe provided.
   *
   * @param cpe not null
   * @return <b>null</b> there is not cpe
   * @throws IOException throw when there is a problem performing the request or the
   *     deserialization.
   */
  public SearchCpeVO getCpes(@NonNull CPE cpe) throws IOException {
    log.debug("[getCpes] Request to NIST cpe = {}", cpe.toCpeString());
    var response = nistAPI.getCPEs(cpe.toCpeString()).execute();
    log.debug("[getCpes] Response from NIST {}", response.code());
    return response.isSuccessful() && response.body() != null ? response.body() : null;
  }
}
