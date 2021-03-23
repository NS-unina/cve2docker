package com.lprevidente.edb2docker.api;

import com.lprevidente.edb2docker.entity.vo.nist.SearchCpeVO;
import com.lprevidente.edb2docker.entity.vo.nist.SearchCveVO;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;

public interface NistAPI {
  @GET("cve/1.0/{cveID}??addOns=dictionaryCpes")
  Call<SearchCveVO> getCVEInformation(@Path(value = "cveID", encoded = true) String cveID);

  @GET("cpes/1.0")
  Call<SearchCpeVO> getCPEs(@Query(value = "cpeMatchString", encoded = true) String cpe);
}
