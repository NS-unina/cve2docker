package com.lprevidente.cve2docker.api;

import com.lprevidente.cve2docker.entity.vo.nist.SearchCpeVO;
import com.lprevidente.cve2docker.entity.vo.nist.SearchCveVO;
import com.lprevidente.cve2docker.entity.vo.nist.SearchVO;
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
