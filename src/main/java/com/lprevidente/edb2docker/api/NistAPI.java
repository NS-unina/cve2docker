package com.lprevidente.edb2docker.api;

import com.lprevidente.edb2docker.entity.vo.nist.SearchCpeVO;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Query;

public interface NistAPI {

  @GET("cpes/1.0")
  Call<SearchCpeVO> getCPEs(@Query(value = "cpeMatchString", encoded = true) String cpe);
}
