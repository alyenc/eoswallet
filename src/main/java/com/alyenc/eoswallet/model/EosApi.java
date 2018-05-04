/*
* Copyright (c) 2017 Mithril coin.
*
* The MIT License
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
package com.alyenc.eoswallet.model;


import com.google.gson.JsonObject;

import com.alyenc.eoswallet.model.api.JsonToBinRequest;
import com.alyenc.eoswallet.model.api.JsonToBinResponse;
import com.alyenc.eoswallet.model.chain.GetCodeRequest;
import com.alyenc.eoswallet.model.chain.GetCodeResponse;
import com.alyenc.eoswallet.model.chain.GetRequiredKeys;
import com.alyenc.eoswallet.model.chain.RequiredKeysResponse;
import com.alyenc.eoswallet.model.chain.SignedTransaction;
import com.alyenc.eoswallet.model.api.AccountInfoRequest;
import com.alyenc.eoswallet.model.api.EosChainInfo;
import com.alyenc.eoswallet.model.api.GetTableRequest;
import com.alyenc.eoswallet.model.api.PushTxnResponse;
import io.reactivex.Observable;
import retrofit2.http.Body;
import retrofit2.http.POST;
import retrofit2.http.Path;

/**
 * Created by swapnibble on 2017-09-08.
 */

public interface EosApi {

    @POST("/v1/chain/{infoType}")
    Observable<EosChainInfo> readInfo(@Path("infoType") String infoType);

    @POST("/v1/chain/get_account")
    Observable<JsonObject> getAccountInfo(@Body AccountInfoRequest body);

    @POST("/v1/chain/get_table_rows")
    Observable<JsonObject> getTable(@Body GetTableRequest body);

    @POST("/v1/chain/push_transaction")
    Observable<PushTxnResponse> pushTransaction(@Body SignedTransaction body);

    @POST("/v1/chain/push_transaction")
    Observable<JsonObject> pushTransactionRetJson(@Body SignedTransaction body);

    @POST("/v1/chain/get_required_keys")
    Observable<RequiredKeysResponse> getRequiredKeys(@Body GetRequiredKeys body);

    @POST("/v1/chain/abi_json_to_bin")
    Observable<JsonToBinResponse> jsonToBin(@Body JsonToBinRequest body);

    @POST("/v1/chain/get_code")
    Observable<GetCodeResponse> getCode(@Body GetCodeRequest body);

    @POST("/v1/account_history/{history_path}")
    Observable<JsonObject> getAccountHistory(@Path("history_path") String historyPath,  @Body JsonObject body);

    String ACCOUNT_HISTORY_GET_TRANSACTIONS = "get_transactions" ;
    String GET_TRANSACTIONS_KEY = "account_name";

    String ACCOUNT_HISTORY_GET_SERVANTS = "get_controlled_accounts" ;
    String GET_SERVANTS_KEY = "controlling_account";
}