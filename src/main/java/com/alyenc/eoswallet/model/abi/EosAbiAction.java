package com.alyenc.eoswallet.model.abi;

import com.google.gson.annotations.Expose;

/**
 * Created by swapnibble on 2017-12-22.
 */

public class EosAbiAction {
    @Expose
    public String action_name;

    @Expose
    public String type;

    @Override
    public String toString(){
        return "EosAction: " + action_name + ", type: "+ type ;
    }
}
