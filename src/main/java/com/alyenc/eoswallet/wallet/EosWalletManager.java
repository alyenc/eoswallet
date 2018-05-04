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
package com.alyenc.eoswallet.wallet;


import java.io.*;
import java.util.*;

import com.alyenc.eoswallet.crypto.digest.Sha512;
import com.alyenc.eoswallet.crypto.ec.EosPrivateKey;
import com.alyenc.eoswallet.crypto.ec.EosPublicKey;
import com.alyenc.eoswallet.crypto.utils.CryptUtil;
import com.alyenc.eoswallet.crypto.utils.HexUtils;
import com.alyenc.eoswallet.model.chain.SignedTransaction;
import com.alyenc.eoswallet.model.types.EosByteReader;
import com.alyenc.eoswallet.model.types.EosByteWriter;
import com.alyenc.eoswallet.model.types.EosType;
import com.alyenc.eoswallet.model.types.TypeChainId;
import com.alyenc.eoswallet.utils.Consts;
import com.alyenc.eoswallet.utils.StringUtils;
import com.google.common.base.Preconditions;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;

/**
 * Created by swapnibble on 2017-09-19.
 */

public class EosWalletManager {

    private static final String EOS_WALLET_FILE_EXT = ".wallet";
    private static final String EOS_WALLET_PATH="/Users/mikechen";

    private HashMap<String, EosWallet> wallets = new HashMap<>();

    public void createWallet(String name, String password) throws IOException {
        File walletFile = new File(EOS_WALLET_PATH, name + EOS_WALLET_FILE_EXT);

        if (walletFile.exists()) {
            throw new IllegalStateException(String.format("Wallet with name: '%1$s' already exists", name));
        }

        boolean res = walletFile.createNewFile();
        if(!res) {
            throw new IOException("Wallet file create failure");
        }

        EosWallet wallet = new EosWallet();
        EosPrivateKey privKey = new EosPrivateKey();
        wallet.setWif(privKey.toWif());
        wallet.setPublicKey(privKey.getPublicKey().toString());
        wallet.setWalletName(name);
        wallet.setLocked(false);
        wallet.setFilePath(walletFile.getAbsolutePath());
        wallet.setChecksum(password);
        wallet.saveWallet(wallet);

        wallets.put(name, wallet);
    }

    public void unlock(String name, String password) {
        EosWallet wallet = new EosWallet();

        File walletFile = new File(EOS_WALLET_PATH, name + EOS_WALLET_FILE_EXT);
        if (!walletFile.exists()) {
            throw new IllegalStateException(String.format("Wallet with name: '%1$s' not exists", name));
        }
        wallet.loadFile(walletFile.getAbsolutePath());
        System.out.println(wallet.isLocked());
        wallet.unlock(password);
        System.out.println(wallet.isLocked());
        System.out.println(wallet.getWif());
        System.out.println(wallet.getPublicKey());
    }

    public String getPrivateKey(String name, String password) {
        EosWallet wallet = new EosWallet();

        File walletFile = new File(EOS_WALLET_PATH, name + EOS_WALLET_FILE_EXT);

        if (!walletFile.exists()) {
            throw new IllegalStateException(String.format("Wallet with name: '%1$s' not exists", name));
        }
        wallet.loadFile(walletFile.getAbsolutePath());
        wallet.unlock(password);
        return wallet.getWif();
    }

    public boolean importWalletByWif(String wif, String password) throws Exception{
        String name = "EOS_" + new Date().getTime();
        File walletFile = new File(EOS_WALLET_PATH, name + EOS_WALLET_FILE_EXT);

        if (walletFile.exists()) {
            throw new IllegalStateException(String.format("Wallet with name: '%1$s' already exists", name));
        }

        boolean res = walletFile.createNewFile();
        if(!res) {
            throw new IOException("Wallet file create failure");
        }

        EosWallet wallet = new EosWallet();
        EosPrivateKey privKey = new EosPrivateKey(wif);
        System.out.println(">>>>>" + privKey.toWif());
        wallet.setWalletName(name);
        wallet.setWif(wif);
        wallet.setPublicKey(privKey.getPublicKey().toString());
        wallet.setWalletName(name);
        wallet.setLocked(false);
        wallet.setFilePath(walletFile.getAbsolutePath());
        wallet.setChecksum(password);
        wallet.saveWallet(wallet);
        System.out.println(name);
        return true;
    }

    public boolean importWalletByKeyStore(String keyStore, String password) throws Exception{
        String name = "EOS_" + new Date().getTime();
        File walletFile = new File(EOS_WALLET_PATH, name + EOS_WALLET_FILE_EXT);

        if (walletFile.exists()) {
            throw new IllegalStateException(String.format("Wallet with name: '%1$s' already exists", name));
        }

        boolean res = walletFile.createNewFile();
        if(!res) {
            throw new IOException("Wallet file create failure");
        }

        EosWallet wallet = new EosWallet();
        wallet.setChecksum(password);
        wallet.setWalletName(name);
        wallet.setLocked(false);
        wallet.loadString(keyStore);

        return wallet.unlock(password);
    }

    public boolean deleteWallet(String name, String password) throws Exception{
        File walletFile = new File(EOS_WALLET_PATH, name + EOS_WALLET_FILE_EXT);

        if (!walletFile.exists()) {
            throw new IllegalStateException(String.format("Wallet with name: '%1$s' not exists", name));
        }

        EosWallet wallet = new EosWallet();
        wallet.setChecksum(password);
        wallet.setWalletName(name);
        wallet.setLocked(false);
        wallet.loadFile(walletFile.getAbsolutePath());
        boolean unLockResp = wallet.unlock(password);

        if(!unLockResp){
            throw new SecurityException("Password is wrong");
        }

        return walletFile.delete();
    }
    public static void main(String[] args) throws Exception{
        EosWalletManager manager = new EosWalletManager();
        System.out.println(manager.importWalletByKeyStore("{\"cipher\":\"ca315259e5bc29504b48ec2a9fa78ae74a68ac72da2cc6e0a5ef51c0efebc391eb0aef6aae22db1b2203bdbb7b598f3f09b80fedbc5f22620b9fbfdac2fe05c259b9a37a2421d830af1289bd9646dda8f84cde61ada709aee0fd171a38285c44837c4b70ba9b352d73368e7259aaf7a83fe57b3b4414996e7a8549116e2be82bf6166aeb25d4e5dd2d0ff1676d4afa1104e635f1360e15ff70da103c3eec3f989d87fd71ac1032a6ae597385c80fe7b0\",\"address\":\"EOS5cBFMCa1743UdTvv4yBzwBQv3t9NRE7pvzmQm2LSZL3VAPV3g3\",\"iv\":\"8a73bb304c17d5b237d7debd3e6ee944d09dd7e920f5d5e6ba6ecfb2a0fa79ca44dcbfde78fb55f52bb44e0af4ea6b65c75048ef1f6b1e96ff5ca2cd05e87775\"}", "m$6e2H&N5s"));
    }
}
