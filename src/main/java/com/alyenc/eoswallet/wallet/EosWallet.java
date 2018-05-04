
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

import com.alyenc.eoswallet.crypto.utils.CryptUtil;
import com.alyenc.eoswallet.crypto.utils.HexUtils;
import com.alyenc.eoswallet.crypto.digest.Sha512;
import com.alyenc.eoswallet.utils.StringUtils;
import com.alyenc.eoswallet.crypto.ec.EosPrivateKey;
import com.alyenc.eoswallet.crypto.ec.EosPublicKey;
import com.google.common.base.Preconditions;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.alyenc.eoswallet.model.types.EosByteReader;
import com.alyenc.eoswallet.model.types.EosByteWriter;
import com.alyenc.eoswallet.model.types.EosType;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by swapnibble on 2017-09-25.
 */

public class EosWallet implements EosType.Packer, EosType.Unpacker {
    private static String WALLET_DATA_JSON_KEY = "cipher";
    private static String WALLET_ADDRESS_KEY = "address";
    private static String WALLET_IV_KEY = "iv";
    private static int ENCRYPT_KEY_LEN = 32;

    private String walletName;
    private boolean locked;
    private String publicKey;
    private String filePath;
    private byte[] walletData;
    private String wif;
    private Sha512 checksum = Sha512.ZERO_HASH;


    public String getWalletName() {
        return walletName;
    }

    public void setWalletName(String walletName) {
        this.walletName = walletName;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public byte[] getWalletData() {
        return walletData;
    }

    public void setWalletData(byte[] walletData) {
        this.walletData = walletData;
    }

    public void setWif(String wif) {
        this.wif = wif;
    }

    public Sha512 getChecksum() {
        return checksum;
    }

    public void setChecksum(String password) {
        this.checksum = Sha512.from(password.getBytes());
    }

    public String getWif() {
        if (isLocked()) {
            return "";
        }
        return wif;
    }

    @Override
    public void pack(EosType.Writer writer) {
        writer.putBytes(checksum.getBytes());
        writer.putString(publicKey);
        writer.putString(wif);
    }

    @Override
    public void unpack(EosType.Reader reader) throws EosType.InsufficientBytesException {
        checksum = new Sha512(reader.getBytes(Sha512.HASH_LENGTH));
        publicKey = reader.getString();
        wif = reader.getString();
    }

    public static class WalletLockedException extends IllegalStateException {
        WalletLockedException(String msg) {
            super(msg);
        }
    }

    private boolean loadReader(Reader contentReader) {
        JsonReader reader = null;
        try {
            reader = new JsonReader(contentReader);
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(reader);

            JsonElement itemElement = element.getAsJsonObject().get(WALLET_DATA_JSON_KEY);
            if (null == itemElement) {
                return false;
            }

            String hexData = itemElement.getAsString();
            if (StringUtils.isEmpty(hexData)) {
                return false;
            }

            walletData = HexUtils.toBytes(hexData);
            return true;
        } catch (IllegalStateException | JsonIOException | JsonSyntaxException e) {
            e.printStackTrace();
            return false;
        } finally {
            if (null != reader) {
                try {
                    reader.close();
                } catch (Throwable t) {
                    // TODO Auto-generated catch block
                    //e.printStackTrace();
                }
            }
        }
    }

    public boolean loadString(String jsonString) {
        return loadReader(new StringReader(jsonString));
    }

    public boolean loadFile(File jsonFile) {
        if (!jsonFile.exists()) {
            return false;
        }

        try {
            return loadReader(new FileReader(jsonFile));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }


    public boolean loadFile(String filePath) {
        if (StringUtils.isEmpty(filePath)) {
            if (StringUtils.isEmpty(filePath)) {
                return false;
            }
        }

        return loadFile(new File(filePath));
    }

    public boolean saveWallet(EosWallet wallet) {
        if (StringUtils.isEmpty(wallet.getFilePath())) {
            return false;
        }
        encryptKeys();
        FileOutputStream fos = null;
        try {
            Gson gson = new Gson();
            JsonObject object = new JsonObject();
            object.addProperty(WALLET_DATA_JSON_KEY, HexUtils.toHex(wallet.getWalletData()));
            object.addProperty(WALLET_ADDRESS_KEY, publicKey);
            object.addProperty(WALLET_IV_KEY, Sha512.from(getIv(checksum)).toString());

            String json = gson.toJson(object);
            if (StringUtils.isEmpty(json)) {
                return false;
            }

            fos = new FileOutputStream(filePath);
            fos.write(json.getBytes());
            fos.flush();

            return true;
        } catch (SecurityException | IOException fne) {
            fne.printStackTrace();
            return false;
        } finally {
            if (null != fos) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private byte[] getIv(Sha512 hash) {
        return Arrays.copyOfRange(hash.getBytes(), ENCRYPT_KEY_LEN, ENCRYPT_KEY_LEN + 16);
    }

    private void encryptKeys() {
        if (isLocked()) {
            return;
        }

        EosByteWriter writer = new EosByteWriter(256);
        this.pack(writer);

        walletData = CryptUtil.aesEncrypt(Arrays.copyOf(checksum.getBytes(), ENCRYPT_KEY_LEN)
                , writer.toBytes(), getIv(checksum));
    }

    public void lock() {
        if (isLocked()) {
            return;
        }

        encryptKeys();

        publicKey = "";
        wif = "";
        checksum = Sha512.ZERO_HASH;
    }

    public boolean unlock(String password) {
        Preconditions.checkArgument((password != null) && (password.length() > 0));

        Sha512 pw = Sha512.from(password.getBytes());

        byte[] decrypted = CryptUtil.aesDecrypt(Arrays.copyOf(pw.getBytes(), ENCRYPT_KEY_LEN),
                walletData, getIv(pw));

        if (null == decrypted) {
            return false;
        }

        Sha512 oldChecksum = checksum;
        String oldPublicKey = publicKey;
        String oldWif = wif;
        try {
            this.unpack(new EosByteReader(decrypted));
            System.out.println(this);
            if (checksum.compareTo(pw) != 0) {
                checksum = oldChecksum;
                publicKey = oldPublicKey;
                wif = oldWif;
                return false;
            }
        } catch (EosType.InsufficientBytesException e) {
            e.printStackTrace();
            checksum = oldChecksum;
            publicKey = oldPublicKey;
            wif = oldWif;
        }
        return true;
    }

    public void setPassword(String password) {
        if (isLocked()) {
            throw new EosWallet.WalletLockedException("The wallet must be unlocked before the password can be set");
        }

        checksum = Sha512.from(password.getBytes());
        lock();
    }

    public boolean isLocked() {
        return Sha512.ZERO_HASH.equals(checksum);
    }

    @Override
    public String toString() {
        return "EosWallet{" +
                "walletName='" + walletName + '\'' +
                ", locked=" + locked +
                ", publicKey='" + publicKey + '\'' +
                ", filePath='" + filePath + '\'' +
                ", walletData=" + Arrays.toString(walletData) +
                ", wif='" + wif + '\'' +
                ", checksum=" + checksum +
                '}';
    }
}
