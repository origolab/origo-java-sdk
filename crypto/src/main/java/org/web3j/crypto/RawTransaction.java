/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.crypto;

import java.math.BigInteger;

import org.web3j.utils.Bech32;
import org.web3j.utils.Numeric;

/**
 * Transaction class used for signing transactions locally.<br>
 * For the specification, refer to p4 of the <a href="http://gavwood.com/paper.pdf">yellow
 * paper</a>.
 */
public class RawTransaction {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    private boolean isPrivate;

    protected RawTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            boolean isPrivate) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
        this.to = to;
        this.value = value;
        this.data = data != null ? Numeric.cleanHexPrefix(data) : null;
        this.isPrivate = isPrivate;
    }

    protected RawTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data) {
        this(nonce, gasPrice, gasLimit, to, value, data, false);
    }

    public static RawTransaction createContractTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            BigInteger value,
            String init) {

        return new RawTransaction(nonce, gasPrice, gasLimit, "", value, init);
    }

    public static RawTransaction createEtherTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value) {

        return new RawTransaction(nonce, gasPrice, gasLimit, to, value, "");
    }

    public static RawTransaction createOgoTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to, BigInteger value)
            throws Exception {
        return new RawTransaction(
                nonce, gasPrice, gasLimit, Bech32.fromBech32Address(to), value, "");
    }

    public static RawTransaction createTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to, String data) {
        return createTransaction(nonce, gasPrice, gasLimit, to, BigInteger.ZERO, data);
    }

    public static RawTransaction createTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data) {

        return new RawTransaction(nonce, gasPrice, gasLimit, to, value, data);
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public BigInteger getGasPrice() {
        return gasPrice;
    }

    public BigInteger getGasLimit() {
        return gasLimit;
    }

    public String getTo() {
        return to;
    }

    public String getOgoTo() throws Exception {
        return Bech32.toBech32Address(to);
    }

    public BigInteger getValue() {
        return value;
    }

    public String getData() {
        return data;
    }

    public boolean isPrivate() {
        return isPrivate;
    }
}
