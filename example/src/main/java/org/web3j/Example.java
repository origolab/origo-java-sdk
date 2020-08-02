/*
 * Copyright 2020 Web3 Labs Ltd.
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
package org.web3j;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import io.reactivex.disposables.Disposable;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.Transaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;

/** Demonstrations of Origo Java SDK. */
public class Example {

    private static final int COUNT = 1;

    private final Web3j web3j;

    public Example() {
        web3j = Web3j.build(new HttpService("http://localhost:6622/"));
        // web3j = Web3j.build(new HttpService("https://rpc.origo.network/"));
    }

    private void run() throws Exception {

        System.out.println("Doing clientVersionExample");
        clientVersionExample();

        getTransactionExample();

        getBlockExample();
        generateAddressExample();
        // createAndSignTransactionExample();
        getLatestBlockSubscriptionExample();
        System.exit(
                0); // we explicitly call the exit to clean up our ScheduledThreadPoolExecutor used
        // by web3j
    }

    public static void main(String[] args) throws Exception {
        new Example().run();
    }

    void getLatestBlockSubscriptionExample() throws Exception {
        Disposable subscription =
                web3j.blockFlowable(true)
                        .subscribe(
                                block -> {
                                    System.out.println(
                                            "Sweet, block number "
                                                    + block.getBlock().getNumber()
                                                    + " has just been created");
                                },
                                Throwable::printStackTrace);

        TimeUnit.MINUTES.sleep(2);
        subscription.dispose();
    }

    void clientVersionExample() throws Exception {
        CountDownLatch countDownLatch = new CountDownLatch(1);

        Disposable subscription =
                web3j.web3ClientVersion()
                        .flowable()
                        .subscribe(
                                x -> {
                                    System.out.println(
                                            "Client is running version: "
                                                    + x.getWeb3ClientVersion());
                                    countDownLatch.countDown();
                                });

        countDownLatch.await();
        subscription.dispose();
    }

    void getTransactionExample() throws Exception {
        System.out.println("Doing getTransactionExample");

        EthTransaction ethTransaction =
                web3j.ethGetTransactionByHash(
                                "0x2a4520eaa85fec4bfffae7e30da1b7d4f9e06a5bd21560ae8cf87bb65de64974")
                        .send();
        Transaction transaction = ethTransaction.getTransaction().get();

        System.out.println(
                "Transaction: "
                        + transaction.getHash()
                        + " , from: "
                        + transaction.getOgoFrom()
                        + " , to: "
                        + transaction.getOgoTo()
                        + "\n");
    }

    void getBlockExample() throws Exception {
        System.out.println("Doing getBlockExample");
        EthBlock ethBlock =
                web3j.ethGetBlockByNumber(
                                DefaultBlockParameter.valueOf(Numeric.toBigInt("0xA5624")), true)
                        .send();
        EthBlock.Block block = ethBlock.getBlock();
        List<Transaction> transactions =
                block.getTransactions().stream()
                        .map(transactionResult -> (Transaction) transactionResult.get())
                        .collect(Collectors.toList());
        System.out.println(
                "block " + block.getNumber() + ", has " + transactions.size() + " transactions.\n");
        System.out.println("Transaction 0 is: " + transactions.get(0).getHash());
    }

    void generateAddressExample() throws Exception {
        ECKeyPair ecKeyPair = Keys.createEcKeyPair();
        BigInteger privateKeyInDec = ecKeyPair.getPrivateKey();

        String sPrivatekeyInHex = privateKeyInDec.toString(16);

        Credentials credential = Credentials.create(ecKeyPair);
        String address = credential.getAddress();
        String addressOgo = credential.getOgoAddress();

        System.out.println(
                "private key: "
                        + sPrivatekeyInHex
                        + " address:"
                        + address
                        + ", ogo address:"
                        + addressOgo);
    }

    void createAndSignTransactionExample() throws Exception {
        String privateKey = "CHANGE TO YOUR PRIVATE KEY.";
        Credentials credentials = Credentials.create(privateKey);

        // get the next available nonce
        EthGetTransactionCount ethGetTransactionCount =
                web3j.ethGetTransactionCount(
                                credentials.getAddress(), DefaultBlockParameterName.LATEST)
                        .sendAsync()
                        .get();
        BigInteger nonce = ethGetTransactionCount.getTransactionCount();
        System.out.println("nonce: " + nonce);

        // create our transaction
        RawTransaction rawTransaction =
                RawTransaction.createOgoTransaction(
                        nonce,
                        BigInteger.valueOf(1000000000),
                        BigInteger.valueOf(21000),
                        "ogopub19sygy30jgqm8wyms38lfqtn692dkaje946ye8u",
                        BigInteger.ONE);
        System.out.println(rawTransaction.getTo());
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        String hexValue = Numeric.toHexString(signedMessage);
        System.out.println("Transaction message: " + hexValue);
        EthSendTransaction transactionResponse = web3j.ethSendRawTransaction(hexValue).send();
        System.out.println("Sent transaction: " + transactionResponse.getTransactionHash());
    }
}
