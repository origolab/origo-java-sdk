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
import org.web3j.crypto.SignedRawTransaction;
import org.web3j.crypto.TransactionDecoder;
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
import org.web3j.utils.Bech32;
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
        validateAddressExample();
        decodeEncodeTransactionExample();
        // createAndSignTransactionExample();
        getLatestBlockSubscriptionExample();
        // we explicitly call the exit to clean up our ScheduledThreadPoolExecutor used by web3j.
        System.exit(0);
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

    void validateAddressExample() {
        String validAddress = "ogopub19sygy30jgqm8wyms38lfqtn692dkaje946ye8u";
        String invalidAddress = "ogopub19sygy30jgqm8wyms38lfqtn692dkaje946ye8";
        System.out.println(
                validAddress + " valid address: " + Bech32.isValidBech32Address(validAddress));
        System.out.println(
                invalidAddress + " valid address: " + Bech32.isValidBech32Address(invalidAddress));
    }

    void decodeEncodeTransactionExample() throws Exception {
        // https://www.ogoscan.io/tx/0xf50872e911ac1656587e58fb7773d38f3685e472040e2a799753ee776d6a9221
        String pubTxRaw =
                "0xf86e0685051f4d5c00825208948669c63d545b647ef76ec989b1cd9525068b09e98a01eca0e3268db7f95a008058a0e5b5fb0651d227f99243b0b172bd694d4e508ddd3f082dc19d85bf093ed76d45a00ef67518c54153db87a6ce878abf1f10cb16d9894fa07bf75811dfb99e13230a";
        // https://www.ogoscan.io/tx/0xb164f419931bc0152bc74569527a58613e99f102db02ae3e6aa3718f76dbe2fc
        String privateTxRaw =
                "0xf905cd808506fc23ac008252089503b675323d95dbbb1c3e3a1901d393ec87357bbeef890f8ac302ff907e000080f9059cf9018df9018aa0ee884e887606e1dd7bcefe192d40b21f88ca85f302a5a01e109c2bbf29987122a0b1e5cbc7e64343cb421ad5a73900baad640db6986f47406beec55783a3175200a0b077b062e9add5f91d36f2242149148eb5abb78e31a26eaadbe32d2cb52fec73a0f07aca1ab0e9f453185e4d25f5600633f48316b27b836191529e96366f5a1731b8c081159d27865fd0c49fc87586d403fdceb39f72ffc93ab348e231205f7fda13f2d21fb594738f8bfab7b05e45b13deb1f94ca3f6fb17262df0f8da92913c7b639b679a6eeb4f6d2e7996eed9d2ea64efb827d86ce0b8b3bb04b563106f575255909375b6479a1ed67b39685811b46d479a1c7595ed6bab5224a70c03772060cc0c5d8a0ece9a9a2561cd34bfa41767b2394131e0bbab08034f283090f72b1155a3db28ca618d5ba5e8d118af0d8030ce3ce2cb32383b44b0e0d7837c365ef779cf842a02e5d88cdf9a5395ff183fbf8a2475bcddd4a4e25b7fbbb42a3c5d3f0b272bc5fa00efd481105819d55dd5f20bf0587bf73f97eb7f0af40c910d7161c6694139f03f903c1f903bea0d012c408d84e205171ce9c978273a8fd22b0c67ee9f8ee2a7c7ce22e8eba87d0a019edaeba7068a437fef3e9dd35af2215669d493b006293a8ad303d30e2b05a14a015f9fe63efc9ce819eb5f84a28da8bdd46806669c6dde1515f066fff37c646a7b902441e8821b62360837c5f37f86a15a63e8937812f49b541076e7972cc95dc1c057ce3e1cbe5f5e090a7e258d44cbace72e0030a009d64b4d333a62520442004924017585a5727ca0f75473290e39dfa86556778618fa014f9c02b397a455c995a6b58a4d6cf2142dbdf7556ea215d995c7b43e26b975b6a7c68f736fc4103e24ed82ac95de207d14fe4a45b8951679720a3fe5e05c5d3d5a3accf0eedb9b287b204c1530ab041f860029f98a604b68e8ae262789c327ef3ea1099abd0e4ca056e79171b374d1166e65cac52308012dd1c4a981e4039c7600ec301acbf7cdce90181580cbd5829a20685a2c2e21d8f0fe95704b167aa785387d574dd2e937c8deb6af74429db7dcaa09bcd3e7c77b04d6f907a8cf674cb173ddc1df64bb39e8b65955f7ef27d787630ddccf267c9c8ad12b05bc90e317dcc4821c295ceac223168644e225343b7a96d73136089e34e28e9f93822a3a0b62220a6cfcf8389a8d2030cc026019e9fc335324f7af0a129f1743a1ca2b4e0b9642be31663db4278495afe1841c412e0ecf7db477848869757a4a6b37c115d91e74651a277ac23e2d54f2669fa61d84222a210dd2de59ee4748d28bff499c3dd0843d1098890fb58924b6ccf77eeb3491a71462bf1252dc016db05e971be83e19feac16a3bd71ad63ce132b1e546bed2d12857d35a5783395c4510fb0e13e4931dd783d7acd21393d686173e8251a0dce8bef88fafaa829178c1d28085f423e3c450e25aa2e8ce9147744c4a6b1b1037169f18101c7b8a0a1f6e4ad61cf4244d0f469c60fb1b6df822ac65ab979408b8504a8b94e4d3ff95f9db00c065319b09ca685d777da9f24ea4b50b40aaece2654b8aa610af21ba072fc4280584fccae61e2cba9b924959a094d64d88e4ecc32e10c1438bbf56edd2219398ea4c2c451f57b8c0aa6d83d466f1bd8229b96652d71c45ba2bd9f12918c32c89ffb489018861c70b95b885ec5db72a802e496142b16c71a2ac9c13a0345a88aac58f1781b666fd711fae0f455cc4577c1d362f61b955739dd8982651f7e8ae4691723612192eb7290ca1f8ebb0ad47e1028df78b734b0ff61301b36a5bad3a3090563d086892bda6c70b345a4bcfdd5d893f7c3eb85d7aacae0265ed84ead20a237520b6300c55776f1df835f58319110c159e328841eacda9800bd066314841dd8b12ec2775c0798542c0b06ff0b840852c2ecca059f9c0c9f2eb6e5937bce474bad6c50903d1870d0ac79fbd38045c4c33c0faf675353a11f4f022d6e942afd618a85a25e648169f22ad2cb840d00d1a8080";
        SignedRawTransaction publicTx = (SignedRawTransaction) TransactionDecoder.decode(pubTxRaw);
        System.out.println(
                "to: "
                        + publicTx.getOgoTo()
                        + ", amount: "
                        + publicTx.getValue()
                        + ", from: "
                        + publicTx.getOgoFrom());

        SignedRawTransaction privateTx =
                (SignedRawTransaction) TransactionDecoder.decode(privateTxRaw);
        // Private tx, you can ignore.
        System.out.println("Tx is private:" + privateTx.isPrivate());
    }
}
