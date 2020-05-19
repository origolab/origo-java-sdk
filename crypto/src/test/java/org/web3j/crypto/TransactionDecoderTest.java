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

import org.junit.jupiter.api.Test;

import org.web3j.utils.Bech32;
import org.web3j.utils.Numeric;

import static org.junit.jupiter.api.Assertions.*;

public class TransactionDecoderTest {

    @Test
    public void testDecoding() throws Exception {
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.ONE;
        BigInteger gasLimit = BigInteger.TEN;
        String to = "0x0add5355";
        BigInteger value = BigInteger.valueOf(Long.MAX_VALUE);
        RawTransaction rawTransaction =
                RawTransaction.createEtherTransaction(nonce, gasPrice, gasLimit, to, value);
        byte[] encodedMessage = TransactionEncoder.encode(rawTransaction);
        String hexMessage = Numeric.toHexString(encodedMessage);

        RawTransaction result = TransactionDecoder.decode(hexMessage);
        assertNotNull(result);
        assertEquals(nonce, result.getNonce());
        assertEquals(gasPrice, result.getGasPrice());
        assertEquals(gasLimit, result.getGasLimit());
        assertEquals(to, result.getTo());
        assertEquals(value, result.getValue());
        assertEquals("", result.getData());
        assertFalse(result.isPrivate());
    }

    @Test
    public void testOgoTransactionDecoding() throws Exception {
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.ONE;
        BigInteger gasLimit = BigInteger.TEN;
        String to = Bech32.toBech32Address("0x0add5355");
        BigInteger value = BigInteger.valueOf(Long.MAX_VALUE);
        RawTransaction rawTransaction =
                RawTransaction.createOgoTransaction(nonce, gasPrice, gasLimit, to, value);
        byte[] encodedMessage = TransactionEncoder.encode(rawTransaction);
        String hexMessage = Numeric.toHexString(encodedMessage);

        RawTransaction result = TransactionDecoder.decode(hexMessage);
        assertNotNull(result);
        assertEquals(nonce, result.getNonce());
        assertEquals(gasPrice, result.getGasPrice());
        assertEquals(gasLimit, result.getGasLimit());
        assertEquals(to, Bech32.toBech32Address(result.getTo()));
        assertEquals(value, result.getValue());
        assertEquals("", result.getData());
        assertFalse(result.isPrivate());
    }

    @Test
    public void testDecodingSigned() throws Exception {
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.ONE;
        BigInteger gasLimit = BigInteger.TEN;
        String to = "0x0add5355";
        BigInteger value = BigInteger.valueOf(Long.MAX_VALUE);
        RawTransaction rawTransaction =
                RawTransaction.createEtherTransaction(nonce, gasPrice, gasLimit, to, value);
        byte[] signedMessage =
                TransactionEncoder.signMessage(rawTransaction, SampleKeys.CREDENTIALS);
        String hexMessage = Numeric.toHexString(signedMessage);

        RawTransaction result = TransactionDecoder.decode(hexMessage);
        assertNotNull(result);
        assertEquals(nonce, result.getNonce());
        assertEquals(gasPrice, result.getGasPrice());
        assertEquals(gasLimit, result.getGasLimit());
        assertEquals(to, result.getTo());
        assertEquals(value, result.getValue());
        assertEquals("", result.getData());
        assertTrue(result instanceof SignedRawTransaction);
        SignedRawTransaction signedResult = (SignedRawTransaction) result;
        assertNotNull(signedResult.getSignatureData());
        Sign.SignatureData signatureData = signedResult.getSignatureData();
        byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
        BigInteger key = Sign.signedMessageToKey(encodedTransaction, signatureData);
        assertEquals(key, SampleKeys.PUBLIC_KEY);
        assertEquals(SampleKeys.ADDRESS, signedResult.getFrom());
        signedResult.verify(SampleKeys.ADDRESS);
        assertNull(signedResult.getChainId());
        assertFalse(result.isPrivate());
    }

    @Test
    public void testOgoDecodingSigned() throws Exception {
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.ONE;
        BigInteger gasLimit = BigInteger.TEN;
        String to = Bech32.toBech32Address("0x0add5355");
        BigInteger value = BigInteger.valueOf(Long.MAX_VALUE);
        RawTransaction rawTransaction =
                RawTransaction.createOgoTransaction(nonce, gasPrice, gasLimit, to, value);
        byte[] signedMessage =
                TransactionEncoder.signMessage(rawTransaction, SampleKeys.CREDENTIALS);
        String hexMessage = Numeric.toHexString(signedMessage);

        RawTransaction result = TransactionDecoder.decode(hexMessage);
        assertNotNull(result);
        assertEquals(nonce, result.getNonce());
        assertEquals(gasPrice, result.getGasPrice());
        assertEquals(gasLimit, result.getGasLimit());
        assertEquals(to, Bech32.toBech32Address(result.getTo()));
        assertEquals(value, result.getValue());
        assertEquals("", result.getData());
        assertTrue(result instanceof SignedRawTransaction);
        SignedRawTransaction signedResult = (SignedRawTransaction) result;
        assertNotNull(signedResult.getSignatureData());
        Sign.SignatureData signatureData = signedResult.getSignatureData();
        byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
        BigInteger key = Sign.signedMessageToKey(encodedTransaction, signatureData);
        assertEquals(key, SampleKeys.PUBLIC_KEY);
        assertEquals(SampleKeys.ADDRESS, signedResult.getFrom());
        signedResult.verify(SampleKeys.ADDRESS);
        assertNull(signedResult.getChainId());
        assertFalse(result.isPrivate());
    }

    @Test
    public void testDecodingSignedChainId() throws Exception {
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.ONE;
        BigInteger gasLimit = BigInteger.TEN;
        String to = "0x0add5355";
        BigInteger value = BigInteger.valueOf(Long.MAX_VALUE);
        long chainId = 46;
        RawTransaction rawTransaction =
                RawTransaction.createEtherTransaction(nonce, gasPrice, gasLimit, to, value);
        byte[] signedMessage =
                TransactionEncoder.signMessage(rawTransaction, chainId, SampleKeys.CREDENTIALS);
        String hexMessage = Numeric.toHexString(signedMessage);

        RawTransaction result = TransactionDecoder.decode(hexMessage);
        assertNotNull(result);
        assertEquals(nonce, result.getNonce());
        assertEquals(gasPrice, result.getGasPrice());
        assertEquals(gasLimit, result.getGasLimit());
        assertEquals(to, result.getTo());
        assertEquals(value, result.getValue());
        assertEquals("", result.getData());
        assertTrue(result instanceof SignedRawTransaction);
        SignedRawTransaction signedResult = (SignedRawTransaction) result;
        assertEquals(SampleKeys.ADDRESS, signedResult.getFrom());
        signedResult.verify(SampleKeys.ADDRESS);
        assertEquals(chainId, signedResult.getChainId().longValue());
        assertFalse(result.isPrivate());
    }

    @Test
    public void testOgoDecodingSignedChainId() throws Exception {
        BigInteger nonce = BigInteger.ZERO;
        BigInteger gasPrice = BigInteger.ONE;
        BigInteger gasLimit = BigInteger.TEN;
        String to = Bech32.toBech32Address("0x0add5355");
        BigInteger value = BigInteger.valueOf(Long.MAX_VALUE);
        long chainId = 46;
        RawTransaction rawTransaction =
                RawTransaction.createOgoTransaction(nonce, gasPrice, gasLimit, to, value);
        byte[] signedMessage =
                TransactionEncoder.signMessage(rawTransaction, chainId, SampleKeys.CREDENTIALS);
        String hexMessage = Numeric.toHexString(signedMessage);

        RawTransaction result = TransactionDecoder.decode(hexMessage);
        assertNotNull(result);
        assertEquals(nonce, result.getNonce());
        assertEquals(gasPrice, result.getGasPrice());
        assertEquals(gasLimit, result.getGasLimit());
        assertEquals(to, Bech32.toBech32Address(result.getTo()));
        assertEquals(value, result.getValue());
        assertEquals("", result.getData());
        assertTrue(result instanceof SignedRawTransaction);
        SignedRawTransaction signedResult = (SignedRawTransaction) result;
        assertEquals(SampleKeys.ADDRESS, signedResult.getFrom());
        signedResult.verify(SampleKeys.ADDRESS);
        assertEquals(chainId, signedResult.getChainId().longValue());
        assertFalse(result.isPrivate());
    }

    @Test
    public void testRSize31() throws Exception {

        String hexTransaction =
                "0xf883370183419ce09433c98f20dd73d7bb1d533c4aa3371f2b30c6ebde80a45093dc7d"
                        + "00000000000000000000000000000000000000000000000000000000000000351c"
                        + "9fb90996c836fb34b782ee3d6efa9e2c79a75b277c014e353b51b23b00524d2da"
                        + "07435ebebca627a51a863bf590aff911c4746ab8386a0477c8221bb89671a5d58";

        RawTransaction result = TransactionDecoder.decode(hexTransaction);
        SignedRawTransaction signedResult = (SignedRawTransaction) result;
        assertEquals("0x1b609b03e2e9b0275a61fa5c69a8f32550285536", signedResult.getFrom());
    }

    @Test
    public void testDecodingPrivateTx() throws Exception {
        String p_tx_raw =
                "0xf9046c0c8506fc23ac00825208028998ed3d49b390f4000080f90410c0f903c1f903b"
                        + "ea082cdd17129723f212a77ac2dcc00a2e296cb88b8a38f5fbd472f27ab55c1"
                        + "c836a008afa1d831ad3e8bba7d68e8a44ed9efab5fa20a6a1c85f10d711d81c2"
                        + "afbd6ea0b0b808ea38bdd0686dc5fe6226ef1c3204ed6ba0e6a0b441ad46fb80"
                        + "5b57785cb90244bfa283dd645600bc23f930646c32254dafb0c2113eab45d34e"
                        + "fa7d6b3dfef25b726174b1d0537dea36a83ff1cf20c213c57facc25dae34610"
                        + "51015e8e60957027e3304dcacb3c615bd5c3da74437465bc23af6d4b330f142"
                        + "1fa03e866f89f68d6a58a5486003489a78da270c2a48d89ab3a5b1a5697e4b57"
                        + "d87eb81288374de36596438be9c38884f3dfbead49c1014424acd172bc821b7"
                        + "42e3b147fbfd641f3a3c339a12866a9b06a6e86718845ece862a9ffd727f6d9"
                        + "1da7e6a8239776a49c57700d1918287305b9d465a09d4767cdee8e3faa9961ab"
                        + "ba5eae934f8e28481c5a06bf07a38669d4b678bcdc3bee411db991319998d564"
                        + "b29dfef488c4d5d16e893b45af4a1cd5157d47c58da7f40a3d003d42066990d8d2"
                        + "fe0a82c200311e8ecf1a885289ca52a63367637e1e38a4953a9fe1f85803b72104"
                        + "82b76f8620786289803d170daf0da8f7b35ff4132f92778f50d757494bd784a227"
                        + "eadda677698eb3b28de5b23184d503d12abe3e557dd15ffdf0e783dc213aee4f40"
                        + "62c926feb89f1bfd2c69e0372051d787391d73ca6a1252987be85de26e261f69af"
                        + "cf16db21ff55160a8310a7240e791565935ec03d53105b4ceca23592c894a3035efa6"
                        + "f1fd20785a6cce6db1c8016bd68e84331fba63eb41203d98ccb0ab703e7de2c13167eb1e"
                        + "1ae5c48532820280759ce0fb4c4062b79b0342b5aec922cf2f1714a6a37bb8b35e0201"
                        + "4ab575ea164221c58b6311e86b6ea64c6d900fd2c73504dab92edffae2d67b897270b72"
                        + "a14ed2bee7aa7992d3d3da26f7c466fd248b33e9df24b2466e513ab850c3653987ef93"
                        + "ade564adaeb11cf477f0e4d89fb34a2e3127b1615ab35db1aa4ec00a1051ef119eced09"
                        + "43d23b84f4eec8a504b7ce072e63d10f0f323353e4a6c57a9a61844e0c7c5d8be3b59100"
                        + "f46f2b8c093cb6af398497b07c13ad30e63b6b944f0b9ef3fd59964116078dc97029498ac"
                        + "7ef71e7366bee3d17c3a9611dbf10f4eaf2a4ba503bef388a9cfd175960eec7f37df8de267"
                        + "40e01bed2039cbaafc6dee4e9d907a44c75aa53a85865b5b44ec63155b54a7c08d54a8f4"
                        + "9aac8e698c0d96d35a6a84690692ead9742993464c6de80d132cb1c3d364e843d7dd5045c7"
                        + "e338b172201c6acdeebddb5d253b8a0c334192f6358ee4f7667af902441c3303d073cec4a8"
                        + "05a3b2238653ce57eaf930272b88fffffd6f2f4c0e00b84090a23327d59256c667a4af486d"
                        + "1c4678b8074c512707cc12ccdd66632ab5fdaf1c4ab7796b490e088ab55d77c17651a2746fe7824"
                        + "806169b020ee4f5c0c68d0857a0c8b940d8795bfd82e4ab3a05583da5e8df2ea18245983d5c994"
                        + "c608a2ccb01daa05cc08ff1b400f9d74d82875a1a3bd30a393c362e43279f346e4b6d63d0a56728";
        RawTransaction tx = TransactionDecoder.decode(p_tx_raw);
        assertEquals(BigInteger.valueOf(12), tx.getNonce());
        assertEquals(BigInteger.valueOf(21000), tx.getGasLimit());
        assertEquals(BigInteger.valueOf(30000000000L), tx.getGasPrice());
        assertEquals(new BigInteger("2821000000000000000000"), tx.getValue());
        assertEquals("", tx.getData());
        assertEquals("", tx.getTo());
        assertTrue(tx.isPrivate());

        String p_tx_raw2 =
                "0xf905cd808506fc23ac0082520895033be3fa8b13f033394fc9f2114ed4b01f9140cd"
                        + "398901a055690d9db8000080f9059cf9018df9018aa057aaa434dcc529cccb"
                        + "1d0bd939be6216bbdf601780e45af12121fbea225f9c96a0ff8b45f7b8abbc"
                        + "e4dc94205ddc19c368f2ae02cb3976e5cb774c7928fddc2a12a0128cdc79ae"
                        + "94fe6ec5ef1e01f1134c8f654ff51ae5f0feb2d63a03aa73651c36a0daad7a"
                        + "b0180ecdb410c95f6fec98f7979fd839753138e9caf9e992490c3d7795b8c0"
                        + "afbaeaf9528c1c7bbc3fe9ea5dcfd7ba419693498118533173d6368b1ff1a5"
                        + "48e855e326d461e6d75884650b9524c9dc94daa15f1e845fb4c84cebf4dbf1"
                        + "9338728765e96b0851c21cf4c49ef3360b1aa2bc36ca3d59b9cd93de73f30c"
                        + "20f7c31442927228609f6b95cdc514b1f7a28370287ed5cdaaf228c91c6987"
                        + "c17442bde442d9daf639662bd4f37e5eee0ab0a08251325df2e27249576241"
                        + "60a8698e95def3aa005561d269d9052d1a2547f9ab3357b48debb2821e5f33"
                        + "ac162f167980f842a00cef2cf707494f85ae36e9c9cc0164a963f22b8bb488"
                        + "7b1bcfc8a1f030f8a351a0dadbb14ff3a2ac8272d79812aab5f56f3d5e4337"
                        + "e054692c97aad0ecb3918e0df903c1f903bea0ba183001bf7a9ce7d226b17e"
                        + "9cd39cf63e24a8738ddeb3b1911de8edad0bc9efa0d82d1dd419ab1eac82d3"
                        + "79cadf7bc5a601b88df16bc2dbf9457986340a828f71a0d44cf0ef4830883d"
                        + "f97ec44ea78b734d28a2744b2fb270637cc2b917e8a334a3b90244de203b40"
                        + "9ecf4736b295bc9d137d33ff5c68782e59178602cdf4bf2bebadc4c5e1401c"
                        + "abdfabe487140bb6899bafefb8424c399ba6dd56ced4330ec0f48243301eb8"
                        + "f51d252072fc053d480c87ac5f8645d6e6318afe44f55169a41f7556d2400f"
                        + "4b0213c8485cab958ea25e4f757b53e4f5a76f8cf1223fb85a1db605eedf74"
                        + "0b2cb0777f9115655e6ba3be1fe815e28dc738c290dd85510cf96eafed1554"
                        + "6d1a5805da621aec595bb2ce73cb499708b2ac910d7d813ca8b6581dd71489"
                        + "23dc10e23f7b0c722326d4d307ecb9970bf1d9857e491b1e7c28b753950cdd"
                        + "8332a660bc7f14cc093be37017606add777aa3f3d77d48525348ca8a62e1f6"
                        + "2c8ee3a93b04c2235a33e7ee8784b66fc291c56afabd8da98b75816184faf7"
                        + "66ba68255ac52d0c2a45c3fffa786be78ad74dc01ba6ffcf91466742414829"
                        + "a39ed26000d3fe56a9202791a534892a1aa70d1fa3f54fc1ffaed96403a780"
                        + "22a613db2596199e06928fc68f25c08919cd3c35227ec9464a30abce8d5897"
                        + "c5d2cca1016b4f9477f9e8bb6b128f1cad40f522de9a7e1434d06193b0ace3"
                        + "c60b4c3fe637ce33273704635a561e18a18e497c6cf6b8bce0dad8c7574bb8"
                        + "cf2f105e8787851596ba6fe10ec2d2fbe72122f32f3ff05c00723aa1d5c582"
                        + "1b616b1de687c52ebf9382f37345e7fe860d24aee892cb4cecefa462f8fec8"
                        + "970cb8b22ee1822e41fc88b174550c78513bc2f0089d30696cb2ef01fe00f9"
                        + "eb7389dc93afc94d517ef82128cfe70746d452d70aeea271f9a83719dfc2c3"
                        + "94ed814402bab2c1defb48052224e37daaa3b850eb952c2a8506097dd4ab48"
                        + "f6403e38a0e330f8b7ccc8bce97f987917f492a85bdbe0d53fcfb54173834b"
                        + "8892b76e409f9c3e9b792a8d624f6fc3eb41dbd5bda0a5f5e0f748b549264c"
                        + "33dccfd4c14450b8c0b87b00360f9a5fcfe13e83d749a41d3351775b1a9782"
                        + "ce67532c8091139e7fc71c3675bf957ab8a4c3efdeb1ac8a4168976628bcc6"
                        + "2b37ff7ca7519ea9ab7da3f76ecc979e1d6119715c5cd1f1db01460c4c47ac"
                        + "3a48f6905d2d4a319cf18210023f59bc460cc65ab298c59bb6bd2259bb7f2de"
                        + "9b8ac97243e72d8a4e74c99f1fa405b0e486a0567e7a81462c4d2e514a62432"
                        + "063ca5aaf6070f12cbefbb8eafcd4bab0e2dbedd00c40f2d9273edb4ff81af"
                        + "a07444e5a2d11086b535a1f7007a8506fc2d48f0b8405b352d2b9e53097c88"
                        + "c5cf1dc10cea30670aaf9210178f3c7b803fc732960c4ccaa02263638bf51c"
                        + "ae5e6b7acf0114e141dd9a1a0ce9715e2de114f0f53b51011a8080";
        RawTransaction tx2 = TransactionDecoder.decode(p_tx_raw2);
        assertEquals("0x3be3fa8b13f033394fc9f2114ed4b01f9140cd39", tx2.getTo());
    }
}
