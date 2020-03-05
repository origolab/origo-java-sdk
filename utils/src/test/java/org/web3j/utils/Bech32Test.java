package org.web3j.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.web3j.utils.Bech32.fromBech32Address;
import static org.web3j.utils.Bech32.toBech32Address;


public class Bech32Test {
    @Test
    public void testEncodeDecodeHexToBech32() throws Exception {
        String hex_address = "3A8B8ECF0A6AB5AAFA08EA4C74A84E27B208EBEA";
        String bech32 = Bech32.toBech32Address(hex_address);
        String decoded_hex = Bech32.fromBech32Address(bech32);
        assertEquals(hex_address, decoded_hex);
    }
}
