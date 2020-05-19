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
package org.web3j.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Bech32Test {
    @Test
    public void testEncodeDecodeHexToBech32() throws Exception {
        String hex_address = "3A8B8ECF0A6AB5AAFA08EA4C74A84E27B208EBEA";
        String bech32 = Bech32.toBech32Address(hex_address);
        String decoded_hex = Bech32.fromBech32Address(bech32);
        assertEquals(hex_address, decoded_hex);
    }
}
