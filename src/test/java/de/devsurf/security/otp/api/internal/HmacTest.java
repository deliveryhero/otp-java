/*
 * JBoss, Home of Professional Open Source
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.devsurf.security.otp.api.internal;

import java.nio.ByteBuffer;

import org.junit.Test;


import de.devsurf.security.otp.api.Clock;
import de.devsurf.security.otp.api.Hash;
import de.devsurf.security.otp.api.internal.Base32;
import de.devsurf.security.otp.api.internal.Hmac;

import static junit.framework.Assert.assertEquals;

public class HmacTest {
    @Test
    public void testDigest() throws Exception {
    	byte[] challenge = ByteBuffer.allocate(8).putLong(new Clock().getCurrentInterval()).array();
        byte[] hash = new Hmac(Hash.SHA1, Base32.decode(Base32.random())).digest(challenge);
        assertEquals(20, hash.length);
    }
}
