#ifndef SPACE_TCP_HMAC_HPP
#define SPACE_TCP_HMAC_HPP

// Code taken and adapted from https://github.com/unixpickle/LibOrange/blob/master/LibOrange/hmac-sha256.c

/*
 * Copyright 2006 Apple Computer, Inc.  All rights reserved.
 *
 * iTunes U Sample Code License
 * IMPORTANT:  This Apple software is supplied to you by Apple Computer, Inc. ("Apple")
 * in consideration of your agreement to the following terms, and your use,
 * installation, modification or distribution of this Apple software constitutes
 * acceptance of these terms.  If you do not agree with these terms, please do not use,
 * install, modify or distribute this Apple software.
 *
 * In consideration of your agreement to abide by the following terms and subject to
 * these terms, Apple grants you a personal, non-exclusive, non-transferable license,
 * under Apple's copyrights in this original Apple software (the "Apple Software"):
 *
 * (a) to internally use, reproduce, modify and internally distribute the Apple
 * Software, with or without modifications, in source and binary forms, within your
 * educational organization or internal campus network for the sole purpose of
 * integrating Apple's iTunes U software with your internal campus network systems; and
 *
 * (b) to redistribute the Apple Software to other universities or educational
 * organizations, with or without modifications, in source and binary forms, for the
 * sole purpose of integrating Apple's iTunes U software with their internal campus
 * network systems; provided that the following conditions are met:
 *
 * 	-  If you redistribute the Apple Software in its entirety and without
 *     modifications, you must retain the above copyright notice, this entire license
 *     and the disclaimer provisions in all such redistributions of the Apple Software.
 * 	-  If you modify and redistribute the Apple Software, you must indicate that you
 *     have made changes to the Apple Software, and you must retain the above
 *     copyright notice, this entire license and the disclaimer provisions in all
 *     such redistributions of the Apple Software and/or derivatives thereof created
 *     by you.
 *     -  Neither the name, trademarks, service marks or logos of Apple may be used to
 *     endorse or promote products derived from the Apple Software without specific
 *     prior written permission from Apple.
 *
 * Except as expressly stated above, no other rights or licenses, express or implied,
 * are granted by Apple herein, including but not limited to any patent rights that may
 * be infringed by your derivative works or by other works in which the Apple Software
 * may be incorporated.  THE APPLE SOFTWARE IS PROVIDED BY APPLE ON AN "AS IS" BASIS.
 * APPLE MAKES NO WARRANTIES, EXPRESS OR IMPLIED, AND HEREBY DISCLAIMS ALL WARRANTIES,
 * INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES OF NON-INFRINGEMENT,
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE
 * OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS OR SYSTEMS.
 * APPLE IS NOT OBLIGATED TO PROVIDE ANY MAINTENANCE, TECHNICAL OR OTHER SUPPORT FOR
 * THE APPLE SOFTWARE, OR TO PROVIDE ANY UPDATES TO THE APPLE SOFTWARE.  IN NO EVENT
 * SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
 * OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
 * (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Rev.  120806
 *
 * This source code file contains a self-contained ANSI C program with no
 * external dependencies except for standard ANSI C libraries. On Mac OS X, it
 * can be compiled and run by executing the following commands in a terminal
 * window:
 *     gcc -o seconds seconds.c
 *     ./seconds
 */

#include "sha256.hpp"

namespace space_tcp {

class Hmac {
public:
    static auto create(const uint8_t *key, size_t len) -> Hmac {
        return {key, len};
    }

    auto get_digest() -> uint8_t * {
        return digest;
    }

    void sha256_update(const uint8_t *message, size_t len) {
        sha.update(message, len);
    }

    void sha256_finalize(const uint8_t *msg, size_t len) {
        // Finalize the inner hash and store its value in the digest array.
        sha.finalize(msg, len);
        for (auto i = 0; i < 32; ++i) this->digest[i] = this->sha.get_hash()[i];
        // Convert the inner hash key block to the outer hash key block.
        for (unsigned char &i : this->key) i ^= (0x36 ^ 0x5c);
        // Calculate the outer hash.
        sha = Sha256::create();
        sha.update(this->key, 64);
        sha.finalize(this->digest, 32);
        // Use the outer hash value as the HMAC digest.
        for (auto i = 0; i < 32; ++i) this->digest[i] = this->sha.get_hash()[i];
    }

private:
    Hmac(const uint8_t *key, size_t len) : sha{Sha256::create()} {
        size_t i;
        // Prepare the inner hash key block, hashing the key if it's too long.
        if (len <= 64) {
            for (i = 0; i < len; ++i) this->key[i] = static_cast<uint8_t>(key[i] ^ 0x36);
            for (; i < 64; ++i) this->key[i] = 0x36;
        } else {
            sha.finalize(key, len);
            for (i = 0; i < 32; ++i) this->key[i] = static_cast<uint8_t>(this->sha.get_hash()[i] ^ 0x36);
            for (; i < 64; ++i) this->key[i] = 0x36;
        }
        // Initialize the inner hash with the key block.
        sha = Sha256::create();
        sha.update(this->key, 64);
    }

    uint8_t digest[32]{};
    uint8_t key[64]{};
    Sha256 sha;
};

}  // namespace space_tcp

#endif //SPACE_TCP_HMAC_HPP
