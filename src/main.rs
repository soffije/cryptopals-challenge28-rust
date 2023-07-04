use std::io::Error;

// SHA-1 implementation
fn sha1(message: &[u8]) -> Result<[u8; 20], Error> {
    let mut padded_message = Vec::new();
    padded_message.extend_from_slice(message);

    // Append byte '1' after the message
    padded_message.push(0x80);

    // Append bytes '0' until the length is congruent to 448 % 512 bytes
    while padded_message.len() % 64 != 56 {
        padded_message.push(0);
    }

    let message_length_bits = (message.len() as u64) * 8;

    // Append the message length (64 bits) in big-endian order
    padded_message.extend_from_slice(&message_length_bits.to_be_bytes());

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    for chunk in padded_message.chunks_exact(64) {
        let mut words = [0u32; 80];

        // Split each 64-byte chunk into 16 words of 32 bits
        for (i, chunk) in chunk.chunks_exact(4).enumerate() {
            words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        // Extend 16 words into 80 words
        for i in 16..80 {
            words[i] = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
            words[i] = words[i].rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4); // Initialize variables a, b, c, d, e with initial hash values

        for (i, word) in words.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999), // Constants and logic for rounds 0-19
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1), // Constants and logic for rounds 20-39
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC), // Constants and logic for rounds 40-59
                60..=79 => (b ^ c ^ d, 0xCA62C1D6), // Constants and logic for rounds 60-79
                _ => unreachable!(), // Should never happen
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word); // Calculate temporary value for the current round

            e = d; // Update variable e
            d = c; // Update variable d
            c = b.rotate_left(30); // Update variable c
            b = a; // Update variable b
            a = temp; // Update variable a
        }

        h0 = h0.wrapping_add(a); // Update hash value h0 with variable a
        h1 = h1.wrapping_add(b); // Update hash value h1 with variable b
        h2 = h2.wrapping_add(c); // Update hash value h2 with variable c
        h3 = h3.wrapping_add(d); // Update hash value h3 with variable d
        h4 = h4.wrapping_add(e); // Update hash value h4 with variable e
    }

    let mut result = [0u8; 20]; // Create a mutable array for the final result with length 20
    result[0..4].copy_from_slice(&h0.to_be_bytes()); // Copy h0 to the result array
    result[4..8].copy_from_slice(&h1.to_be_bytes()); // Copy h1 to the result array
    result[8..12].copy_from_slice(&h2.to_be_bytes()); // Copy h2 to the result array
    result[12..16].copy_from_slice(&h3.to_be_bytes()); // Copy h3 to the result array
    result[16..20].copy_from_slice(&h4.to_be_bytes()); // Copy h4 to the result array

    Ok(result)
}

// Implemented MAC = SHA1(key || message)
fn calculate_mac(key: &[u8], message: &[u8]) -> Result<[u8; 20], Error> {
    let mut mac_input = Vec::with_capacity(key.len() + message.len()); // Create a new vector to store the MAC input
    mac_input.extend_from_slice(key); // Append the key to the MAC input vector
    mac_input.extend_from_slice(message); // Append the message to the MAC input vector

    let mac_result = sha1(&mac_input)?;
    Ok(mac_result)
}

fn main() {
    let key = b"secret_key";
    let message = b"Hello, world!";

    if let Ok(mac) = calculate_mac(key, message) {
        println!("MAC: {}", hex::encode(mac));

        // Attempt to forge a message
        let forged_message = b"Hello, forged message!";
        if let Ok(forged_mac) = calculate_mac(key, forged_message) {
            println!("Forged MAC: {}", hex::encode(forged_mac));

            if forged_mac == mac {
                println!("The forged message has the same MAC as the original message.");
            } else {
                println!("The forged message has a different MAC from the original message.");
            }
        } else {
            println!("Failed to calculate MAC for the forged message.");
        }

        // Attempt to create a new MAC without knowing the key
        let another_key = b"another_key";
        if let Ok(mac_with_another_key) = calculate_mac(another_key, message) {
            println!("MAC with another key: {}", hex::encode(mac_with_another_key));

            if mac_with_another_key == mac {
                println!("A new MAC was successfully created with another key.");
            } else {
                println!("A new MAC could not be created without knowing the key.");
            }
        } else {
            println!("Failed to calculate MAC with another key.");
        }
    } else {
        println!("Failed to calculate MAC.");
    }
}
