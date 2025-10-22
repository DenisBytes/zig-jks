const std = @import("std");
const testing = std.testing;
const common = @import("common.zig");
const types = @import("types.zig");

const Error = types.Error;

const salt_len = 20;

// OID for Sun's proprietary key protection algorithm: 1.3.6.1.4.1.42.2.17.1.1
const supported_oid = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01 };

/// Minimal ASN.1 encoder for keyInfo structure
const Asn1Encoder = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator) Asn1Encoder {
        return .{
            .allocator = allocator,
            .buffer = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: *Asn1Encoder) void {
        self.buffer.deinit();
    }

    fn encodeLength(self: *Asn1Encoder, len: usize) !void {
        if (len < 128) {
            try self.buffer.append(@intCast(len));
        } else if (len <= 0xFF) {
            try self.buffer.append(0x81);
            try self.buffer.append(@intCast(len));
        } else if (len <= 0xFFFF) {
            try self.buffer.append(0x82);
            try self.buffer.append(@intCast(len >> 8));
            try self.buffer.append(@intCast(len & 0xFF));
        } else {
            return error.DataTooLong;
        }
    }

    fn encodeOctetString(self: *Asn1Encoder, data: []const u8) !void {
        try self.buffer.append(0x04); // OCTET STRING tag
        try self.encodeLength(data.len);
        try self.buffer.appendSlice(data);
    }

    fn encodeOid(self: *Asn1Encoder, oid: []const u8) !void {
        try self.buffer.append(0x06); // OID tag
        try self.encodeLength(oid.len);
        try self.buffer.appendSlice(oid);
    }

    fn encodeNull(self: *Asn1Encoder) !void {
        try self.buffer.append(0x05); // NULL tag
        try self.buffer.append(0x00); // NULL length
    }

    fn encodeSequence(self: *Asn1Encoder, data: []const u8) !void {
        try self.buffer.append(0x30); // SEQUENCE tag
        try self.encodeLength(data.len);
        try self.buffer.appendSlice(data);
    }
};

/// Minimal ASN.1 decoder for keyInfo structure
const Asn1Decoder = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) Asn1Decoder {
        return .{ .data = data, .pos = 0 };
    }

    fn readByte(self: *Asn1Decoder) !u8 {
        if (self.pos >= self.data.len) return error.EndOfStream;
        const byte = self.data[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readLength(self: *Asn1Decoder) !usize {
        const first = try self.readByte();
        if (first < 128) {
            return first;
        }

        const num_bytes = first & 0x7F;
        if (num_bytes > 2) return error.InvalidKeyData;

        var length: usize = 0;
        var i: usize = 0;
        while (i < num_bytes) : (i += 1) {
            length = (length << 8) | try self.readByte();
        }

        return length;
    }

    fn readBytes(self: *Asn1Decoder, len: usize) ![]const u8 {
        if (self.pos + len > self.data.len) return error.EndOfStream;
        const slice = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return slice;
    }

    fn expectTag(self: *Asn1Decoder, expected: u8) !void {
        const tag = try self.readByte();
        if (tag != expected) return error.InvalidKeyData;
    }

    fn readSequence(self: *Asn1Decoder) ![]const u8 {
        try self.expectTag(0x30); // SEQUENCE
        const len = try self.readLength();
        return try self.readBytes(len);
    }

    fn readOid(self: *Asn1Decoder) ![]const u8 {
        try self.expectTag(0x06); // OID
        const len = try self.readLength();
        return try self.readBytes(len);
    }

    fn readOctetString(self: *Asn1Decoder) ![]const u8 {
        try self.expectTag(0x04); // OCTET STRING
        const len = try self.readLength();
        return try self.readBytes(len);
    }

    fn skipNull(self: *Asn1Decoder) !void {
        try self.expectTag(0x05); // NULL
        _ = try self.readByte(); // length must be 0
    }
};

/// Encrypt a private key using JKS proprietary algorithm
pub fn encrypt(
    allocator: std.mem.Allocator,
    rand: std.Random,
    plain_key: []const u8,
    password: []const u8,
) ![]u8 {
    var hash = std.crypto.hash.Sha1.init(.{});
    const hash_size = std.crypto.hash.Sha1.digest_length;

    // Convert password
    const password_bytes = try common.passwordBytes(allocator, password);
    defer {
        common.zeroing(password_bytes);
        allocator.free(password_bytes);
    }

    const plain_key_len = plain_key.len;
    var num_rounds = plain_key_len / hash_size;
    if (plain_key_len % hash_size != 0) {
        num_rounds += 1;
    }

    // Generate random salt
    var salt: [salt_len]u8 = undefined;
    rand.bytes(&salt);

    // Generate XOR key
    const xor_key = try allocator.alloc(u8, plain_key_len);
    defer allocator.free(xor_key);

    var digest = salt;
    var xor_offset: usize = 0;

    var round: usize = 0;
    while (round < num_rounds) : (round += 1) {
        hash = std.crypto.hash.Sha1.init(.{});
        hash.update(password_bytes);
        hash.update(&digest);
        hash.final(&digest);

        const copy_len = @min(hash_size, plain_key_len - xor_offset);
        @memcpy(xor_key[xor_offset .. xor_offset + copy_len], digest[0..copy_len]);
        xor_offset += copy_len;
    }

    // XOR plain key with xor_key
    const tmp_key = try allocator.alloc(u8, plain_key_len);
    defer allocator.free(tmp_key);

    for (plain_key, 0..) |byte, i| {
        tmp_key[i] = byte ^ xor_key[i];
    }

    // Compute final digest
    hash = std.crypto.hash.Sha1.init(.{});
    hash.update(password_bytes);
    hash.update(plain_key);
    hash.final(&digest);

    // Assemble encrypted key: salt || tmp_key || digest
    const encrypted_key = try allocator.alloc(u8, salt_len + plain_key_len + hash_size);
    defer allocator.free(encrypted_key);

    @memcpy(encrypted_key[0..salt_len], &salt);
    @memcpy(encrypted_key[salt_len .. salt_len + plain_key_len], tmp_key);
    @memcpy(encrypted_key[salt_len + plain_key_len ..], &digest);

    // Encode with ASN.1
    var encoder = Asn1Encoder.init(allocator);
    defer encoder.deinit();

    // Encode AlgorithmIdentifier: SEQUENCE { OID, NULL }
    var algo_buf = std.ArrayList(u8).init(allocator);
    defer algo_buf.deinit();

    var algo_enc = Asn1Encoder.init(allocator);
    defer algo_enc.deinit();

    try algo_enc.encodeOid(&supported_oid);
    try algo_enc.encodeNull();

    try encoder.encodeSequence(algo_enc.buffer.items);
    try encoder.encodeOctetString(encrypted_key);

    // Wrap in outer SEQUENCE
    const inner = try allocator.dupe(u8, encoder.buffer.items);
    defer allocator.free(inner);

    encoder.buffer.clearRetainingCapacity();
    try encoder.encodeSequence(inner);

    return try encoder.buffer.toOwnedSlice();
}

/// Decrypt a private key using JKS proprietary algorithm
pub fn decrypt(
    allocator: std.mem.Allocator,
    data: []const u8,
    password: []const u8,
) ![]u8 {
    // Decode ASN.1
    var decoder = Asn1Decoder.init(data);

    const outer_seq = try decoder.readSequence(); // Outer SEQUENCE
    var inner_decoder = Asn1Decoder.init(outer_seq);

    // Read AlgorithmIdentifier
    const algo_seq = try inner_decoder.readSequence();
    var algo_decoder = Asn1Decoder.init(algo_seq);

    const oid = try algo_decoder.readOid();
    if (!std.mem.eql(u8, oid, &supported_oid)) {
        return Error.UnsupportedAlgorithm;
    }

    try algo_decoder.skipNull();

    // Read encrypted private key
    const encrypted_key = try inner_decoder.readOctetString();

    if (inner_decoder.pos != inner_decoder.data.len) {
        return Error.InvalidKeyData;
    }

    // Decrypt
    var hash = std.crypto.hash.Sha1.init(.{});
    const hash_size = std.crypto.hash.Sha1.digest_length;

    const password_bytes = try common.passwordBytes(allocator, password);
    defer {
        common.zeroing(password_bytes);
        allocator.free(password_bytes);
    }

    if (encrypted_key.len < salt_len + hash_size) {
        return Error.InvalidKeyData;
    }

    var salt: [salt_len]u8 = undefined;
    @memcpy(&salt, encrypted_key[0..salt_len]);

    const encrypted_key_len = encrypted_key.len - salt_len - hash_size;
    var num_rounds = encrypted_key_len / hash_size;
    if (encrypted_key_len % hash_size != 0) {
        num_rounds += 1;
    }

    const encrypted_part = encrypted_key[salt_len .. salt_len + encrypted_key_len];

    // Generate XOR key
    const xor_key = try allocator.alloc(u8, encrypted_key_len);
    defer allocator.free(xor_key);

    var digest = salt;
    var xor_offset: usize = 0;

    var round: usize = 0;
    while (round < num_rounds) : (round += 1) {
        hash = std.crypto.hash.Sha1.init(.{});
        hash.update(password_bytes);
        hash.update(&digest);
        hash.final(&digest);

        const copy_len = @min(hash_size, encrypted_key_len - xor_offset);
        @memcpy(xor_key[xor_offset .. xor_offset + copy_len], digest[0..copy_len]);
        xor_offset += copy_len;
    }

    // XOR to get plain key
    const plain_key = try allocator.alloc(u8, encrypted_key_len);
    errdefer allocator.free(plain_key);

    for (encrypted_part, 0..) |byte, i| {
        plain_key[i] = byte ^ xor_key[i];
    }

    // Verify digest
    hash = std.crypto.hash.Sha1.init(.{});
    hash.update(password_bytes);
    hash.update(plain_key);
    hash.final(&digest);

    const expected_digest = encrypted_key[salt_len + encrypted_key_len ..];
    if (!std.mem.eql(u8, &digest, expected_digest)) {
        return Error.InvalidDigest;
    }

    return plain_key;
}

// Tests

test "encrypt and decrypt round trip" {
    var prng = std.Random.DefaultPrng.init(0);
    const rand = prng.random();

    const plain_key = "test private key data";
    const password = "password123";

    const encrypted = try encrypt(testing.allocator, rand, plain_key, password);
    defer testing.allocator.free(encrypted);

    const decrypted = try decrypt(testing.allocator, encrypted, password);
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(plain_key, decrypted);
}

test "decrypt with wrong password fails" {
    var prng = std.Random.DefaultPrng.init(0);
    const rand = prng.random();

    const plain_key = "test private key data";
    const password = "password123";

    const encrypted = try encrypt(testing.allocator, rand, plain_key, password);
    defer testing.allocator.free(encrypted);

    const result = decrypt(testing.allocator, encrypted, "wrongpassword");
    try testing.expectError(Error.InvalidDigest, result);
}

test "encrypt with different key sizes" {
    var prng = std.Random.DefaultPrng.init(0);
    const rand = prng.random();

    const password = "password123";

    // Test various key sizes
    const sizes = [_]usize{ 16, 32, 64, 100, 256 };

    for (sizes) |size| {
        const plain_key = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(plain_key);

        for (plain_key, 0..) |*byte, i| {
            byte.* = @intCast(i % 256);
        }

        const encrypted = try encrypt(testing.allocator, rand, plain_key, password);
        defer testing.allocator.free(encrypted);

        const decrypted = try decrypt(testing.allocator, encrypted, password);
        defer testing.allocator.free(decrypted);

        try testing.expectEqualSlices(u8, plain_key, decrypted);
    }
}
