const std = @import("std");
const testing = std.testing;
const common = @import("common.zig");
const types = @import("types.zig");
const encoder_mod = @import("encoder.zig");
const decoder_mod = @import("decoder.zig");
const keyprotector = @import("keyprotector.zig");

const Error = types.Error;
const Certificate = types.Certificate;
const PrivateKeyEntry = types.PrivateKeyEntry;
const TrustedCertificateEntry = types.TrustedCertificateEntry;
const Entry = types.Entry;

/// Options for KeyStore behavior
pub const KeyStoreOptions = struct {
    /// Order aliases alphabetically when listing
    ordered: bool = false,
    /// Preserve original case of aliases (default: convert to lowercase)
    case_exact: bool = false,
    /// Minimum password length (default: 0, no minimum)
    min_password_len: usize = 0,
};

/// KeyStore manages JKS entries (private keys and trusted certificates)
pub const KeyStore = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Entry),
    options: KeyStoreOptions,
    random: std.Random,

    /// Create a new KeyStore with default options
    pub fn init(allocator: std.mem.Allocator) KeyStore {
        return initWithOptions(allocator, .{});
    }

    /// Create a new KeyStore with custom options
    pub fn initWithOptions(allocator: std.mem.Allocator, options: KeyStoreOptions) KeyStore {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Entry).init(allocator),
            .options = options,
            .random = std.crypto.random,
        };
    }

    /// Free all resources
    pub fn deinit(self: *KeyStore) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            kv.value_ptr.*.deinit(self.allocator);
        }
        self.entries.deinit();
    }

    /// Convert alias to the appropriate case
    fn convertAlias(self: *const KeyStore, alias: []const u8) ![]u8 {
        if (self.options.case_exact) {
            return try self.allocator.dupe(u8, alias);
        }

        // Convert to lowercase
        const lower = try self.allocator.alloc(u8, alias.len);
        for (alias, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }
        return lower;
    }

    /// Set a private key entry
    pub fn setPrivateKeyEntry(
        self: *KeyStore,
        alias: []const u8,
        entry: PrivateKeyEntry,
        password: []const u8,
    ) !void {
        if (password.len < self.options.min_password_len) {
            return Error.ShortPassword;
        }

        try entry.validate();

        // Encrypt the private key
        const encrypted_key = try keyprotector.encrypt(
            self.allocator,
            self.random,
            entry.private_key,
            password,
        );
        errdefer self.allocator.free(encrypted_key);

        // Clone certificates
        const cert_chain = try self.allocator.alloc(Certificate, entry.certificate_chain.len);
        errdefer {
            for (cert_chain) |cert| {
                cert.deinit(self.allocator);
            }
            self.allocator.free(cert_chain);
        }

        for (entry.certificate_chain, 0..) |cert, i| {
            cert_chain[i] = try cert.clone(self.allocator);
        }

        // Create entry with encrypted key
        const encrypted_entry = PrivateKeyEntry{
            .creation_time = entry.creation_time,
            .private_key = encrypted_key,
            .certificate_chain = cert_chain,
        };

        const converted_alias = try self.convertAlias(alias);
        errdefer self.allocator.free(converted_alias);

        // Remove existing entry if present
        if (self.entries.fetchRemove(converted_alias)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }

        try self.entries.put(converted_alias, Entry{ .private_key = encrypted_entry });
    }

    /// Get a private key entry (decrypts the private key)
    pub fn getPrivateKeyEntry(
        self: *KeyStore,
        alias: []const u8,
        password: []const u8,
    ) !PrivateKeyEntry {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        const entry = self.entries.get(converted_alias) orelse return Error.EntryNotFound;

        switch (entry) {
            .private_key => |pke| {
                // Decrypt the private key
                const decrypted_key = try keyprotector.decrypt(
                    self.allocator,
                    pke.private_key,
                    password,
                );
                errdefer self.allocator.free(decrypted_key);

                // Clone certificate chain
                const cert_chain = try self.allocator.alloc(Certificate, pke.certificate_chain.len);
                errdefer {
                    for (cert_chain) |cert| {
                        cert.deinit(self.allocator);
                    }
                    self.allocator.free(cert_chain);
                }

                for (pke.certificate_chain, 0..) |cert, i| {
                    cert_chain[i] = try cert.clone(self.allocator);
                }

                return PrivateKeyEntry{
                    .creation_time = pke.creation_time,
                    .private_key = decrypted_key,
                    .certificate_chain = cert_chain,
                };
            },
            .trusted_certificate => return Error.WrongEntryType,
        }
    }

    /// Check if an entry is a private key entry
    pub fn isPrivateKeyEntry(self: *KeyStore, alias: []const u8) !bool {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        if (self.entries.get(converted_alias)) |entry| {
            return entry == .private_key;
        }
        return false;
    }

    /// Set a trusted certificate entry
    pub fn setTrustedCertificateEntry(
        self: *KeyStore,
        alias: []const u8,
        entry: TrustedCertificateEntry,
    ) !void {
        try entry.validate();

        // Clone certificate
        const cert = try entry.certificate.clone(self.allocator);
        errdefer cert.deinit(self.allocator);

        const new_entry = TrustedCertificateEntry{
            .creation_time = entry.creation_time,
            .certificate = cert,
        };

        const converted_alias = try self.convertAlias(alias);
        errdefer self.allocator.free(converted_alias);

        // Remove existing entry if present
        if (self.entries.fetchRemove(converted_alias)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }

        try self.entries.put(converted_alias, Entry{ .trusted_certificate = new_entry });
    }

    /// Get a trusted certificate entry
    pub fn getTrustedCertificateEntry(
        self: *KeyStore,
        alias: []const u8,
    ) !TrustedCertificateEntry {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        const entry = self.entries.get(converted_alias) orelse return Error.EntryNotFound;

        switch (entry) {
            .trusted_certificate => |tce| {
                const cert = try tce.certificate.clone(self.allocator);
                return TrustedCertificateEntry{
                    .creation_time = tce.creation_time,
                    .certificate = cert,
                };
            },
            .private_key => return Error.WrongEntryType,
        }
    }

    /// Check if an entry is a trusted certificate entry
    pub fn isTrustedCertificateEntry(self: *KeyStore, alias: []const u8) !bool {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        if (self.entries.get(converted_alias)) |entry| {
            return entry == .trusted_certificate;
        }
        return false;
    }

    /// Delete an entry
    pub fn deleteEntry(self: *KeyStore, alias: []const u8) !void {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        if (self.entries.fetchRemove(converted_alias)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }
    }

    /// Get all aliases
    pub fn aliases(self: *KeyStore) ![][]const u8 {
        const result = try self.allocator.alloc([]const u8, self.entries.count());
        errdefer self.allocator.free(result);

        var it = self.entries.keyIterator();
        var i: usize = 0;
        while (it.next()) |key| : (i += 1) {
            result[i] = key.*;
        }

        if (self.options.ordered) {
            std.mem.sort([]const u8, result, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.lessThan);
        }

        return result;
    }

    /// Store the keystore to a writer
    pub fn store(self: *KeyStore, writer: std.io.AnyWriter, password: []const u8) !void {
        if (password.len < self.options.min_password_len) {
            return Error.ShortPassword;
        }

        var enc = encoder_mod.Encoder.init(writer);

        // Initialize hash with password
        const password_bytes = try common.passwordBytes(self.allocator, password);
        defer {
            common.zeroing(password_bytes);
            self.allocator.free(password_bytes);
        }

        enc.hash.update(password_bytes);
        enc.hash.update(common.whitener_message);

        // Write header
        try enc.writeU32(common.magic);
        try enc.writeU32(common.version_02);
        try enc.writeU32(@intCast(self.entries.count()));

        // Write entries
        const alias_list = try self.aliases();
        defer self.allocator.free(alias_list);

        for (alias_list) |alias_str| {
            const entry = self.entries.get(alias_str).?;
            switch (entry) {
                .private_key => |pke| {
                    try enc.writePrivateKeyEntry(alias_str, pke);
                },
                .trusted_certificate => |tce| {
                    try enc.writeTrustedCertificateEntry(alias_str, tce);
                },
            }
        }

        // Write digest
        const digest = enc.finalize();
        try writer.writeAll(&digest);
    }

    /// Load a keystore from a reader
    pub fn load(self: *KeyStore, reader: std.io.AnyReader, password: []const u8) !void {
        var dec = decoder_mod.Decoder.init(self.allocator, reader);

        // Initialize hash with password
        const password_bytes = try common.passwordBytes(self.allocator, password);
        defer {
            common.zeroing(password_bytes);
            self.allocator.free(password_bytes);
        }

        dec.hash.update(password_bytes);
        dec.hash.update(common.whitener_message);

        // Read header
        const read_magic = try dec.readU32();
        if (read_magic != common.magic) {
            return Error.InvalidMagic;
        }

        const version = try dec.readU32();
        if (version != common.version_01 and version != common.version_02) {
            return Error.InvalidVersion;
        }

        const entry_count = try dec.readU32();

        // Read entries
        var i: u32 = 0;
        while (i < entry_count) : (i += 1) {
            const result = try dec.readEntry(version);
            errdefer {
                self.allocator.free(result.alias);
                result.entry.deinit(self.allocator);
            }

            try self.entries.put(result.alias, result.entry);
        }

        // Verify digest
        const computed_digest = dec.finalize();
        var actual_digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        try reader.readNoEof(&actual_digest);

        if (!std.mem.eql(u8, &computed_digest, &actual_digest)) {
            return Error.InvalidDigest;
        }
    }
};

// Tests

test "KeyStore: set and get private key entry" {
    var ks = KeyStore.init(testing.allocator);
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };
    const chain = [_]Certificate{cert};

    const entry = PrivateKeyEntry{
        .creation_time = 1000000,
        .private_key = "test_private_key_data",
        .certificate_chain = &chain,
    };

    try ks.setPrivateKeyEntry("mykey", entry, "password123");
    const retrieved = try ks.getPrivateKeyEntry("mykey", "password123");
    defer retrieved.deinit(testing.allocator);

    try testing.expectEqual(entry.creation_time, retrieved.creation_time);
    try testing.expectEqualStrings(entry.private_key, retrieved.private_key);
}

test "KeyStore: set and get trusted certificate entry" {
    var ks = KeyStore.init(testing.allocator);
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01, 0x02, 0x03 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 2000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("mycert", entry);
    const retrieved = try ks.getTrustedCertificateEntry("mycert");
    defer retrieved.deinit(testing.allocator);

    try testing.expectEqual(entry.creation_time, retrieved.creation_time);
    try testing.expectEqualStrings(cert.type, retrieved.certificate.type);
    try testing.expectEqualSlices(u8, cert.content, retrieved.certificate.content);
}

test "KeyStore: case insensitive aliases by default" {
    var ks = KeyStore.init(testing.allocator);
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("MyAlias", entry);

    // Should be able to retrieve with different case
    const retrieved = try ks.getTrustedCertificateEntry("myalias");
    defer retrieved.deinit(testing.allocator);

    try testing.expectEqual(entry.creation_time, retrieved.creation_time);
}

test "KeyStore: case exact aliases with option" {
    var ks = KeyStore.initWithOptions(testing.allocator, .{ .case_exact = true });
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("MyAlias", entry);

    // Should not find with different case
    const result = ks.getTrustedCertificateEntry("myalias");
    try testing.expectError(Error.EntryNotFound, result);
}

test "KeyStore: store and load round trip" {
    var ks = KeyStore.init(testing.allocator);
    defer ks.deinit();

    // Add a trusted certificate
    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01, 0x02, 0x03 },
    };

    const tce = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("mycert", tce);

    // Add a private key
    const chain = [_]Certificate{cert};
    const pke = PrivateKeyEntry{
        .creation_time = 2000000,
        .private_key = "test_private_key",
        .certificate_chain = &chain,
    };

    try ks.setPrivateKeyEntry("mykey", pke, "password123");

    // Store to buffer
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    try ks.store(buffer.writer().any(), "storepass");

    // Load into new keystore
    var ks2 = KeyStore.init(testing.allocator);
    defer ks2.deinit();

    var stream = std.io.fixedBufferStream(buffer.items);
    try ks2.load(stream.reader().any(), "storepass");

    // Verify entries
    try testing.expectEqual(@as(usize, 2), ks2.entries.count());

    const retrieved_tce = try ks2.getTrustedCertificateEntry("mycert");
    defer retrieved_tce.deinit(testing.allocator);
    try testing.expectEqual(tce.creation_time, retrieved_tce.creation_time);

    const retrieved_pke = try ks2.getPrivateKeyEntry("mykey", "password123");
    defer retrieved_pke.deinit(testing.allocator);
    try testing.expectEqual(pke.creation_time, retrieved_pke.creation_time);
    try testing.expectEqualStrings(pke.private_key, retrieved_pke.private_key);
}

test "KeyStore: delete entry" {
    var ks = KeyStore.init(testing.allocator);
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("mycert", entry);
    try testing.expectEqual(@as(usize, 1), ks.entries.count());

    try ks.deleteEntry("mycert");
    try testing.expectEqual(@as(usize, 0), ks.entries.count());

    const result = ks.getTrustedCertificateEntry("mycert");
    try testing.expectError(Error.EntryNotFound, result);
}

test "KeyStore: aliases list" {
    var ks = KeyStore.init(testing.allocator);
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("alias1", entry);
    try ks.setTrustedCertificateEntry("alias2", entry);
    try ks.setTrustedCertificateEntry("alias3", entry);

    const alias_list = try ks.aliases();
    defer testing.allocator.free(alias_list);

    try testing.expectEqual(@as(usize, 3), alias_list.len);
}

test "KeyStore: ordered aliases" {
    var ks = KeyStore.initWithOptions(testing.allocator, .{ .ordered = true });
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("charlie", entry);
    try ks.setTrustedCertificateEntry("alice", entry);
    try ks.setTrustedCertificateEntry("bob", entry);

    const alias_list = try ks.aliases();
    defer testing.allocator.free(alias_list);

    try testing.expectEqualStrings("alice", alias_list[0]);
    try testing.expectEqualStrings("bob", alias_list[1]);
    try testing.expectEqualStrings("charlie", alias_list[2]);
}

test "KeyStore: minimum password length" {
    var ks = KeyStore.initWithOptions(testing.allocator, .{ .min_password_len = 8 });
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82 },
    };
    const chain = [_]Certificate{cert};

    const pke = PrivateKeyEntry{
        .creation_time = 1000000,
        .private_key = "test_key",
        .certificate_chain = &chain,
    };

    // Short password should fail
    const result1 = ks.setPrivateKeyEntry("mykey", pke, "short");
    try testing.expectError(Error.ShortPassword, result1);

    // Long enough password should work
    try ks.setPrivateKeyEntry("mykey", pke, "longpassword");
}
