//! Java KeyStore (JKS) encoder/decoder.
//!
//! JKS is Oracle's legacy keystore format, still used everywhere in Java land.
//! Uses SHA-1 for integrity (yeah, I know). New stuff should use PKCS#12.
//!
//! Example:
//! ```zig
//! const jks = @import("jks");
//!
//! var ks = jks.Jks.init(allocator);
//! defer ks.deinit();
//!
//! const cert = jks.Certificate{
//!     .type = "X.509",
//!     .content = cert_der_bytes,
//! };
//!
//! try ks.setTrustedCertificateEntry("my-cert", .{
//!     .creation_time = std.time.milliTimestamp(),
//!     .certificate = cert,
//! });
//!
//! try ks.store(writer, "password");
//! ```

const std = @import("std");
const encoder = @import("encoder.zig");
const decoder = @import("decoder.zig");
const crypto = @import("crypto.zig");

// JKS format constants
pub const magic: u32 = 0xfeedfeed;
pub const version_01: u32 = 1;
pub const version_02: u32 = 2;
const private_key_tag: u32 = 1;
const trusted_certificate_tag: u32 = 2;
const whitener_message = "Mighty Aphrodite";
const byte_order = std.builtin.Endian.big;

// Public types
pub const Certificate = struct {
    type: []const u8,
    content: []const u8,

    pub fn validate(self: Certificate) Error!void {
        if (self.type.len == 0) return Error.EmptyCertificateType;
        if (self.content.len == 0) return Error.EmptyCertificateContent;
    }

    pub fn clone(self: Certificate, allocator: std.mem.Allocator) !Certificate {
        const type_copy = try allocator.dupe(u8, self.type);
        errdefer allocator.free(type_copy);

        const content_copy = try allocator.dupe(u8, self.content);
        errdefer allocator.free(content_copy);

        return Certificate{
            .type = type_copy,
            .content = content_copy,
        };
    }

    pub fn deinit(self: Certificate, allocator: std.mem.Allocator) void {
        allocator.free(self.type);
        allocator.free(self.content);
    }
};

pub const PrivateKeyEntry = struct {
    creation_time: i64,
    private_key: []const u8,
    certificate_chain: []const Certificate,

    pub fn validate(self: PrivateKeyEntry) Error!void {
        if (self.private_key.len == 0) return Error.EmptyPrivateKey;

        for (self.certificate_chain, 0..) |cert, i| {
            cert.validate() catch |err| {
                std.log.err("Invalid certificate at index {d} in chain", .{i});
                return err;
            };
        }
    }

    pub fn deinit(self: PrivateKeyEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.private_key);
        for (self.certificate_chain) |cert| {
            cert.deinit(allocator);
        }
        allocator.free(self.certificate_chain);
    }
};

pub const TrustedCertificateEntry = struct {
    creation_time: i64,
    certificate: Certificate,

    pub fn validate(self: TrustedCertificateEntry) Error!void {
        try self.certificate.validate();
    }

    pub fn deinit(self: TrustedCertificateEntry, allocator: std.mem.Allocator) void {
        self.certificate.deinit(allocator);
    }
};

pub const Entry = union(enum) {
    private_key: PrivateKeyEntry,
    trusted_certificate: TrustedCertificateEntry,

    pub fn validate(self: Entry) Error!void {
        return switch (self) {
            .private_key => |e| e.validate(),
            .trusted_certificate => |e| e.validate(),
        };
    }

    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        switch (self) {
            .private_key => |e| e.deinit(allocator),
            .trusted_certificate => |e| e.deinit(allocator),
        }
    }
};

pub const Error = error{
    EntryNotFound,
    WrongEntryType,
    EmptyPrivateKey,
    EmptyCertificateType,
    EmptyCertificateContent,
    ShortPassword,
    InvalidMagic,
    InvalidDigest,
    InvalidVersion,
    UnknownEntryTag,
    UnsupportedAlgorithm,
    InvalidKeyData,
    StringTooLong,
    DataTooLong,
};

pub const Options = struct {
    ordered: bool = false,
    case_exact: bool = false,
    min_password_len: usize = 0,
};

pub const Jks = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Entry),
    options: Options,
    random: std.Random,

    pub fn init(allocator: std.mem.Allocator) Jks {
        return initWithOptions(allocator, .{});
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, options: Options) Jks {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Entry).init(allocator),
            .options = options,
            .random = std.crypto.random,
        };
    }

    pub fn deinit(self: *Jks) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            kv.value_ptr.*.deinit(self.allocator);
        }
        self.entries.deinit();
    }

    fn convertAlias(self: *const Jks, alias: []const u8) ![]u8 {
        if (self.options.case_exact) {
            return try self.allocator.dupe(u8, alias);
        }

        const lower = try self.allocator.alloc(u8, alias.len);
        for (alias, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }
        return lower;
    }

    pub fn setPrivateKeyEntry(
        self: *Jks,
        alias: []const u8,
        entry: PrivateKeyEntry,
        password: []const u8,
    ) !void {
        if (password.len < self.options.min_password_len) {
            return Error.ShortPassword;
        }

        try entry.validate();
        const encrypted_key = try crypto.encrypt(
            self.allocator,
            self.random,
            entry.private_key,
            password,
        );
        errdefer self.allocator.free(encrypted_key);

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

        const encrypted_entry = PrivateKeyEntry{
            .creation_time = entry.creation_time,
            .private_key = encrypted_key,
            .certificate_chain = cert_chain,
        };

        const converted_alias = try self.convertAlias(alias);
        errdefer self.allocator.free(converted_alias);

        if (self.entries.fetchRemove(converted_alias)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }

        try self.entries.put(converted_alias, Entry{ .private_key = encrypted_entry });
    }

    pub fn getPrivateKeyEntry(
        self: *Jks,
        alias: []const u8,
        password: []const u8,
    ) !PrivateKeyEntry {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        const entry = self.entries.get(converted_alias) orelse return Error.EntryNotFound;

        switch (entry) {
            .private_key => |pke| {
                const decrypted_key = try crypto.decrypt(
                    self.allocator,
                    pke.private_key,
                    password,
                );
                errdefer self.allocator.free(decrypted_key);

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

    pub fn isPrivateKeyEntry(self: *Jks, alias: []const u8) !bool {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        if (self.entries.get(converted_alias)) |entry| {
            return entry == .private_key;
        }
        return false;
    }

    pub fn setTrustedCertificateEntry(
        self: *Jks,
        alias: []const u8,
        entry: TrustedCertificateEntry,
    ) !void {
        try entry.validate();
        const cert = try entry.certificate.clone(self.allocator);
        errdefer cert.deinit(self.allocator);

        const new_entry = TrustedCertificateEntry{
            .creation_time = entry.creation_time,
            .certificate = cert,
        };

        const converted_alias = try self.convertAlias(alias);
        errdefer self.allocator.free(converted_alias);

        if (self.entries.fetchRemove(converted_alias)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }

        try self.entries.put(converted_alias, Entry{ .trusted_certificate = new_entry });
    }

    pub fn getTrustedCertificateEntry(
        self: *Jks,
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

    pub fn isTrustedCertificateEntry(self: *Jks, alias: []const u8) !bool {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        if (self.entries.get(converted_alias)) |entry| {
            return entry == .trusted_certificate;
        }
        return false;
    }

    pub fn deleteEntry(self: *Jks, alias: []const u8) !void {
        const converted_alias = try self.convertAlias(alias);
        defer self.allocator.free(converted_alias);

        if (self.entries.fetchRemove(converted_alias)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }
    }

    pub fn aliases(self: *Jks) ![][]const u8 {
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

    pub fn store(self: *Jks, writer: std.io.AnyWriter, password: []const u8) !void {
        if (password.len < self.options.min_password_len) {
            return Error.ShortPassword;
        }

        var enc = encoder.Encoder.init(writer);
        const password_bytes = try passwordBytes(self.allocator, password);
        defer {
            zeroing(password_bytes);
            self.allocator.free(password_bytes);
        }

        enc.hash.update(password_bytes);
        enc.hash.update(whitener_message);
        try enc.writeU32(magic);
        try enc.writeU32(version_02);
        try enc.writeU32(@intCast(self.entries.count()));

        const alias_list = try self.aliases();
        defer self.allocator.free(alias_list);

        for (alias_list) |alias_str| {
            const entry = self.entries.get(alias_str).?;
            switch (entry) {
                .private_key => |pke| {
                    try enc.writeU32(private_key_tag);
                    try enc.writeString(alias_str);
                    try enc.writeU64(@intCast(pke.creation_time));
                    try enc.writeU32(@intCast(pke.private_key.len));
                    try enc.writeBytes(pke.private_key);
                    try enc.writeU32(@intCast(pke.certificate_chain.len));
                    for (pke.certificate_chain) |cert| {
                        try enc.writeCertificate(cert.type, cert.content, version_02);
                    }
                },
                .trusted_certificate => |tce| {
                    try enc.writeU32(trusted_certificate_tag);
                    try enc.writeString(alias_str);
                    try enc.writeU64(@intCast(tce.creation_time));
                    try enc.writeCertificate(tce.certificate.type, tce.certificate.content, version_02);
                },
            }
        }

        const digest = enc.finalize();
        try writer.writeAll(&digest);
    }

    pub fn load(self: *Jks, reader: std.io.AnyReader, password: []const u8) !void {
        var dec = decoder.Decoder.init(self.allocator, reader);
        const password_bytes = try passwordBytes(self.allocator, password);
        defer {
            zeroing(password_bytes);
            self.allocator.free(password_bytes);
        }

        dec.hash.update(password_bytes);
        dec.hash.update(whitener_message);

        const read_magic = try dec.readU32();
        if (read_magic != magic) {
            return Error.InvalidMagic;
        }

        const version = try dec.readU32();
        if (version != version_01 and version != version_02) {
            return Error.InvalidVersion;
        }

        const entry_count = try dec.readU32();
        var i: u32 = 0;
        while (i < entry_count) : (i += 1) {
            const tag = try dec.readU32();
            const alias = try dec.readString();
            errdefer self.allocator.free(alias);

            const entry = switch (tag) {
                private_key_tag => blk: {
                    const creation_time = try dec.readU64();
                    const pk_len = try dec.readU32();
                    const private_key = try dec.readBytes(pk_len);
                    errdefer self.allocator.free(private_key);

                    const cert_num = try dec.readU32();
                    const chain = try self.allocator.alloc(Certificate, cert_num);
                    errdefer {
                        for (chain) |cert| {
                            cert.deinit(self.allocator);
                        }
                        self.allocator.free(chain);
                    }

                    for (chain) |*cert| {
                        const cert_data = try dec.readCertificate(version);
                        cert.* = Certificate{
                            .type = cert_data.cert_type,
                            .content = cert_data.content,
                        };
                    }

                    const pke = PrivateKeyEntry{
                        .creation_time = @intCast(creation_time),
                        .private_key = private_key,
                        .certificate_chain = chain,
                    };
                    break :blk Entry{ .private_key = pke };
                },
                trusted_certificate_tag => blk: {
                    const creation_time = try dec.readU64();
                    const cert_data = try dec.readCertificate(version);

                    const tce = TrustedCertificateEntry{
                        .creation_time = @intCast(creation_time),
                        .certificate = Certificate{
                            .type = cert_data.cert_type,
                            .content = cert_data.content,
                        },
                    };
                    break :blk Entry{ .trusted_certificate = tce };
                },
                else => return Error.UnknownEntryTag,
            };
            errdefer entry.deinit(self.allocator);

            try self.entries.put(alias, entry);
        }

        const computed_digest = dec.finalize();
        var actual_digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        try reader.readNoEof(&actual_digest);

        if (!std.mem.eql(u8, &computed_digest, &actual_digest)) {
            return Error.InvalidDigest;
        }
    }
};

// Helper functions
fn passwordBytes(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, password.len * 2);
    errdefer allocator.free(result);

    for (password, 0..) |b, i| {
        result[i * 2] = 0;
        result[i * 2 + 1] = b;
    }

    return result;
}

fn zeroing(buf: []u8) void {
    @memset(buf, 0);
}

// Tests
const testing = std.testing;

test "Jks: basic operations" {
    var ks = Jks.init(testing.allocator);
    defer ks.deinit();

    try testing.expectEqual(@as(usize, 0), ks.entries.count());
}

test "Jks: set and get private key entry" {
    var ks = Jks.init(testing.allocator);
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

test "Jks: set and get trusted certificate entry" {
    var ks = Jks.init(testing.allocator);
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

test "Jks: store and load round trip" {
    var ks = Jks.init(testing.allocator);
    defer ks.deinit();

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01, 0x02, 0x03 },
    };

    const tce = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("mycert", tce);

    const chain = [_]Certificate{cert};
    const pke = PrivateKeyEntry{
        .creation_time = 2000000,
        .private_key = "test_private_key",
        .certificate_chain = &chain,
    };

    try ks.setPrivateKeyEntry("mykey", pke, "password123");

    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    try ks.store(buffer.writer().any(), "storepass");

    var ks2 = Jks.init(testing.allocator);
    defer ks2.deinit();

    var stream = std.io.fixedBufferStream(buffer.items);
    try ks2.load(stream.reader().any(), "storepass");

    try testing.expectEqual(@as(usize, 2), ks2.entries.count());

    const retrieved_tce = try ks2.getTrustedCertificateEntry("mycert");
    defer retrieved_tce.deinit(testing.allocator);
    try testing.expectEqual(tce.creation_time, retrieved_tce.creation_time);

    const retrieved_pke = try ks2.getPrivateKeyEntry("mykey", "password123");
    defer retrieved_pke.deinit(testing.allocator);
    try testing.expectEqual(pke.creation_time, retrieved_pke.creation_time);
    try testing.expectEqualStrings(pke.private_key, retrieved_pke.private_key);
}

test {
    std.testing.refAllDecls(@This());
}
