const std = @import("std");
const testing = std.testing;

/// Represents an X.509 or other certificate.
pub const Certificate = struct {
    /// Certificate type (e.g., "X509")
    type: []const u8,
    /// Certificate content (DER-encoded bytes)
    content: []const u8,

    /// Validates that the certificate has all required fields.
    pub fn validate(self: Certificate) Error!void {
        if (self.type.len == 0) return Error.EmptyCertificateType;
        if (self.content.len == 0) return Error.EmptyCertificateContent;
    }

    /// Creates a deep copy of the certificate.
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

    /// Frees all memory associated with this certificate.
    pub fn deinit(self: Certificate, allocator: std.mem.Allocator) void {
        allocator.free(self.type);
        allocator.free(self.content);
    }
};

/// Entry containing a private key and associated certificate chain.
pub const PrivateKeyEntry = struct {
    /// Creation timestamp in milliseconds since epoch
    creation_time: i64,
    /// Encrypted private key bytes (PKCS8 format)
    private_key: []const u8,
    /// Certificate chain for the private key
    certificate_chain: []const Certificate,

    /// Validates that the entry has all required fields.
    pub fn validate(self: PrivateKeyEntry) Error!void {
        if (self.private_key.len == 0) return Error.EmptyPrivateKey;

        for (self.certificate_chain, 0..) |cert, i| {
            cert.validate() catch |err| {
                std.log.err("Invalid certificate at index {d} in chain", .{i});
                return err;
            };
        }
    }

    std.crypto

    /// Frees all memory associated with this entry.
    pub fn deinit(self: PrivateKeyEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.private_key);
        for (self.certificate_chain) |cert| {
            cert.deinit(allocator);
        }
        allocator.free(self.certificate_chain);
    }
};

/// Entry containing only a trusted certificate.
pub const TrustedCertificateEntry = struct {
    /// Creation timestamp in milliseconds since epoch
    creation_time: i64,
    /// The trusted certificate
    certificate: Certificate,

    /// Validates that the entry has all required fields.
    pub fn validate(self: TrustedCertificateEntry) Error!void {
        try self.certificate.validate();
    }

    /// Frees all memory associated with this entry.
    pub fn deinit(self: TrustedCertificateEntry, allocator: std.mem.Allocator) void {
        self.certificate.deinit(allocator);
    }
};

/// Union type representing either a private key or trusted certificate entry.
pub const Entry = union(enum) {
    private_key: PrivateKeyEntry,
    trusted_certificate: TrustedCertificateEntry,

    /// Validates the entry.
    pub fn validate(self: Entry) Error!void {
        return switch (self) {
            .private_key => |e| e.validate(),
            .trusted_certificate => |e| e.validate(),
        };
    }

    /// Frees all memory associated with this entry.
    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        switch (self) {
            .private_key => |e| e.deinit(allocator),
            .trusted_certificate => |e| e.deinit(allocator),
        }
    }
};

/// Errors that can occur during keystore operations.
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

// Tests

test "Certificate.validate accepts valid certificate" {
    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    try cert.validate();
}

test "Certificate.validate rejects empty type" {
    const cert = Certificate{
        .type = "",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    try testing.expectError(Error.EmptyCertificateType, cert.validate());
}

test "Certificate.validate rejects empty content" {
    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{},
    };

    try testing.expectError(Error.EmptyCertificateContent, cert.validate());
}

test "Certificate.clone creates independent copy" {
    const original = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    const copy = try original.clone(testing.allocator);
    defer copy.deinit(testing.allocator);

    try testing.expectEqualStrings(original.type, copy.type);
    try testing.expectEqualSlices(u8, original.content, copy.content);

    // Ensure they're independent (different memory addresses)
    try testing.expect(original.type.ptr != copy.type.ptr);
    try testing.expect(original.content.ptr != copy.content.ptr);
}

test "PrivateKeyEntry.validate accepts valid entry" {
    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    const chain = [_]Certificate{cert};

    const entry = PrivateKeyEntry{
        .creation_time = 1000000,
        .private_key = &[_]u8{ 0x01, 0x02, 0x03 },
        .certificate_chain = &chain,
    };

    try entry.validate();
}

test "PrivateKeyEntry.validate rejects empty private key" {
    const entry = PrivateKeyEntry{
        .creation_time = 1000000,
        .private_key = &[_]u8{},
        .certificate_chain = &[_]Certificate{},
    };

    try testing.expectError(Error.EmptyPrivateKey, entry.validate());
}

test "TrustedCertificateEntry.validate accepts valid entry" {
    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try entry.validate();
}

test "TrustedCertificateEntry.validate rejects invalid certificate" {
    const cert = Certificate{
        .type = "",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    const entry = TrustedCertificateEntry{
        .creation_time = 1000000,
        .certificate = cert,
    };

    try testing.expectError(Error.EmptyCertificateType, entry.validate());
}
