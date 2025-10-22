// zig-jks: A Zig implementation of Java KeyStore (JKS) format
//
// This library provides functionality to read and write Java KeyStore files
// in the JKS format, which is used to store cryptographic keys and certificates.

const std = @import("std");

// Re-export main types
pub const KeyStore = @import("keystore.zig").KeyStore;
pub const KeyStoreOptions = @import("keystore.zig").KeyStoreOptions;

// Re-export entry types
pub const Certificate = @import("types.zig").Certificate;
pub const PrivateKeyEntry = @import("types.zig").PrivateKeyEntry;
pub const TrustedCertificateEntry = @import("types.zig").TrustedCertificateEntry;
pub const Entry = @import("types.zig").Entry;

// Re-export errors
pub const Error = @import("types.zig").Error;

// Re-export constants for advanced users
pub const common = @import("common.zig");

// Test that we can create a KeyStore
test "can create and destroy KeyStore" {
    var ks = KeyStore.init(std.testing.allocator);
    defer ks.deinit();

    try std.testing.expect(ks.entries.count() == 0);
}

// Run all tests from submodules
test {
    std.testing.refAllDecls(@This());
    _ = @import("common.zig");
    _ = @import("types.zig");
    _ = @import("encoder.zig");
    _ = @import("decoder.zig");
    _ = @import("keyprotector.zig");
    _ = @import("keystore.zig");
}
