const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("jks", .{
        .root_source_file = b.path("src/jks.zig"),
        .target = target,
    });

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    const generate_testdata = b.addExecutable(.{
        .name = "generate_testdata",
        .root_module = b.createModule(.{
            .root_source_file = b.path("testdata/generate.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "jks", .module = mod },
            },
        }),
    });

    const run_generate_testdata = b.addRunArtifact(generate_testdata);
    const generate_step = b.step("generate-testdata", "Generate test JKS files");
    generate_step.dependOn(&run_generate_testdata.step);

    const examples = [_]struct { name: []const u8, file: []const u8, desc: []const u8 }{
        .{ .name = "create", .file = "examples/01_create_keystore.zig", .desc = "Create a keystore from scratch" },
        .{ .name = "inspect", .file = "examples/02_inspect_keystore.zig", .desc = "Inspect keystore contents" },
        .{ .name = "manage", .file = "examples/03_manage_entries.zig", .desc = "Manage entries" },
        .{ .name = "workflow", .file = "examples/04_load_modify_save.zig", .desc = "Load, modify, save workflow" },
        .{ .name = "passwords", .file = "examples/05_working_with_passwords.zig", .desc = "Password handling" },
    };

    inline for (examples) |example| {
        const example_exe = b.addExecutable(.{
            .name = example.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(example.file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "jks", .module = mod },
                },
            }),
        });

        const run_example = b.addRunArtifact(example_exe);
        const example_step = b.step(example.name, example.desc);
        example_step.dependOn(&run_example.step);
    }
}
